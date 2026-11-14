#!/usr/bin/env python3
"""sparse_rows -- 从零采集 MySQL 8.4.11 稀疏行镜像，输出 JSON 变更数组。

输入为 TABLE_MAP_EVENT 与 WRITE/UPDATE/DELETE_ROWS_EVENT_V2 三种事件拼接
而成的字节流（每个事件 = 19 字节头 + 事件体 + 尾部 CRC32）。解析完全自写，
仅用标准库（zlib 提供 CRC32，json 仅用于输出序列化）。

用法:
    python3 sparse_rows.py INPUT [OUTPUT]

    INPUT   事件字节流文件，"-" 表示标准输入。
    OUTPUT  JSON 输出文件；省略或 "-" 表示标准输出。给定真实路径时，
            只有整次解析成功才会原子地替换输出文件。

退出码:
    0  成功（空输入输出 []）。
    1  输入非法（截断 / 未知类型 / 非法结构 / 校验和错误），整次拒绝，
       stderr 报告出错事件的零基序号与零基字节起点，输出文件保持不变。
    2  用法错误或 IO 错误。

格式依据:
    MySQL 8.4.11 rows_event.h（TABLE_MAP / ROWS_EVENT_V2 布局）及同版
    json_binary 二进制 JSON 格式。详见 README.md。
"""

import json
import os
import sys
import tempfile
import zlib

HEADER_LEN = 19          # binlog 事件公共头长度
CHECKSUM_LEN = 4         # 事件尾部 CRC32 长度

# 事件类型码（log_event_type）
TABLE_MAP_EVENT = 19
WRITE_ROWS_EVENT_V2 = 30
UPDATE_ROWS_EVENT_V2 = 31
DELETE_ROWS_EVENT_V2 = 32

# 接受的列类型码
MYSQL_TYPE_LONGLONG = 8      # 有符号 8 字节整数
MYSQL_TYPE_JSON = 245        # json_binary 文档

JSON_METADATA_LEN = 4        # JSON 列在 TABLE_MAP 中的元数据固定 4 字节
ROW_EXTRA_DATA_LEN = 2       # 行事件 extra_data_len 固定为 2（无附加数据）

# json_binary 类型码
JB_SMALL_OBJECT = 0x00
JB_LARGE_OBJECT = 0x01
JB_SMALL_ARRAY = 0x02
JB_LARGE_ARRAY = 0x03
JB_LITERAL = 0x04
JB_INT16 = 0x05
JB_UINT16 = 0x06
JB_INT32 = 0x07
JB_UINT32 = 0x08
JB_INT64 = 0x09
JB_UINT64 = 0x0A
JB_DOUBLE = 0x0B
JB_STRING = 0x0C
JB_OPAQUE = 0x0F

JB_LITERALS = {0x00: None, 0x01: True, 0x02: False}
JB_CONTAINERS = frozenset((JB_SMALL_OBJECT, JB_LARGE_OBJECT,
                           JB_SMALL_ARRAY, JB_LARGE_ARRAY))
# 内联与否按容器大小裁决：小容器内联 <=2 字节，大容器内联 <=4 字节
JB_INLINE_SMALL = frozenset((JB_LITERAL, JB_INT16, JB_UINT16))
JB_INLINE_LARGE = JB_INLINE_SMALL | frozenset((JB_INT32, JB_UINT32))

_OPS = {WRITE_ROWS_EVENT_V2: "I",
        UPDATE_ROWS_EVENT_V2: "U",
        DELETE_ROWS_EVENT_V2: "D"}


class Reject(Exception):
    """内部异常：当前事件非法，整次输入应被拒绝。"""


class StreamError(Exception):
    """对外异常：整次拒绝。offset 为出错事件的零基字节起点，index 为其零基序号。"""

    def __init__(self, offset, index, message):
        super().__init__(message)
        self.offset = offset
        self.index = index
        self.message = message


# ---------------------------------------------------------------------------
# 通用小端游标
# ---------------------------------------------------------------------------

class Cursor:
    """带边界检查的小端字节游标，越界即 Reject。"""

    __slots__ = ("buf", "pos", "end")

    def __init__(self, buf, pos=0, end=None):
        self.buf = buf
        self.pos = pos
        self.end = len(buf) if end is None else end

    def remain(self):
        return self.end - self.pos

    def take(self, n, what):
        if n < 0 or self.pos + n > self.end:
            raise Reject("truncated " + what)
        p = self.pos
        self.pos += n
        return p

    def u8(self, what):
        return self.buf[self.take(1, what)]

    def u16(self, what):
        p = self.take(2, what)
        return self.buf[p] | (self.buf[p + 1] << 8)

    def u32(self, what):
        p = self.take(4, what)
        return int.from_bytes(self.buf[p:self.pos], "little")

    def u64(self, what):
        p = self.take(8, what)
        return int.from_bytes(self.buf[p:self.pos], "little")

    def data(self, n, what):
        p = self.take(n, what)
        return self.buf[p:self.pos]

    def lenenc(self, what):
        """MySQL 长度编码整数（net_length_size）。"""
        b0 = self.u8(what)
        if b0 < 0xFB:
            return b0
        if b0 == 0xFC:
            return self.u16(what)
        if b0 == 0xFD:
            p = self.take(3, what)
            return self.buf[p] | (self.buf[p + 1] << 8) | (self.buf[p + 2] << 16)
        if b0 == 0xFE:
            return self.u64(what)
        raise Reject("invalid length-encoded " + what)


# ---------------------------------------------------------------------------
# json_binary 解析（MySQL 8.4.11 sql-common/json_binary）
# ---------------------------------------------------------------------------

def _jb_bounds(pos, n, limit):
    if pos < 0 or n < 0 or pos + n > limit:
        raise Reject("JSON offset out of bounds")


def _jb_lenenc(buf, pos, limit):
    """json_binary 字符串的可变长度前缀，返回 (长度, 新位置)。"""
    _jb_bounds(pos, 1, limit)
    b0 = buf[pos]
    if b0 < 0xFB:
        return b0, pos + 1
    if b0 == 0xFC:
        _jb_bounds(pos, 3, limit)
        return buf[pos + 1] | (buf[pos + 2] << 8), pos + 3
    if b0 == 0xFD:
        _jb_bounds(pos, 4, limit)
        return buf[pos + 1] | (buf[pos + 2] << 8) | (buf[pos + 3] << 16), pos + 4
    if b0 == 0xFE:
        _jb_bounds(pos, 9, limit)
        return int.from_bytes(buf[pos + 1:pos + 9], "little"), pos + 9
    raise Reject("invalid JSON string length")


def _jb_scalar(buf, pos, limit, tcode):
    """解析非容器值，返回 (值, 结束位置)。double 与 opaque 一律拒绝。"""
    if tcode == JB_LITERAL:
        _jb_bounds(pos, 1, limit)
        lit = buf[pos]
        if lit not in JB_LITERALS:
            raise Reject("invalid JSON literal 0x%02x" % lit)
        return JB_LITERALS[lit], pos + 1
    if tcode == JB_INT16:
        _jb_bounds(pos, 2, limit)
        return int.from_bytes(buf[pos:pos + 2], "little", signed=True), pos + 2
    if tcode == JB_UINT16:
        _jb_bounds(pos, 2, limit)
        return int.from_bytes(buf[pos:pos + 2], "little"), pos + 2
    if tcode == JB_INT32:
        _jb_bounds(pos, 4, limit)
        return int.from_bytes(buf[pos:pos + 4], "little", signed=True), pos + 4
    if tcode == JB_UINT32:
        _jb_bounds(pos, 4, limit)
        return int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
    if tcode == JB_INT64:
        _jb_bounds(pos, 8, limit)
        return int.from_bytes(buf[pos:pos + 8], "little", signed=True), pos + 8
    if tcode == JB_UINT64:
        _jb_bounds(pos, 8, limit)
        return int.from_bytes(buf[pos:pos + 8], "little"), pos + 8
    if tcode == JB_DOUBLE:
        raise Reject("JSON double values are not supported")
    if tcode == JB_OPAQUE:
        raise Reject("JSON opaque values are not supported")
    if tcode == JB_STRING:
        n, p = _jb_lenenc(buf, pos, limit)
        _jb_bounds(p, n, limit)
        try:
            return buf[p:p + n].decode("utf-8"), p + n
        except UnicodeDecodeError:
            raise Reject("invalid UTF-8 in JSON string")
    raise Reject("unknown JSON value type 0x%02x" % tcode)


def _jb_entry(buf, epos, cstart, cend, small):
    """解析容器内的一个值条目（1 字节类型 + 2/4 字节内联值或偏移）。"""
    tcode = buf[epos]
    offlen = 2 if small else 4
    field = buf[epos + 1: epos + 1 + offlen]
    inline = JB_INLINE_SMALL if small else JB_INLINE_LARGE
    if tcode in inline:
        # 内联值，尾部填充字节不检查
        value, _ = _jb_scalar(field, 0, len(field), tcode)
        return value
    # 偏移从本容器计数字段（即容器起点）起算
    vstart = cstart + int.from_bytes(field, "little")
    if tcode in JB_CONTAINERS:
        value, _ = _jb_container(buf, vstart, cend, tcode)
        return value
    value, _ = _jb_scalar(buf, vstart, cend, tcode)
    return value


def _jb_container(buf, pos, limit, tcode):
    """解析小/大容器，返回 (值, 容器结束位置)。"""
    small = tcode in (JB_SMALL_OBJECT, JB_SMALL_ARRAY)
    is_obj = tcode in (JB_SMALL_OBJECT, JB_LARGE_OBJECT)
    offlen = 2 if small else 4
    hdrlen = 4 if small else 8
    _jb_bounds(pos, hdrlen, limit)
    if small:
        count = buf[pos] | (buf[pos + 1] << 8)
        size = buf[pos + 2] | (buf[pos + 3] << 8)
    else:
        count = int.from_bytes(buf[pos:pos + 4], "little")
        size = int.from_bytes(buf[pos + 4:pos + 8], "little")
    cend = pos + size
    if size < hdrlen or cend > limit:
        raise Reject("JSON container out of bounds")
    key_len = offlen + 2
    val_len = 1 + offlen
    entries = count * (key_len + val_len) if is_obj else count * val_len
    if pos + hdrlen + entries > cend:
        raise Reject("JSON container entries out of bounds")
    if is_obj:
        keys = []
        seen = set()
        for i in range(count):
            e = pos + hdrlen + i * key_len
            if small:
                koff = buf[e] | (buf[e + 1] << 8)
                klen = buf[e + 2] | (buf[e + 3] << 8)
            else:
                koff = int.from_bytes(buf[e:e + 4], "little")
                klen = buf[e + 4] | (buf[e + 5] << 8)
            ks = pos + koff
            _jb_bounds(ks, klen, cend)
            try:
                key = buf[ks:ks + klen].decode("utf-8")
            except UnicodeDecodeError:
                raise Reject("invalid UTF-8 in JSON object key")
            if key in seen:
                raise Reject("duplicate key in JSON object")
            seen.add(key)
            keys.append(key)
        values = []
        vbase = pos + hdrlen + count * key_len
        for i in range(count):
            values.append(_jb_entry(buf, vbase + i * val_len, pos, cend, small))
        return dict(zip(keys, values)), cend
    values = []
    for i in range(count):
        values.append(_jb_entry(buf, pos + hdrlen + i * val_len,
                                pos, cend, small))
    return values, cend


def parse_json_binary(doc):
    """解析一份 json_binary 文档（SQL 层 4 字节小端长度之后的内容）。

    支持大小容器、字面量、整数与字符串；拒绝 double、opaque、越界、
    非法 UTF-8、重键与尾随字节；不检查键排序与内联填充。
    """
    if not doc:
        raise Reject("empty JSON value")
    tcode = doc[0]
    if tcode in JB_CONTAINERS:
        value, end = _jb_container(doc, 1, len(doc), tcode)
    else:
        value, end = _jb_scalar(doc, 1, len(doc), tcode)
    if end != len(doc):
        raise Reject("trailing bytes after JSON value")
    return value


# ---------------------------------------------------------------------------
# TABLE_MAP_EVENT
# ---------------------------------------------------------------------------

class TableMap:
    __slots__ = ("db", "table", "types", "nullable")

    def __init__(self, db, table, types, nullable):
        self.db = db                # str
        self.table = table          # str
        self.types = types          # list[int]，仅 LONGLONG / JSON
        self.nullable = nullable    # list[bool]


def _parse_table_map(body):
    cur = Cursor(body)
    table_id = int.from_bytes(cur.data(6, "table id"), "little")
    cur.data(2, "table map flags")  # 忽略标志
    db_len = cur.u8("schema name length")
    db_raw = cur.data(db_len, "schema name")
    if cur.u8("schema name terminator") != 0:
        raise Reject("bad schema name terminator")
    tbl_len = cur.u8("table name length")
    tbl_raw = cur.data(tbl_len, "table name")
    if cur.u8("table name terminator") != 0:
        raise Reject("bad table name terminator")
    col_count = cur.lenenc("column count")
    if col_count < 1:
        raise Reject("table map column count must be positive")
    types = list(cur.data(col_count, "column types"))
    for t in types:
        if t not in (MYSQL_TYPE_LONGLONG, MYSQL_TYPE_JSON):
            raise Reject("unsupported column type %d" % t)
    meta_len = cur.lenenc("column metadata length")
    cur.data(meta_len, "column metadata")
    # LONGLONG 无元数据，JSON 元数据固定 4 字节（内容忽略）
    want = sum(JSON_METADATA_LEN if t == MYSQL_TYPE_JSON else 0 for t in types)
    if meta_len != want:
        raise Reject("bad column metadata length %d (want %d)"
                     % (meta_len, want))
    null_bits = cur.data((col_count + 7) // 8, "null bitmap")
    nullable = [bool(null_bits[i >> 3] >> (i & 7) & 1) for i in range(col_count)]
    if cur.remain() != 0:
        raise Reject("table map optional metadata is not supported")
    try:
        db = db_raw.decode("utf-8")
        table = tbl_raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Reject("schema/table name is not valid UTF-8")
    return table_id, TableMap(db, table, types, nullable)


# ---------------------------------------------------------------------------
# ROWS_EVENT_V2（WRITE / UPDATE / DELETE）
# ---------------------------------------------------------------------------

def _bitmap_columns(bitmap_bytes, ncol):
    """出现列序号列表；位图尾位（>= ncol）忽略。"""
    return [i for i in range(ncol) if bitmap_bytes[i >> 3] >> (i & 7) & 1]


def _read_image(cur, tmap, cols):
    """读取一行镜像。NULL 位图按出现列压紧，尾位忽略；缺列省略。"""
    null_bits = cur.data((len(cols) + 7) // 8, "NULL bitmap")
    image = {}
    for k, col in enumerate(cols):
        if null_bits[k >> 3] >> (k & 7) & 1:
            if not tmap.nullable[col]:
                raise Reject("NULL value in NOT NULL column %d" % col)
            image[str(col)] = ["sql"]  # SQL NULL，无载荷
            continue
        if tmap.types[col] == MYSQL_TYPE_LONGLONG:
            n = int.from_bytes(cur.data(8, "LONGLONG value"),
                               "little", signed=True)
            image[str(col)] = ["int", n]
        else:  # MYSQL_TYPE_JSON
            jlen = cur.u32("JSON value length")
            image[str(col)] = ["json", parse_json_binary(cur.data(jlen,
                                                                  "JSON value"))]
    return image


def _parse_rows_event(body, event_index, maps, op):
    cur = Cursor(body)
    table_id = int.from_bytes(cur.data(6, "table id"), "little")
    cur.data(2, "row event flags")  # 忽略标志
    extra_len = cur.u16("extra data length")
    if extra_len != ROW_EXTRA_DATA_LEN:
        raise Reject("unsupported row event extra data length %d" % extra_len)
    tmap = maps.get(table_id)
    if tmap is None:
        raise Reject("row event references unknown table id %d" % table_id)
    ncol = len(tmap.types)
    if cur.lenenc("column count") != ncol:
        raise Reject("row event column count does not match table map")
    bm_len = (ncol + 7) // 8
    cols1 = _bitmap_columns(cur.data(bm_len, "columns-present bitmap"), ncol)
    if not cols1:
        raise Reject("columns-present bitmap has no bits set")
    cols2 = None
    if op == "U":
        cols2 = _bitmap_columns(cur.data(bm_len, "columns-present bitmap 2"),
                                ncol)
        if not cols2:
            raise Reject("columns-present bitmap has no bits set")
    rows = []
    while cur.remain() > 0:
        first = _read_image(cur, tmap, cols1)
        if op == "I":
            rows.append([event_index, tmap.db, tmap.table, op, None, first])
        elif op == "D":
            rows.append([event_index, tmap.db, tmap.table, op, first, None])
        else:  # U：前行镜像与后行镜像成对出现
            second = _read_image(cur, tmap, cols2)
            rows.append([event_index, tmap.db, tmap.table, op, first, second])
    return rows


# ---------------------------------------------------------------------------
# 事件流
# ---------------------------------------------------------------------------

def parse_stream(data):
    """解析整段事件字节流，返回 [event, db, table, op, old, new] 列表。

    event 为事件的零基序号（TABLE_MAP 也计入）。任一事件非法即整次拒绝，
    抛出 StreamError（offset 为出错事件的零基字节起点）。
    """
    maps = {}
    changes = []
    pos = 0
    event_index = 0
    while pos < len(data):
        start = pos
        try:
            if len(data) - pos < HEADER_LEN:
                raise Reject("truncated event header")
            etype = data[pos + 4]                       # 仅用类型
            elen = int.from_bytes(data[pos + 9:pos + 13], "little")  # 与长度
            if elen < HEADER_LEN + CHECKSUM_LEN:
                raise Reject("invalid event length %d" % elen)
            if pos + elen > len(data):
                raise Reject("truncated event")
            ev = data[pos:pos + elen]
            crc = int.from_bytes(ev[len(ev) - CHECKSUM_LEN:], "little")
            if zlib.crc32(ev[:len(ev) - CHECKSUM_LEN]) & 0xFFFFFFFF != crc:
                raise Reject("event checksum mismatch")
            body = ev[HEADER_LEN:len(ev) - CHECKSUM_LEN]
            if etype == TABLE_MAP_EVENT:
                table_id, tmap = _parse_table_map(body)
                maps[table_id] = tmap  # 按 table_id 替换
            elif etype in _OPS:
                changes.extend(_parse_rows_event(body, event_index, maps,
                                                 _OPS[etype]))
            else:
                raise Reject("unknown event type %d" % etype)
        except Reject as e:
            raise StreamError(start, event_index, str(e)) from None
        pos += elen
        event_index += 1
    return changes


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main(argv):
    args = argv[1:]
    if len(args) < 1 or len(args) > 2:
        sys.stderr.write(__doc__)
        return 2
    src = args[0]
    dst = args[1] if len(args) == 2 else "-"
    try:
        if src == "-":
            data = sys.stdin.buffer.read()
        else:
            with open(src, "rb") as f:
                data = f.read()
    except OSError as e:
        sys.stderr.write("error: cannot read input: %s\n" % e)
        return 2
    try:
        changes = parse_stream(data)
    except StreamError as e:
        sys.stderr.write("error: invalid event stream: event #%d "
                         "(byte offset %d): %s\n"
                         % (e.index, e.offset, e.message))
        return 1
    text = json.dumps(changes, ensure_ascii=False) + "\n"
    if dst == "-":
        sys.stdout.write(text)
        return 0
    # 成功才替换输出：先写同目录临时文件，再原子 rename
    outdir = os.path.dirname(os.path.abspath(dst))
    fd, tmp = tempfile.mkstemp(dir=outdir, prefix=".sparse_rows-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, dst)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        sys.stderr.write("error: cannot write output: %s\n" % e)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
