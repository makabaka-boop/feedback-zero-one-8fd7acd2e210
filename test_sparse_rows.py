#!/usr/bin/env python3
"""sparse_rows 的独立字节验收测试。

所有事件字节均由本文件按 MySQL 8.4.11 rows_event.h / json_binary 格式
独立拼装（常量就地重写，不引用被测模块），再交给 sparse_rows 解析，
校验输出数组或整次拒绝行为（含出错事件的零基字节起点）。

运行: python3 test_sparse_rows.py  （或 python3 -m unittest -v）
"""

import itertools
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sparse_rows as sr

HERE = os.path.dirname(os.path.abspath(__file__))
PROG = os.path.join(HERE, "sparse_rows.py")

# ---- 独立重写的格式常量 ----
T_TABLE_MAP = 19
T_WRITE_V2 = 30
T_UPDATE_V2 = 31
T_DELETE_V2 = 32
TY_LONGLONG = 8
TY_JSON = 245

JB_SMALL_OBJ, JB_LARGE_OBJ = 0x00, 0x01
JB_SMALL_ARR, JB_LARGE_ARR = 0x02, 0x03
JB_LIT, JB_I16, JB_U16 = 0x04, 0x05, 0x06
JB_I32, JB_U32, JB_I64, JB_U64 = 0x07, 0x08, 0x09, 0x0A
JB_DBL, JB_STR, JB_OPAQUE = 0x0B, 0x0C, 0x0F


# ---- 独立字节构造器 ----

def lenenc(n):
    if n < 0xFB:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfc" + n.to_bytes(2, "little")
    if n <= 0xFFFFFF:
        return b"\xfd" + n.to_bytes(3, "little")
    return b"\xfe" + n.to_bytes(8, "little")


def header(etype, total):
    # timestamp(4) type(1) server_id(4) event_size(4) log_pos(4) flags(2)
    return (0).to_bytes(4, "little") + bytes([etype]) \
        + (1).to_bytes(4, "little") + total.to_bytes(4, "little") \
        + (0).to_bytes(4, "little") + (0).to_bytes(2, "little")


def event(etype, body):
    h = header(etype, 19 + len(body) + 4)
    crc = zlib.crc32(h + body) & 0xFFFFFFFF
    return h + body + crc.to_bytes(4, "little")


def bitmap(bits):
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def table_map(tid, db, table, types, nullable, meta=b"", extra=b""):
    body = tid.to_bytes(6, "little") + b"\x01\x00"
    body += bytes([len(db)]) + db.encode("utf-8") + b"\x00"
    body += bytes([len(table)]) + table.encode("utf-8") + b"\x00"
    body += lenenc(len(types)) + bytes(types)
    body += lenenc(len(meta)) + meta
    body += bitmap(nullable)
    body += extra
    return event(T_TABLE_MAP, body)


def json_meta(types):
    return b"".join(b"\x00\x00\x00\x00" if t == TY_JSON else b""
                    for t in types)


def std_map(tid=1, db="d", table="t", types=(TY_LONGLONG, TY_JSON),
            nullable=(True, True)):
    types = list(types)
    return table_map(tid, db, table, types, list(nullable),
                     meta=json_meta(types))


def row_image(cols, vals):
    """cols: 出现列序号；vals: {col: ('null',)|('int',n)|('json',doc)}。"""
    body = bitmap([vals[c][0] == "null" for c in cols])
    for c in cols:
        v = vals[c]
        if v[0] == "null":
            continue
        if v[0] == "int":
            body += v[1].to_bytes(8, "little", signed=True)
        else:
            body += len(v[1]).to_bytes(4, "little") + v[1]
    return body


def rows_event(etype, tid, ncols, present1, rows, present2=None,
               extra_len=2):
    body = tid.to_bytes(6, "little") + b"\x00\x00" \
        + extra_len.to_bytes(2, "little")
    if extra_len > 2:
        body += b"\x00" * (extra_len - 2)
    body += lenenc(ncols) + bitmap(present1)
    if present2 is not None:
        body += bitmap(present2)
    body += rows
    return event(etype, body)


def jb_container(small, is_obj, items):
    """对象: items=[(key,(tcode,data))]；数组: items=[(tcode,data)]。
    data 为编码后的值载荷（嵌套容器为完整容器字节）；放得下就内联。"""
    offlen = 2 if small else 4
    hdrlen = 4 if small else 8
    count = len(items)
    if is_obj:
        keys = [k.encode("utf-8") for k, _ in items]
        vals = [v for _, v in items]
    else:
        keys, vals = None, items
    key_len = (offlen + 2) if is_obj else 0
    val_len = 1 + offlen
    data_off = hdrlen + count * (key_len + val_len)
    body = b""
    key_offs = []
    if is_obj:
        for k in keys:
            key_offs.append(data_off + len(body))
            body += k
    inline = {JB_LIT, JB_I16, JB_U16} if small \
        else {JB_LIT, JB_I16, JB_U16, JB_I32, JB_U32}
    val_fields = []
    for tcode, data in vals:
        if tcode in inline:
            assert len(data) <= offlen
            val_fields.append(bytes([tcode])
                              + data + b"\x00" * (offlen - len(data)))
        else:
            off = data_off + len(body)
            body += data
            val_fields.append(bytes([tcode]) + off.to_bytes(offlen, "little"))
    size = data_off + len(body)
    if small:
        head = count.to_bytes(2, "little") + size.to_bytes(2, "little")
    else:
        head = count.to_bytes(4, "little") + size.to_bytes(4, "little")
    out = head
    if is_obj:
        for k, koff in zip(keys, key_offs):
            out += koff.to_bytes(offlen, "little") + len(k).to_bytes(2, "little")
    for vf in val_fields:
        out += vf
    return out + body


def doc(tcode, payload=b""):
    return bytes([tcode]) + payload


def jb_str(s):
    raw = s.encode("utf-8")
    return bytes([JB_STR]) + lenenc(len(raw)) + raw


def i16(n):
    return n.to_bytes(2, "little", signed=True)


def i32(n):
    return n.to_bytes(4, "little", signed=True)


def i64(n):
    return n.to_bytes(8, "little", signed=True)


# ---- 追溯的独立暴力枚举（不经过被测模块的任何求解逻辑） ----

def _bjeq(x, y):
    """JSON 递归比较：对象忽略键序，布尔不同于整数。"""
    if isinstance(x, bool) or isinstance(y, bool):
        return type(x) is type(y) and x == y
    if isinstance(x, dict) and isinstance(y, dict):
        return set(x) == set(y) and all(_bjeq(x[k], y[k]) for k in x)
    if isinstance(x, list) and isinstance(y, list):
        return len(x) == len(y) and all(_bjeq(a, b) for a, b in zip(x, y))
    return type(x) is type(y) and x == y


def _bveq(a, b):
    """标签值比较：标签参与比较。"""
    if a[0] != b[0]:
        return False
    if a[0] == "sql":
        return True
    if a[0] == "int":
        return a[1] == b[1]
    return _bjeq(a[1], b[1])


def _bchain_ok(items, chain):
    """独立重写的身份链合法性：插入必链首、删除必链尾、值须相干。"""
    ops = [items[m][0] for m in chain]
    if ops.count("I") > 1 or ops.count("D") > 1:
        return False
    if "I" in ops and ops[0] != "I":
        return False
    if "D" in ops and ops[-1] != "D":
        return False
    st = {}
    for m in chain:
        op, old, new = items[m]
        if op == "I":
            st = dict(new)
            continue
        for c, v in old.items():
            if c in st and not _bveq(st[c], v):
                return False
            st[c] = v
        if op == "U":
            st.update(new)
    return True


def brute_trace(items):
    """独立枚举全部身份划分，返回 {"min_initial", "must_same"}。

    items: [(op, old, new)]，old/new 为 {列号字符串: 标签值} 或 None。
    按受限增长串枚举所有链划分，收集全部最优解后逐对判定。
    """
    n = len(items)
    best = [None]
    sols = [[]]

    def visit(i, assign, nchains, cost):
        if best[0] is not None and cost > best[0]:
            return
        if i == n:
            if best[0] is None or cost < best[0]:
                best[0] = cost
                sols[0] = [tuple(assign)]
            elif cost == best[0]:
                sols[0].append(tuple(assign))
            return
        for c in range(nchains):     # 接到既有链尾
            chain = [k for k in range(i) if assign[k] == c] + [i]
            if _bchain_ok(items, chain):
                assign[i] = c
                visit(i + 1, assign, nchains, cost)
        assign[i] = nchains          # 新开链（初始行或插入）
        if _bchain_ok(items, [i]):
            visit(i + 1, assign, nchains + 1,
                  cost + (0 if items[i][0] == "I" else 1))
        assign[i] = -1

    visit(0, [-1] * n, 0, 0)
    same = [[all(s[a] == s[b] for s in sols[0]) for b in range(n)]
            for a in range(n)]
    return {"min_initial": best[0], "must_same": same}


# JSON 文档池：(字节, 解析值)；含同值不同键序、布尔与整数 1 的对照
JSON_POOL = [
    (doc(JB_LIT, b"\x00"), None),
    (doc(JB_LIT, b"\x01"), True),
    (doc(JB_I16, i16(1)), 1),
    (doc(JB_I16, i16(2)), 2),
    (jb_str("a"), "a"),
    (doc(JB_SMALL_OBJ, jb_container(True, True, [
        ("a", (JB_I16, i16(1))), ("b", (JB_I16, i16(2)))])),
     {"a": 1, "b": 2}),
    (doc(JB_SMALL_OBJ, jb_container(True, True, [
        ("b", (JB_I16, i16(2))), ("a", (JB_I16, i16(1)))])),
     {"a": 1, "b": 2}),
    (doc(JB_SMALL_ARR, jb_container(True, False, [
        (JB_LIT, b"\x01"), (JB_I16, i16(1))])), [True, 1]),
]
JSON_VALUES = dict(JSON_POOL)


def _present(ncols, cols):
    return [c in cols for c in range(ncols)]


def _item_event(item, tid, ncols):
    """把一条 (op, old, new) 变更独立拼成对应行事件字节。"""
    op, old, new = item
    if op == "I":
        cols = sorted(new)
        return rows_event(T_WRITE_V2, tid, ncols, _present(ncols, cols),
                          row_image(cols, new))
    if op == "D":
        cols = sorted(old)
        return rows_event(T_DELETE_V2, tid, ncols, _present(ncols, cols),
                          row_image(cols, old))
    c1, c2 = sorted(old), sorted(new)
    return rows_event(T_UPDATE_V2, tid, ncols, _present(ncols, c1),
                      row_image(c1, old) + row_image(c2, new),
                      present2=_present(ncols, c2))


def _trace_stream_of(items, types, tid=1, db="d", table="t"):
    ncols = len(types)
    out = table_map(tid, db, table, types, [True] * ncols,
                    meta=json_meta(types))
    for item in items:
        out += _item_event(item, tid, ncols)
    return out


def _tagged_items(items):
    """把构造用原始元组镜像换算成解析输出形态的标签值。"""
    def conv(img):
        if img is None:
            return None
        out = {}
        for c, v in img.items():
            if v[0] == "null":
                out[str(c)] = ["sql"]
            elif v[0] == "int":
                out[str(c)] = ["int", v[1]]
            else:
                out[str(c)] = ["json", JSON_VALUES[v[1]]]
        return out
    return [(op, conv(old), conv(new)) for op, old, new in items]


def _rand_items(rng, types, n):
    ncols = len(types)

    def img():
        cols = [c for c in range(ncols) if rng.random() < 0.6]
        if not cols:
            cols = [rng.randrange(ncols)]
        d = {}
        for c in cols:
            if types[c] == TY_LONGLONG:
                d[c] = ("int", rng.randrange(3)) if rng.random() < 0.7 \
                    else ("null",)
            else:
                d[c] = ("json", rng.choice(JSON_POOL)[0]) \
                    if rng.random() < 0.7 else ("null",)
        return d

    items = []
    for _ in range(n):
        op = rng.choice("IUD")
        if op == "I":
            items.append(("I", None, img()))
        elif op == "U":
            items.append(("U", img(), img()))
        else:
            items.append(("D", img(), None))
    return items


# ---- 测试 ----

class TestBasic(unittest.TestCase):
    def test_empty_stream(self):
        self.assertEqual(sr.parse_stream(b""), [])

    def test_spec_examples(self):
        # 规格示例：JSON 载荷 04 00 -> ["json", null]；SQL 空值 -> ["sql"]
        m = std_map(types=(TY_JSON,), nullable=(True,))
        rows = row_image([0], {0: ("json", b"\x04\x00")}) \
            + row_image([0], {0: ("null",)})
        w = rows_event(T_WRITE_V2, 1, 1, [True], rows)
        got = sr.parse_stream(m + w)
        self.assertEqual(got, [
            [1, "d", "t", "I", None, {"0": ["json", None]}],
            [1, "d", "t", "I", None, {"0": ["sql"]}],
        ])

    def test_insert_sparse_and_int_range(self):
        m = std_map(types=(TY_LONGLONG, TY_JSON, TY_LONGLONG),
                    nullable=(True, True, True))
        # 缺列省略：只出现第 0、2 列
        rows = row_image([0, 2], {0: ("int", -1),
                                  2: ("int", 2 ** 63 - 1)})
        w = rows_event(T_WRITE_V2, 1, 3, [True, False, True], rows)
        got = sr.parse_stream(m + w)
        self.assertEqual(got, [[1, "d", "t", "I", None,
                                {"0": ["int", -1],
                                 "2": ["int", 2 ** 63 - 1]}]])

    def test_update_and_delete(self):
        m = std_map()
        before = row_image([0, 1], {0: ("int", 5),
                                    1: ("json", jb_str("a"))})
        after = row_image([1], {1: ("json", jb_str("b"))})  # 后镜像稀疏
        u = rows_event(T_UPDATE_V2, 1, 2, [True, True], before + after,
                       present2=[False, True])
        d = rows_event(T_DELETE_V2, 1, 2, [True, True],
                       row_image([0, 1], {0: ("int", 7), 1: ("null",)}))
        got = sr.parse_stream(m + u + d)
        self.assertEqual(got, [
            [1, "d", "t", "U",
             {"0": ["int", 5], "1": ["json", "a"]},
             {"1": ["json", "b"]}],
            [2, "d", "t", "D",
             {"0": ["int", 7], "1": ["sql"]}, None],
        ])

    def test_event_numbering_and_map_replace(self):
        m1 = std_map(tid=7, table="a", types=(TY_LONGLONG,),
                     nullable=(False,))
        w1 = rows_event(T_WRITE_V2, 7, 1, [True],
                        row_image([0], {0: ("int", 1)}))
        m2 = std_map(tid=7, db="d2", table="b", types=(TY_JSON,),
                     nullable=(True,))
        w2 = rows_event(T_WRITE_V2, 7, 1, [True],
                        row_image([0], {0: ("json", b"\x04\x01")}))
        got = sr.parse_stream(m1 + w1 + m2 + w2)
        self.assertEqual(got, [
            [1, "d", "a", "I", None, {"0": ["int", 1]}],
            [3, "d2", "b", "I", None, {"0": ["json", True]}],
        ])

    def test_two_tables_interleaved(self):
        m1 = std_map(tid=1, table="x", types=(TY_LONGLONG,),
                     nullable=(False,))
        m2 = std_map(tid=2, table="y", types=(TY_LONGLONG,),
                     nullable=(False,))
        w1 = rows_event(T_WRITE_V2, 1, 1, [True],
                        row_image([0], {0: ("int", 10)}))
        w2 = rows_event(T_DELETE_V2, 2, 1, [True],
                        row_image([0], {0: ("int", 20)}))
        got = sr.parse_stream(m1 + m2 + w1 + w2)
        self.assertEqual(got, [
            [2, "d", "x", "I", None, {"0": ["int", 10]}],
            [3, "d", "y", "D", {"0": ["int", 20]}, None],
        ])

    def test_bitmap_tail_bits_ignored(self):
        m = std_map(types=(TY_LONGLONG, TY_LONGLONG), nullable=(True, True))
        # 出现位图：仅第 1 列，尾位全部置 1（应忽略）
        present = bytes([0b11111110])
        # NULL 位图：1 个出现列占 1 位（不空），尾位置 1（应忽略）
        nullmap = bytes([0b11111110])
        body = (1).to_bytes(6, "little") + b"\x00\x00" + b"\x02\x00" \
            + lenenc(2) + present + nullmap + (9).to_bytes(8, "little")
        w = event(T_WRITE_V2, body)
        got = sr.parse_stream(m + w)
        self.assertEqual(got, [[1, "d", "t", "I", None,
                                {"1": ["int", 9]}]])


class TestJsonDocuments(unittest.TestCase):
    def roundtrip(self, doc_bytes):
        m = std_map(types=(TY_JSON,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("json", doc_bytes)}))
        got = sr.parse_stream(m + w)
        self.assertEqual(len(got), 1)
        return got[0][5]["0"][1]

    def test_literals_and_ints(self):
        self.assertIsNone(self.roundtrip(doc(JB_LIT, b"\x00")))
        self.assertIs(self.roundtrip(doc(JB_LIT, b"\x01")), True)
        self.assertIs(self.roundtrip(doc(JB_LIT, b"\x02")), False)
        self.assertEqual(self.roundtrip(doc(JB_I16, i16(-2))), -2)
        self.assertEqual(self.roundtrip(doc(JB_U16, (65535).to_bytes(2, "little"))),
                         65535)
        self.assertEqual(self.roundtrip(doc(JB_I32, i32(-70000))), -70000)
        self.assertEqual(self.roundtrip(doc(JB_U32, (4000000000).to_bytes(4, "little"))),
                         4000000000)
        self.assertEqual(self.roundtrip(doc(JB_I64, i64(-2))), -2)
        self.assertEqual(self.roundtrip(doc(JB_U64, (2 ** 64 - 1).to_bytes(8, "little"))),
                         2 ** 64 - 1)

    def test_strings(self):
        self.assertEqual(self.roundtrip(jb_str("héllo")), "héllo")
        self.assertEqual(self.roundtrip(jb_str("")), "")
        long_s = "x" * 300  # 触发多字节长度前缀
        self.assertEqual(self.roundtrip(jb_str(long_s)), long_s)

    def test_small_object(self):
        d = doc(JB_SMALL_OBJ, jb_container(True, True, [
            ("a", (JB_I16, i16(1))),
            ("b", (JB_STR, jb_str("hi")[1:])),
        ]))
        self.assertEqual(self.roundtrip(d), {"a": 1, "b": "hi"})

    def test_large_object(self):
        d = doc(JB_LARGE_OBJ, jb_container(False, True, [
            ("k", (JB_I32, i32(70000))),
            ("u", (JB_U32, (4000000000).to_bytes(4, "little"))),
            ("键", (JB_LIT, b"\x01")),
        ]))
        self.assertEqual(self.roundtrip(d),
                         {"k": 70000, "u": 4000000000, "键": True})

    def test_arrays_and_nesting(self):
        inner_obj = jb_container(True, True, [("z", (JB_LIT, b"\x00"))])
        inner_arr = jb_container(True, False, [
            (JB_I16, i16(1)),
            (JB_SMALL_OBJ, inner_obj),
        ])
        d = doc(JB_SMALL_OBJ, jb_container(True, True,
                                           [("arr", (JB_SMALL_ARR, inner_arr))]))
        self.assertEqual(self.roundtrip(d), {"arr": [1, {"z": None}]})

        big = doc(JB_LARGE_ARR, jb_container(False, False, [
            (JB_STR, jb_str("xy")[1:]),
            (JB_I64, i64(-2)),
            (JB_U64, (2 ** 64 - 1).to_bytes(8, "little")),
        ]))
        self.assertEqual(self.roundtrip(big), ["xy", -2, 2 ** 64 - 1])

    def test_empty_containers(self):
        d = doc(JB_SMALL_OBJ, jb_container(True, True, []))
        self.assertEqual(self.roundtrip(d), {})
        d = doc(JB_SMALL_ARR, jb_container(True, False, []))
        self.assertEqual(self.roundtrip(d), [])


class TestRejections(unittest.TestCase):
    """整次拒绝：校验抛出的 StreamError 及其零基事件起点。"""

    def assert_reject(self, stream, offset, index=0):
        with self.assertRaises(sr.StreamError) as cm:
            sr.parse_stream(stream)
        self.assertEqual(cm.exception.offset, offset)
        self.assertEqual(cm.exception.index, index)

    def test_truncated_header(self):
        self.assert_reject(b"\x00\x01\x02", 0)

    def test_truncated_event(self):
        h = header(T_TABLE_MAP, 100)  # 声明 100 字节，实际不足
        self.assert_reject(h + b"\x00" * 10, 0)

    def test_bad_event_length(self):
        h = header(T_TABLE_MAP, 10)  # 小于 头+CRC
        self.assert_reject(h + b"\x00" * 10, 0)

    def test_unknown_event_type(self):
        self.assert_reject(event(99, b"\x00"), 0)

    def test_bad_crc(self):
        m = bytearray(std_map(types=(TY_LONGLONG,), nullable=(True,)))
        m[25] ^= 0xFF  # 破坏事件体，CRC 不再匹配
        self.assert_reject(bytes(m), 0)

    def test_error_offset_after_valid_prefix(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        bad = event(99, b"")
        self.assert_reject(m + bad, len(m), index=1)

    def test_table_map_zero_columns(self):
        self.assert_reject(table_map(1, "d", "t", [], []), 0)

    def test_table_map_unsupported_type(self):
        self.assert_reject(table_map(1, "d", "t", [3], [True]), 0)

    def test_table_map_json_metadata_not_four(self):
        self.assert_reject(table_map(1, "d", "t", [TY_JSON], [True],
                                     meta=b"\x00"), 0)

    def test_table_map_optional_metadata_rejected(self):
        self.assert_reject(table_map(1, "d", "t", [TY_LONGLONG], [True],
                                     extra=b"\x00"), 0)

    def test_rows_unknown_table(self):
        w = rows_event(T_WRITE_V2, 9, 1, [True],
                       row_image([0], {0: ("int", 1)}))
        self.assert_reject(w, 0)

    def test_rows_column_count_mismatch(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 2, [True, True],
                       row_image([0, 1], {0: ("int", 1), 1: ("int", 2)}))
        self.assert_reject(m + w, len(m), index=1)

    def test_rows_extra_data_rejected(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 1)}), extra_len=4)
        self.assert_reject(m + w, len(m), index=1)

    def test_rows_empty_present_bitmap(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [False], b"")
        self.assert_reject(m + w, len(m), index=1)

    def test_update_empty_second_bitmap(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_UPDATE_V2, 1, 1, [True], b"", present2=[False])
        self.assert_reject(m + w, len(m), index=1)

    def test_null_in_not_null_column(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(False,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("null",)}))
        self.assert_reject(m + w, len(m), index=1)

    def test_truncated_row(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True], b"\x00\x2a")  # 值不足 8 字节
        self.assert_reject(m + w, len(m), index=1)

    def _reject_json(self, doc_bytes):
        m = std_map(types=(TY_JSON,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("json", doc_bytes)}))
        self.assert_reject(m + w, len(m), index=1)

    def test_json_double_rejected(self):
        self._reject_json(doc(JB_DBL, b"\x00" * 8))

    def test_json_opaque_rejected(self):
        self._reject_json(doc(JB_OPAQUE, b"\xf5\x01\x00"))

    def test_json_bad_literal(self):
        self._reject_json(doc(JB_LIT, b"\x03"))

    def test_json_trailing_bytes(self):
        self._reject_json(doc(JB_LIT, b"\x00") + b"\x00")

    def test_json_bad_utf8(self):
        self._reject_json(bytes([JB_STR, 1, 0xFF]))

    def test_json_duplicate_keys(self):
        d = doc(JB_SMALL_OBJ, jb_container(True, True, [
            ("a", (JB_LIT, b"\x01")),
            ("a", (JB_LIT, b"\x02")),
        ]))
        self._reject_json(d)

    def test_json_offset_out_of_bounds(self):
        # 小数组，一个字符串值，偏移远超容器
        d = bytes([JB_SMALL_ARR]) + (1).to_bytes(2, "little") \
            + (7).to_bytes(2, "little") + bytes([JB_STR]) \
            + (0x4000).to_bytes(2, "little")
        self._reject_json(d)

    def test_json_container_size_out_of_bounds(self):
        d = bytes([JB_SMALL_ARR]) + (1).to_bytes(2, "little") \
            + (0x4000).to_bytes(2, "little")
        self._reject_json(d)

    def test_json_empty_value(self):
        self._reject_json(b"")


class TestCli(unittest.TestCase):
    def run_cli(self, args, data=None):
        return subprocess.run([sys.executable, PROG] + args,
                              input=data, capture_output=True)

    def test_stdout_and_empty(self):
        r = self.run_cli(["-"], data=b"")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout.decode("utf-8")), [])

    def test_file_roundtrip(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 42)}))
        with tempfile.TemporaryDirectory() as td:
            inp = os.path.join(td, "in.bin")
            out = os.path.join(td, "out.json")
            with open(inp, "wb") as f:
                f.write(m + w)
            r = self.run_cli([inp, out])
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, encoding="utf-8") as f:
                self.assertEqual(json.load(f),
                                 [[1, "d", "t", "I", None,
                                   {"0": ["int", 42]}]])

    def test_failure_reports_offset_and_keeps_output(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        bad = event(99, b"")
        with tempfile.TemporaryDirectory() as td:
            inp = os.path.join(td, "in.bin")
            out = os.path.join(td, "out.json")
            with open(inp, "wb") as f:
                f.write(m + bad)
            with open(out, "w", encoding="utf-8") as f:
                f.write("SENTINEL")
            r = self.run_cli([inp, out])
            self.assertEqual(r.returncode, 1)
            self.assertIn(str(len(m)), r.stderr.decode("utf-8"))
            with open(out, encoding="utf-8") as f:
                self.assertEqual(f.read(), "SENTINEL")  # 失败不替换输出


class TestTrace(unittest.TestCase):
    """追溯入口：最少初始行数与必然身份关联。"""

    def trace(self, stream):
        return sr.trace_stream(stream)

    def test_empty_stream(self):
        self.assertEqual(self.trace(b""),
                         {"min_initial": 0, "must_same": []})

    def test_only_table_map(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        self.assertEqual(self.trace(m),
                         {"min_initial": 0, "must_same": []})

    def test_spec_example(self):
        # 规格示例：单列依次更新 1 为 2、删除 2 → 1，全 true 二阶矩阵
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        u = rows_event(T_UPDATE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 1)})
                       + row_image([0], {0: ("int", 2)}),
                       present2=[True])
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 2)}))
        self.assertEqual(self.trace(m + u + d), {
            "min_initial": 1,
            "must_same": [[True, True], [True, True]],
        })

    def test_later_observation_excludes_earlier_match(self):
        # 后续观测排除早期匹配：更新 1→2 之后删除 1，
        # 被更新的行已是 2，删除看到的 1 只能属于另一条初始行
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        u = rows_event(T_UPDATE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 1)})
                       + row_image([0], {0: ("int", 2)}),
                       present2=[True])
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 1)}))
        self.assertEqual(self.trace(m + u + d), {
            "min_initial": 2,
            "must_same": [[True, False], [False, True]],
        })

    def test_duplicate_rows_stay_distinct(self):
        # 重复行：同值插入仍是不同身份；删除只终结其一，但不必然是哪条
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        ins = row_image([0], {0: ("int", 5)})
        w = rows_event(T_WRITE_V2, 1, 1, [True], ins + ins)
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 5)}))
        self.assertEqual(self.trace(m + w + d), {
            "min_initial": 0,
            "must_same": [[True, False, False],
                          [False, True, False],
                          [False, False, True]],
        })

    def test_sql_null(self):
        # SQL 空值：NULL 等于 NULL，但不等于任何带标签的值
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("null",)}))
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("null",)}))
        self.assertEqual(self.trace(m + w + d), {
            "min_initial": 0,
            "must_same": [[True, True], [True, True]],
        })
        d0 = rows_event(T_DELETE_V2, 1, 1, [True],
                        row_image([0], {0: ("int", 0)}))
        self.assertEqual(self.trace(m + w + d0), {
            "min_initial": 1,
            "must_same": [[True, False], [False, True]],
        })

    def test_tags_participate(self):
        # 标签参与比较：["json", null] 与 ["sql"] 不同
        m = std_map(types=(TY_JSON,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("json", b"\x04\x00")}))
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("null",)}))
        self.assertEqual(self.trace(m + w + d), {
            "min_initial": 1,
            "must_same": [[True, False], [False, True]],
        })

    def test_json_key_order_and_bool_vs_int(self):
        # JSON 递归比较：对象忽略键序；布尔不同于整数
        m = std_map(types=(TY_JSON,), nullable=(True,))
        obj_ab = doc(JB_SMALL_OBJ, jb_container(True, True, [
            ("a", (JB_I16, i16(1))), ("b", (JB_I16, i16(2)))]))
        obj_ba = doc(JB_SMALL_OBJ, jb_container(True, True, [
            ("b", (JB_I16, i16(2))), ("a", (JB_I16, i16(1)))]))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("json", obj_ab)}))
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("json", obj_ba)}))
        self.assertEqual(self.trace(m + w + d), {
            "min_initial": 0,
            "must_same": [[True, True], [True, True]],
        })
        w_t = rows_event(T_WRITE_V2, 1, 1, [True],
                         row_image([0], {0: ("json", b"\x04\x01")}))
        d_1 = rows_event(T_DELETE_V2, 1, 1, [True],
                         row_image([0], {0: ("json", doc(JB_I16, i16(1)))}))
        self.assertEqual(self.trace(m + w_t + d_1), {
            "min_initial": 1,
            "must_same": [[True, False], [False, True]],
        })

    def test_insert_missing_column_binds_later(self):
        # 插入缺列未知：后续删除观测到该列即据此绑定，仍属同一身份
        m = std_map()
        w = rows_event(T_WRITE_V2, 1, 2, [True, False],
                       row_image([0], {0: ("int", 3)}))
        d = rows_event(T_DELETE_V2, 1, 2, [False, True],
                       row_image([1], {1: ("json", jb_str("x"))}))
        self.assertEqual(self.trace(m + w + d), {
            "min_initial": 0,
            "must_same": [[True, True], [True, True]],
        })

    def test_update_overwrites_only_new_image_columns(self):
        # 更新只覆盖新镜像出现列：旧镜像列保持绑定值
        m = std_map(types=(TY_LONGLONG, TY_LONGLONG),
                    nullable=(True, True))
        u = rows_event(T_UPDATE_V2, 1, 2, [True, False],
                       row_image([0], {0: ("int", 1)})
                       + row_image([1], {1: ("int", 7)}),
                       present2=[False, True])
        d = rows_event(T_DELETE_V2, 1, 2, [True, True],
                       row_image([0, 1], {0: ("int", 1), 1: ("int", 7)}))
        self.assertEqual(self.trace(m + u + d), {
            "min_initial": 1,
            "must_same": [[True, True], [True, True]],
        })
        # 删除若观测到与绑定值冲突的 0=2，则只能另属一条初始行
        d2 = rows_event(T_DELETE_V2, 1, 2, [True, True],
                        row_image([0, 1], {0: ("int", 2), 1: ("int", 7)}))
        got = self.trace(m + u + d2)
        self.assertEqual(got["min_initial"], 2)
        self.assertEqual(got["must_same"], [[True, False], [False, True]])

    def test_deleted_identity_not_reused(self):
        # 删除身份不可复用：I 5, D 5, D 5 → 两个删除分属插入行与一条
        # 初始行，但哪个删除终结插入行并不必然（两种最优解释并存）
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 5)}))
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 5)}))
        got = self.trace(m + w + d + d)
        self.assertEqual(got["min_initial"], 1)
        self.assertEqual(got["must_same"], [[True, False, False],
                                            [False, True, False],
                                            [False, False, True]])

    def test_groups_by_db_table(self):
        # 按库表名分组：各组独立求解，min_initial 求和，跨组恒不同身份
        m1 = std_map(tid=1, db="a", table="t", types=(TY_LONGLONG,),
                     nullable=(True,))
        m2 = std_map(tid=2, db="b", table="t", types=(TY_LONGLONG,),
                     nullable=(True,))
        u = rows_event(T_UPDATE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 1)})
                       + row_image([0], {0: ("int", 2)}),
                       present2=[True])
        w = rows_event(T_WRITE_V2, 2, 1, [True],
                       row_image([0], {0: ("int", 9)}))
        d = rows_event(T_DELETE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 2)}))
        self.assertEqual(self.trace(m1 + m2 + u + w + d), {
            "min_initial": 1,
            "must_same": [[True, False, True],
                          [False, True, False],
                          [True, False, True]],
        })

    def test_map_replace_same_signature_ok(self):
        # 同组同签名的映射替换（不同 table_id）不视为不一致
        m1 = std_map(tid=1, types=(TY_LONGLONG,), nullable=(True,))
        m2 = std_map(tid=2, types=(TY_LONGLONG,), nullable=(True,))
        w1 = rows_event(T_WRITE_V2, 1, 1, [True],
                        row_image([0], {0: ("int", 1)}))
        w2 = rows_event(T_WRITE_V2, 2, 1, [True],
                        row_image([0], {0: ("int", 2)}))
        got = self.trace(m1 + w1 + m2 + w2)
        self.assertEqual(got["min_initial"], 0)
        self.assertEqual(got["must_same"], [[True, False], [False, True]])

    def test_inconsistent_mapping_rejected(self):
        # 同组映射列类型或可空性不一致：整次拒绝，报相关事件零基起点
        m1 = std_map(tid=1, types=(TY_LONGLONG,), nullable=(True,))
        m2 = std_map(tid=2, types=(TY_JSON,), nullable=(True,))
        with self.assertRaises(sr.StreamError) as cm:
            self.trace(m1 + m2)
        self.assertEqual(cm.exception.offset, len(m1))
        self.assertEqual(cm.exception.index, 1)
        m3 = std_map(tid=2, types=(TY_LONGLONG,), nullable=(False,))
        with self.assertRaises(sr.StreamError) as cm:
            self.trace(m1 + m3)
        self.assertEqual(cm.exception.offset, len(m1))
        # 不同库表的分组互不受牵连
        m4 = std_map(tid=2, db="other", table="t2", types=(TY_JSON,),
                     nullable=(True,))
        self.assertEqual(self.trace(m1 + m4)["min_initial"], 0)

    def test_group_change_limit(self):
        # 每组最多 12 条行变更；超出即整次拒绝，报超限事件零基起点
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))

        def w(n, start=0):
            rows = b"".join(row_image([0], {0: ("int", i)})
                            for i in range(start, start + n))
            return rows_event(T_WRITE_V2, 1, 1, [True], rows)

        ok = m + w(12)
        self.assertEqual(self.trace(ok)["min_initial"], 0)
        with self.assertRaises(sr.StreamError) as cm:
            self.trace(m + w(13))
        self.assertEqual(cm.exception.offset, len(m))
        ev13 = w(1, start=12)
        with self.assertRaises(sr.StreamError) as cm:
            self.trace(ok + ev13)
        self.assertEqual(cm.exception.offset, len(ok))
        self.assertEqual(cm.exception.index, 2)
        # 分散到不同组则各自未超限
        m2 = std_map(tid=2, db="e", table="t", types=(TY_LONGLONG,),
                     nullable=(True,))
        w2 = rows_event(T_WRITE_V2, 2, 1, [True],
                        row_image([0], {0: ("int", 99)}))
        self.assertEqual(self.trace(ok + m2 + w2)["min_initial"], 0)


class TestTraceBruteForce(unittest.TestCase):
    """独立小例枚举核对：与暴力枚举全部身份划分的结果逐项一致。"""

    def check(self, items, types):
        stream = _trace_stream_of(items, types)
        want = brute_trace(_tagged_items(items))
        got = sr.trace_stream(stream)
        self.assertEqual(got, want, "items=%r types=%r" % (items, types))

    def test_exhaustive_int_short(self):
        # 单列、值域 {0,1}：长度 <= 3 的全部变更序列逐一核对
        atoms = [("I", None, {0: ("int", v)}) for v in (0, 1)]
        atoms += [("U", {0: ("int", o)}, {0: ("int", n)})
                  for o in (0, 1) for n in (0, 1)]
        atoms += [("D", {0: ("int", v)}, None) for v in (0, 1)]
        self.assertEqual(len(atoms), 8)
        for items in itertools.product(atoms, repeat=3):
            self.check(list(items), [TY_LONGLONG])
        for i in range(400):
            rng = random.Random(i)
            items = [rng.choice(atoms) for _ in range(4)]
            self.check(items, [TY_LONGLONG])

    def test_exhaustive_with_sql_null(self):
        # 含 SQL 空值：长度 <= 2 全枚举（NULL 只等于 NULL）
        imgs = [{0: ("int", 0)}, {0: ("int", 1)}, {0: ("null",)}]
        atoms = [("I", None, g) for g in imgs]
        atoms += [("U", g1, g2) for g1 in imgs for g2 in imgs]
        atoms += [("D", g, None) for g in imgs]
        self.assertEqual(len(atoms), 15)
        for items in itertools.product(atoms, repeat=2):
            self.check(list(items), [TY_LONGLONG])

    def test_random_sparse_and_json(self):
        # 稀疏缺列 + JSON 文档（含键序/布尔对照）的随机小例
        rng = random.Random(20261114)
        type_sets = [[TY_JSON], [TY_LONGLONG, TY_JSON],
                     [TY_JSON, TY_LONGLONG], [TY_LONGLONG, TY_LONGLONG]]
        for i in range(200):
            types = rng.choice(type_sets)
            items = _rand_items(rng, types, rng.randrange(1, 7))
            self.check(items, types)

    def test_two_groups_random(self):
        # 双组交错：min_initial 为各组之和，must_same 为对角块
        rng = random.Random(20261115)
        for _ in range(60):
            t1 = [rng.choice((TY_LONGLONG, TY_JSON))]
            t2 = [rng.choice((TY_LONGLONG, TY_JSON))]
            i1 = _rand_items(rng, t1, rng.randrange(0, 5))
            i2 = _rand_items(rng, t2, rng.randrange(0, 5))
            m1 = table_map(1, "d", "t", t1, [True], meta=json_meta(t1))
            m2 = table_map(2, "e", "t", t2, [True], meta=json_meta(t2))
            stream, g1, g2 = m1 + m2, [], []
            p = q = 0
            while p < len(i1) or q < len(i2):
                if q >= len(i2) or (p < len(i1) and rng.random() < 0.5):
                    stream += _item_event(i1[p], 1, 1)
                    g1.append(len(g1) + len(g2))
                    p += 1
                else:
                    stream += _item_event(i2[q], 2, 1)
                    g2.append(len(g1) + len(g2))
                    q += 1
            r1 = brute_trace(_tagged_items(i1))
            r2 = brute_trace(_tagged_items(i2))
            n = len(i1) + len(i2)
            want_same = [[a == b for b in range(n)] for a in range(n)]
            for a in range(len(i1)):
                for b in range(len(i1)):
                    want_same[g1[a]][g1[b]] = r1["must_same"][a][b]
            for a in range(len(i2)):
                for b in range(len(i2)):
                    want_same[g2[a]][g2[b]] = r2["must_same"][a][b]
            want = {"min_initial": r1["min_initial"] + r2["min_initial"],
                    "must_same": want_same}
            self.assertEqual(sr.trace_stream(stream), want,
                             "i1=%r i2=%r" % (i1, i2))


class TestTraceCli(unittest.TestCase):
    def run_cli(self, args, data=None):
        return subprocess.run([sys.executable, PROG] + args,
                              input=data, capture_output=True)

    def test_trace_stdout_empty(self):
        r = self.run_cli(["--trace", "-"], data=b"")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout.decode("utf-8")),
                         {"min_initial": 0, "must_same": []})

    def test_trace_file_atomic_replace(self):
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 1)}))
        with tempfile.TemporaryDirectory() as td:
            inp = os.path.join(td, "in.bin")
            out = os.path.join(td, "out.json")
            with open(inp, "wb") as f:
                f.write(m + w)
            r = self.run_cli(["--trace", inp, out])
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, encoding="utf-8") as f:
                self.assertEqual(json.load(f),
                                 {"min_initial": 0, "must_same": [[True]]})

    def test_trace_failure_keeps_output_and_reports_offset(self):
        # 映射不一致：整次拒绝，报相关事件零基起点，既有输出原样保留
        m = std_map(tid=1, types=(TY_LONGLONG,), nullable=(True,))
        m2 = std_map(tid=2, types=(TY_JSON,), nullable=(True,))
        with tempfile.TemporaryDirectory() as td:
            inp = os.path.join(td, "in.bin")
            out = os.path.join(td, "out.json")
            with open(inp, "wb") as f:
                f.write(m + m2)
            with open(out, "w", encoding="utf-8") as f:
                f.write("SENTINEL")
            r = self.run_cli(["--trace", inp, out])
            self.assertEqual(r.returncode, 1)
            self.assertIn(str(len(m)), r.stderr.decode("utf-8"))
            with open(out, encoding="utf-8") as f:
                self.assertEqual(f.read(), "SENTINEL")

    def test_old_entry_compatible(self):
        # 旧入口兼容：无 --trace 时行为不变
        m = std_map(types=(TY_LONGLONG,), nullable=(True,))
        w = rows_event(T_WRITE_V2, 1, 1, [True],
                       row_image([0], {0: ("int", 42)}))
        r = self.run_cli(["-"], data=m + w)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout.decode("utf-8")),
                         [[1, "d", "t", "I", None, {"0": ["int", 42]}]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
