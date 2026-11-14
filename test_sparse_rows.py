#!/usr/bin/env python3
"""sparse_rows 的独立字节验收测试。

所有事件字节均由本文件按 MySQL 8.4.11 rows_event.h / json_binary 格式
独立拼装（常量就地重写，不引用被测模块），再交给 sparse_rows 解析，
校验输出数组或整次拒绝行为（含出错事件的零基字节起点）。

运行: python3 test_sparse_rows.py  （或 python3 -m unittest -v）
"""

import json
import os
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
