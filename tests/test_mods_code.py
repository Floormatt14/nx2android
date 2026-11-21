"""The runtime .ips/.ips32 parser's record offsets are image offsets: the 0x100-byte NSO-header bias the port-time bake
(porter/mods_layer.py) cuts too — the two halves' contract, validated against a real mod's .ips against its bake's rows
(155/155 identical). The test compiles mods_code.c's real parse_ips (sliced, with dm.h shimmed; tests/mods_code_fixture.c)
and checks it against the bake convention on synthetic patches, without game data."""
import ctypes as C
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'nxnative/dm/host/mods_code.c'
FIXTURE = ROOT / 'tests/mods_code_fixture.c'

SHIM_CUT = '// ---- below this line the test appends mods_code.c\'s parse_ips ----'
PARSE_CUT = '// ---- apply one folder'


def ips32(records, terminator=b'EEOF'):
    """A synthetic IPS32: [(file offset, bytes)]; a length-0 record is RLE: the next 3 bytes are (byte, run)."""
    d = b'IPS32'
    for off, data in records:
        if isinstance(data, tuple): d += off.to_bytes(4, 'big') + b'\x00\x00' + data[0] + data[1].to_bytes(2, 'big')
        else: d += off.to_bytes(4, 'big') + len(data).to_bytes(2, 'big') + data
    return d + terminator


# the bake's convention (porter/mods_layer.py parse_ips + the 0x100 cut): file offsets → image offsets, the record's length its byte count (an RLE record's: its run)
def bake(records):
    out = []
    for o, d in records:
        out.append((o - 0x100, d[1] if isinstance(d, tuple) else len(d)))
    return out


@unittest.skipUnless(shutil.which('cc'), 'a host C compiler is required')
class ModsIpsBias(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        source = SRC.read_text(encoding='utf-8')
        parse = source[source.index('static int parse_ips('):source.index(PARSE_CUT)]
        wrapper = Path(cls.tmp.name) / 'mods_code_adapter.c'
        wrapper.write_text(FIXTURE.read_text(encoding='utf-8').replace(SHIM_CUT, parse))
        lib = Path(cls.tmp.name) / 'mods_code.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', str(wrapper), '-o', str(lib)], check=True, capture_output=True)
        cls.lib = C.CDLL(str(lib))
        cls.parse = cls.lib.parse_records
        cls.parse.argtypes = [C.c_char_p, C.POINTER(C.c_uint64), C.POINTER(C.c_uint32), C.c_long]
        cls.parse.restype = C.c_long

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_parse(self, data):
        p = Path(self.tmp.name) / 'm.ips32'; p.write_bytes(data)
        offs = (C.c_uint64 * 64)(); lens = (C.c_uint32 * 64)()
        n = self.parse(str(p).encode(), offs, lens, 64)
        return n, list(offs)[:max(n, 0)], list(lens)[:max(n, 0)]

    def test_offsets_are_image_offsets(self):
        records = [(0x100 + 0x1000, b'\x01\x02\x03\x04'), (0x100 + 0x2000, bytes(8)), (0x100 + 0x1234, b'\xaa' * 3)]
        n, offs, lens = self.run_parse(ips32(records))
        self.assertEqual(n, 3)
        self.assertEqual(offs, [0x1000, 0x2000, 0x1234])   # file offset − 0x100: the image offset, as the bake's rows read
        self.assertEqual(lens, [4, 8, 3])

    def test_matches_the_bake_convention(self):
        records = [(0x100 + 0x1f56f64, b'\x64\x00\x04\xcb'), (0x100 + 0x1f55ca8, b'\xba\xca\xde\x14')]
        n, offs, lens = self.run_parse(ips32(records))
        self.assertEqual([(o, l) for o, l in zip(offs, lens)], bake(records))

    def test_rle_record_and_terminator(self):
        records = [(0x100 + 0x3000, (b'\x90', 16)), (0x100 + 0x4000, b'\x00\x00\x00\x14')]
        n, offs, lens = self.run_parse(ips32(records))
        self.assertEqual(n, 2)
        self.assertEqual((offs[0], lens[0]), (0x3000, 16))   # an RLE record's length is its run
        self.assertEqual((offs[1], lens[1]), (0x4000, 4))

    def test_a_header_record_refuses_the_file(self):
        n, offs, lens = self.run_parse(ips32([(0x50, b'\x00' * 4)]))   # a file offset inside the NSO header
        self.assertEqual(n, -1)   # refused whole, as mods_file skips a refused file

    def test_truncated_record_refuses_the_file(self):
        d = b'IPS32' + (0x100 + 0x1000).to_bytes(4, 'big') + (0xf570).to_bytes(2, 'big') + b'\x01'   # the record runs past the file
        n, offs, lens = self.run_parse(d)
        self.assertEqual(n, -1)


if __name__ == '__main__':
    unittest.main()
