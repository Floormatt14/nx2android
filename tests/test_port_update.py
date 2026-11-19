# porter update's helpers: the build folder and the recorded scan (porter/pipeline.py Port.update)
import json, tempfile, unittest
from pathlib import Path

from porter.upstream import BuildError
from porter.pipeline import Port


class Opt:
    pass


def port():
    p = Port.__new__(Port)   # the helpers read no state beyond their arguments
    return p


class FindWork(unittest.TestCase):
    def test_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td) / 'work'; work.mkdir()
            self.assertEqual(port().find_work(Path(td) / 'p-data', {'work': str(work)}, '1' * 16), work)

    def test_beside_the_pack(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td) / ('1' * 16 + '_build'); work.mkdir()
            self.assertEqual(port().find_work(Path(td) / 'p-data', {}, '1' * 16), work)

    def test_gone(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(BuildError) as c:
                port().find_work(Path(td) / 'p-data', {}, '1' * 16)
            self.assertIn('port with the dump', str(c.exception))


class ReadScan(unittest.TestCase):
    def test_reads(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td); (work / 'scan.json').write_text(json.dumps({'title_id': '1' * 16}), encoding='utf-8')
            self.assertEqual(port().read_scan(work, '1' * 16)['title_id'], '1' * 16)

    def test_missing(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(BuildError) as c:
                port().read_scan(Path(td), '1' * 16)
            self.assertIn('scan.json', str(c.exception))

    def test_other_game(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td); (work / 'scan.json').write_text(json.dumps({'title_id': '2' * 16}), encoding='utf-8')
            with self.assertRaises(BuildError) as c:
                port().read_scan(work, '1' * 16)
            self.assertIn('port again', str(c.exception))


if __name__ == '__main__':
    unittest.main()
