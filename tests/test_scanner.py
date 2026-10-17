import csv
import tempfile
import unittest
from pathlib import Path
from pii_scanner import parse_folder_name, scan_csv_file, scan_value, run_scan
class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.folder=self.root/'01012026_DEMO_Example-abcd'
        self.folder.mkdir()
        self.file=self.folder/'synthetic.csv'
        self.file.write_text('contact,notes\nalice@example.invalid,synthetic neighbour\nsecond@example.invalid,other\n')
        self.meta=parse_folder_name(self.folder.name)
    def tearDown(self):self.temp.cleanup()
    def test_masked_by_default(self):
        hits=scan_csv_file(self.file,self.meta,'High',0)
        self.assertTrue(hits)
        self.assertTrue(all(h['matched_value']=='[REDACTED]' and h['full_cell_value']=='[REDACTED]' and not h['context'] for h in hits))
    def test_explicit_raw_opt_in(self):
        hits=scan_csv_file(self.file,self.meta,'High',0,True)
        self.assertEqual(hits[0]['matched_value'],'alice@example.invalid')
    def test_row_limit(self):
        hits=scan_csv_file(self.file,self.meta,'High',1)
        self.assertTrue(all(h['row_number']==1 for h in hits))
    def test_folder_metadata(self):self.assertEqual(self.meta['scan_date'],'2026-01-01')
    def test_card_checksum(self):
        self.assertFalse(any(x['pii_type']=='Credit Card' for x in scan_value('4111111111111112')))
        self.assertTrue(any(x['pii_type']=='Credit Card' for x in scan_value('4111111111111111')))
    def test_output_not_rescanned(self):
        out=self.folder/'output.csv'
        a=run_scan(str(self.root),str(out),'High',0)
        b=run_scan(str(self.root),str(out),'High',0)
        self.assertEqual(a,b)
    def test_negative_limit(self):
        with self.assertRaises(ValueError):run_scan(str(self.root),str(self.root/'out.csv'),'Low',-1)
    def test_formula_escaped(self):
        self.file.write_text('=header\nalice@example.invalid\n')
        out=self.root/'output.csv'
        run_scan(str(self.root),str(out),'High',0)
        with out.open(encoding='utf-8-sig') as f: row=next(csv.DictReader(f))
        self.assertEqual(row['column_name'],"'=header")
if __name__=='__main__':unittest.main()
