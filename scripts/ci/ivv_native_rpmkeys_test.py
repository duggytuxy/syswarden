"""Only the reviewed signed RPM digests enter the isolated native verifier."""
import ast
from pathlib import Path
import unittest
from scripts.ci import release_ivv_current as previous
from scripts.ci import release_ivv_v4101 as current


class RPMIdentityTests(unittest.TestCase):
    def test_package_allowlist_equals_both_reviewed_plans(self):
        path = Path(__file__).with_name('ivv_native_rpmkeys.py')
        tree = ast.parse(path.read_text())
        constants = {t.targets[0].id: ast.literal_eval(t.value) for t in tree.body
                     if isinstance(t, ast.Assign) and isinstance(t.targets[0], ast.Name)
                     and t.targets[0].id in ('PACKAGES', 'TRUST_ROOT_SHA256', 'IMAGE')}
        expected = {Path(row['path']).name: row['sha256']
                    for module in (previous, current) for row in module.load_plan()['product_packages']
                    if row['path'].endswith('.rpm')}
        self.assertEqual(constants['PACKAGES'], expected)
        self.assertEqual(constants['TRUST_ROOT_SHA256'], 'e9c0ffd66f3e6a9addd2b7e347b84e8d92b34d1cc8e4f4f438d02eabe59c3874')
        self.assertEqual(constants['IMAGE'], 'sha256:9c045e9162bde53581444d916acf56af7c9cfe26415d1db1c107eeda5610c5d6')


if __name__ == '__main__': unittest.main()
