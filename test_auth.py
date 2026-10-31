import os, tempfile, unittest, sqlite3
from app import AuthService

class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.s=AuthService(os.path.join(self.tmp.name,"test.db"),"test-secret-for-unit-tests")
    def tearDown(self): self.tmp.cleanup()
    def test_password_is_hashed_and_login_works(self):
        self.assertEqual(self.s.register("tester_1","correct-horse-battery-staple")[0],201)
        with self.s.connect() as db:
            stored=db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn("correct-horse-battery-staple",stored)
        self.assertTrue(self.s.verify_password("correct-horse-battery-staple",stored))
        status,_,token=self.s.login("tester_1","correct-horse-battery-staple")
        self.assertEqual(status,200); self.assertEqual(self.s.username_for(token),"tester_1")
    def test_input_validation(self):
        self.assertEqual(self.s.register("x","short")[0],400)
        self.assertEqual(self.s.register("bad name","long-password-value")[0],400)
    def test_generic_login_error(self):
        a=self.s.login("missing","wrong-password-long")[1]
        self.s.register("tester_1","correct-horse-battery-staple")
        b=self.s.login("tester_1","wrong-password-long")[1]
        self.assertEqual(a,b)
    def test_rate_limit(self):
        for _ in range(5): self.s.login("nobody","wrong-password","test-client")
        self.assertEqual(self.s.login("nobody","wrong-password","test-client")[0],429)
    def test_token_tampering(self):
        self.s.register("tester_1","correct-horse-battery-staple")
        _,_,token=self.s.login("tester_1","correct-horse-battery-staple")
        self.assertIsNotNone(self.s.read_token(token))
        self.assertIsNone(self.s.read_token(token+"x"))
    def test_duplicate_registration(self):
        self.assertEqual(self.s.register("tester_1","correct-horse-battery-staple")[0],201)
        self.assertEqual(self.s.register("tester_1","correct-horse-battery-staple")[0],409)

if __name__=="__main__": unittest.main()
