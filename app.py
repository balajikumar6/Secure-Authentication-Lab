import os, re, json, time, hmac, hashlib, secrets, sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse

DB_PATH=os.environ.get("AUTH_DB", os.path.join(os.path.dirname(__file__),"auth.db"))
SECRET_KEY=os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY=secrets.token_hex(32)  # local lab only; set a stable secret in deployment
COOKIE_SECURE=os.environ.get("COOKIE_SECURE","0")=="1"
WINDOW=60
MAX_ATTEMPTS=5

class AuthService:
    def __init__(self, db_path=DB_PATH, secret=SECRET_KEY):
        self.db_path=db_path; self.secret=secret.encode(); self.attempts={}
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)")
    def connect(self):
        db=sqlite3.connect(self.db_path); db.row_factory=sqlite3.Row; return db
    @staticmethod
    def valid_username(u):
        return isinstance(u,str) and re.fullmatch(r"[A-Za-z0-9_]{3,32}",u) is not None
    @staticmethod
    def hash_password(password, salt=None):
        salt=salt or secrets.token_bytes(16)
        digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1)
        return salt.hex()+":"+digest.hex()
    @staticmethod
    def verify_password(password, encoded):
        try:
            salt_hex,digest_hex=encoded.split(":")
            actual=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt_hex),n=2**14,r=8,p=1)
            return hmac.compare_digest(actual.hex(),digest_hex)
        except (ValueError, TypeError, AttributeError):
            return False
    def register(self, username, password):
        if not self.valid_username(username): return 400, {"error":"Invalid username format"}
        if not isinstance(password,str) or not 12<=len(password)<=128: return 400, {"error":"Password must be 12-128 characters"}
        try:
            with self.connect() as db:
                db.execute("INSERT INTO users(username,password_hash) VALUES (?,?)",(username,self.hash_password(password)))
            return 201, {"message":"Account created"}
        except sqlite3.IntegrityError:
            return 409, {"error":"Unable to create account"}
    def login(self, username, password, client="local"):
        key=f"{client}:{str(username).lower()[:64]}"
        now=time.time()
        recent=[t for t in self.attempts.get(key,[]) if now-t<WINDOW]
        if len(recent)>=MAX_ATTEMPTS:
            self.attempts[key]=recent
            return 429, {"error":"Too many attempts. Try again later."}, None
        recent.append(now); self.attempts[key]=recent
        with self.connect() as db:
            row=db.execute("SELECT id,password_hash FROM users WHERE username=?",(username,)).fetchone() if isinstance(username,str) else None
        if row is None or not isinstance(password,str) or not self.verify_password(password,row["password_hash"]):
            return 401, {"error":"Invalid username or password"}, None
        token=self.make_token(row["id"])
        return 200, {"message":"Login successful"}, token
    def make_token(self,user_id):
        payload=f"{user_id}:{int(time.time())+900}"
        sig=hmac.new(self.secret,payload.encode(),hashlib.sha256).hexdigest()
        return payload+"."+sig
    def read_token(self,token):
        try:
            payload,sig=token.rsplit(".",1)
            expected=hmac.new(self.secret,payload.encode(),hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig,expected): return None
            uid,expiry=payload.split(":")
            if int(expiry)<int(time.time()): return None
            return int(uid)
        except (ValueError,TypeError): return None
    def username_for(self,token):
        uid=self.read_token(token)
        if uid is None: return None
        with self.connect() as db:
            row=db.execute("SELECT username FROM users WHERE id=?",(uid,)).fetchone()
        return row["username"] if row else None

def run():
    service=AuthService()
    class Handler(BaseHTTPRequestHandler):
        def send_json(self,status,data,extra=None):
            body=json.dumps(data).encode()
            self.send_response(status); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body)))
            for k,v in (extra or {}).items(): self.send_header(k,v)
            self.end_headers(); self.wfile.write(body)
        def body(self):
            try:
                n=int(self.headers.get("Content-Length","0"))
                if n>4096: return None
                return json.loads(self.rfile.read(n) or b"{}")
            except (ValueError,json.JSONDecodeError): return None
        def token(self):
            c=SimpleCookie(); c.load(self.headers.get("Cookie",""))
            return c["auth_session"].value if "auth_session" in c else None
        def do_GET(self):
            if self.path=="/health": return self.send_json(200,{"status":"ok"})
            if self.path=="/me":
                username=service.username_for(self.token())
                return self.send_json(200,{"username":username}) if username else self.send_json(401,{"error":"Authentication required"})
            self.send_json(404,{"error":"Not found"})
        def do_POST(self):
            data=self.body()
            if data is None: return self.send_json(400,{"error":"Invalid request"})
            if self.path=="/register":
                status,result=service.register(data.get("username"),data.get("password"))
                return self.send_json(status,result)
            if self.path=="/login":
                status,result,token=service.login(data.get("username"),data.get("password"),self.client_address[0])
                headers={"Set-Cookie":f"auth_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900"+("; Secure" if COOKIE_SECURE else "")} if token else None
                return self.send_json(status,result,headers)
            if self.path=="/logout":
                return self.send_json(200,{"message":"Logged out"},{"Set-Cookie":"auth_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"})
            self.send_json(404,{"error":"Not found"})
        def log_message(self,*args): pass
    print("Local lab listening at http://127.0.0.1:5000")
    HTTPServer(("127.0.0.1",5000),Handler).serve_forever()

if __name__=="__main__": run()
