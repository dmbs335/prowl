"""Minimal vulnerable web app testbed for prowl crawler testing.

Endpoints:
  /                     - Homepage with links
  /login                - Login form (GET=form, POST=auth)
  /register             - Register form (GET=form, POST=create)
  /dashboard            - Auth-required dashboard
  /profile/<id>         - User profile (IDOR candidate)
  /settings             - Auth-required settings
  /admin                - Admin panel (403 for non-admin)
  /admin/users          - Admin user list
  /admin/config         - Admin config
  /api/v1/users         - JSON API: user list
  /api/v1/users/<id>    - JSON API: single user
  /api/v1/search        - Search endpoint (query param)
  /api/v1/upload        - File upload (POST only)
  /api/v2/users         - API v2 (different response structure)
  /api/internal/debug   - Internal debug endpoint (403)
  /graphql              - Fake GraphQL endpoint
  /health               - Health check
  /robots.txt           - Robots file with hidden paths
  /sitemap.xml          - Sitemap
  /.env                 - Exposed env file (secret leak)
  /backup.sql           - Fake backup file
  /js/app.js            - JS bundle with embedded API routes
  /js/config.js         - JS config with API keys
  /checkout             - Checkout flow (multi-step)
  /checkout/confirm     - Checkout confirm
  /reset-password       - Password reset form

Run: python testbed.py
Then: python -m prowl crawl http://localhost:9999
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import re
from urllib.parse import urlparse, parse_qs

PORT = 9999

# Fake user DB
USERS = {
    "1": {"id": 1, "name": "alice", "email": "alice@test.com", "role": "user"},
    "2": {"id": 2, "name": "bob", "email": "bob@test.com", "role": "user"},
    "3": {"id": 3, "name": "admin", "email": "admin@test.com", "role": "admin"},
}

# Session store
SESSIONS = {}


class TestbedHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress logs

    def _send(self, code, body, content_type="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "TestbedApp/1.0 (Python)")
        self.send_header("X-Powered-By", "Flask")  # fake fingerprint
        if code == 302:
            pass  # Location already set
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def _send_json(self, code, data):
        self._send(code, json.dumps(data, indent=2), "application/json")

    def _send_redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Server", "TestbedApp/1.0 (Python)")
        self.end_headers()

    def _get_session(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "session=" in part:
                sid = part.split("=", 1)[1].strip()
                return SESSIONS.get(sid)
        return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        # === Pages ===
        if path == "/":
            self._send(200, HOME_HTML)

        elif path == "/login":
            self._send(200, LOGIN_HTML)

        elif path == "/register":
            self._send(200, REGISTER_HTML)

        elif path == "/dashboard":
            session = self._get_session()
            if not session:
                self._send_redirect("/login?next=/dashboard")
            else:
                self._send(200, DASHBOARD_HTML.replace("{{user}}", session["name"]))

        elif path == "/profile" or re.match(r"^/profile/(\d+)$", path):
            m = re.match(r"^/profile/(\d+)$", path)
            uid = m.group(1) if m else "1"
            user = USERS.get(uid)
            if user:
                self._send(200, PROFILE_HTML.replace("{{name}}", user["name"])
                           .replace("{{email}}", user["email"])
                           .replace("{{role}}", user["role"]))
            else:
                self._send(404, "<h1>User not found</h1>")

        elif path == "/settings":
            session = self._get_session()
            if not session:
                self._send_redirect("/login?next=/settings")
            else:
                self._send(200, SETTINGS_HTML)

        elif path == "/admin":
            session = self._get_session()
            if not session:
                self._send_redirect("/login?next=/admin")
            elif session.get("role") != "admin":
                self._send(403, "<h1>403 Forbidden</h1><p>Admin access required</p>")
            else:
                self._send(200, ADMIN_HTML)

        elif path == "/admin/users":
            session = self._get_session()
            if not session or session.get("role") != "admin":
                self._send(403, "<h1>403 Forbidden</h1>")
            else:
                self._send_json(200, list(USERS.values()))

        elif path == "/admin/config":
            session = self._get_session()
            if not session or session.get("role") != "admin":
                self._send(403, "<h1>403 Forbidden</h1>")
            else:
                self._send_json(200, {"debug": True, "db_host": "localhost:5432"})

        # === API v1 ===
        elif path == "/api/v1/users":
            self._send_json(200, {"users": list(USERS.values()), "total": len(USERS)})

        elif re.match(r"^/api/v1/users/(\d+)$", path):
            uid = re.match(r"^/api/v1/users/(\d+)$", path).group(1)
            user = USERS.get(uid)
            if user:
                self._send_json(200, user)
            else:
                self._send_json(404, {"error": "not found"})

        elif path == "/api/v1/search":
            q = qs.get("q", [""])[0]
            results = [u for u in USERS.values() if q.lower() in u["name"].lower()] if q else []
            self._send_json(200, {"query": q, "results": results, "count": len(results)})

        elif path == "/api/v1/upload":
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Server", "TestbedApp/1.0")
            self.end_headers()
            self.wfile.write(b"Method Not Allowed")

        # === API v2 ===
        elif path == "/api/v2/users":
            self._send_json(200, {"data": list(USERS.values()), "meta": {"page": 1, "per_page": 10}})

        elif re.match(r"^/api/v2/users/(\d+)$", path):
            uid = re.match(r"^/api/v2/users/(\d+)$", path).group(1)
            user = USERS.get(uid)
            if user:
                self._send_json(200, {"data": user, "meta": {"cached": False}})
            else:
                self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "User not found"}})

        # === Internal ===
        elif path == "/api/internal/debug":
            self._send(403, "<h1>403 Forbidden</h1>")

        elif path == "/graphql":
            self._send_json(200, {
                "data": {"__schema": {"queryType": {"name": "Query"}, "types": []}},
            })

        elif path == "/health":
            self._send_json(200, {"status": "ok", "version": "1.0.0"})

        elif path == "/robots.txt":
            self._send(200, ROBOTS_TXT, "text/plain")

        elif path == "/sitemap.xml":
            self._send(200, SITEMAP_XML, "application/xml")

        elif path == "/.env":
            self._send(200, ENV_FILE, "text/plain")

        elif path == "/backup.sql":
            self._send(200, "-- MySQL dump\n-- Database: testbed\nCREATE TABLE users...", "text/plain")

        elif path == "/js/app.js":
            self._send(200, APP_JS, "application/javascript")

        elif path == "/js/config.js":
            self._send(200, CONFIG_JS, "application/javascript")

        elif path == "/checkout":
            self._send(200, CHECKOUT_HTML)

        elif path == "/checkout/confirm":
            self._send(200, CHECKOUT_CONFIRM_HTML)

        elif path == "/reset-password":
            self._send(200, RESET_PASSWORD_HTML)

        else:
            self._send(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if path == "/login":
            params = parse_qs(body.decode())
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            if username == "admin" and password == "admin123":
                sid = "sess_admin_001"
                SESSIONS[sid] = {"name": "admin", "role": "admin"}
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", f"session={sid}; Path=/; HttpOnly")
                self.send_header("Server", "TestbedApp/1.0")
                self.end_headers()
            elif username == "alice" and password == "password":
                sid = "sess_alice_001"
                SESSIONS[sid] = {"name": "alice", "role": "user"}
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", f"session={sid}; Path=/; HttpOnly")
                self.send_header("Server", "TestbedApp/1.0")
                self.end_headers()
            else:
                self._send(401, LOGIN_HTML.replace("</form>",
                    '<p style="color:red">Invalid credentials</p></form>'))

        elif path == "/register":
            self._send(200, "<h1>Registration disabled</h1>")

        elif path == "/api/v1/upload":
            ct = self.headers.get("Content-Type", "")
            if "multipart" in ct:
                self._send_json(200, {"status": "uploaded", "filename": "test.txt"})
            elif "json" in ct:
                self._send_json(200, {"status": "accepted", "format": "json"})
            else:
                self._send_json(200, {"status": "accepted", "format": "form"})

        elif path == "/api/v1/search":
            try:
                data = json.loads(body) if body else {}
                q = data.get("query", "")
            except json.JSONDecodeError:
                self._send_json(400, {"error": "invalid JSON"})
                return
            results = [u for u in USERS.values() if q.lower() in u["name"].lower()] if q else []
            self._send_json(200, {"query": q, "results": results})

        elif path == "/graphql":
            try:
                data = json.loads(body) if body else {}
                query = data.get("query", "")
                if "IntrospectionQuery" in query or "__schema" in query:
                    self._send_json(200, GRAPHQL_INTROSPECTION)
                elif "users" in query:
                    self._send_json(200, {"data": {"users": list(USERS.values())}})
                else:
                    self._send_json(200, {"data": None})
            except Exception:
                self._send_json(400, {"errors": [{"message": "Bad request"}]})

        elif path == "/api/v1/users":
            # POST = create user (500 to simulate server processing)
            self._send_json(500, {"error": "Internal server error", "trace": "NullPointerException at UserService.java:42"})

        else:
            self._send(404, "<h1>404 Not Found</h1>")

    def do_DELETE(self):
        self._send(405, "Method Not Allowed")

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if re.match(r"^/api/v1/users/\d+$", path):
            self._send_json(200, {"status": "updated"})
        else:
            self._send(405, "Method Not Allowed")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()


# === HTML Templates ===

HOME_HTML = """<!DOCTYPE html>
<html>
<head><title>TestbedApp</title></head>
<body>
<h1>TestbedApp - Vulnerable Web Application</h1>
<nav>
  <a href="/login">Login</a> |
  <a href="/register">Register</a> |
  <a href="/dashboard">Dashboard</a> |
  <a href="/profile/1">Profile</a> |
  <a href="/settings">Settings</a> |
  <a href="/admin">Admin</a> |
  <a href="/api/v1/users">API Users</a> |
  <a href="/api/v1/search?q=test">Search</a> |
  <a href="/graphql">GraphQL</a> |
  <a href="/health">Health</a> |
  <a href="/checkout">Checkout</a> |
  <a href="/js/app.js">App JS</a>
</nav>
<form action="/api/v1/search" method="get">
  <input name="q" placeholder="Search users...">
  <button type="submit">Search</button>
</form>
</body>
</html>"""

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Login - TestbedApp</title></head>
<body>
<h1>Login</h1>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="abc123xyz">
  <label>Username: <input name="username" type="text"></label><br>
  <label>Password: <input name="password" type="password"></label><br>
  <button type="submit">Login</button>
</form>
<p><a href="/register">Register</a> | <a href="/reset-password">Forgot password?</a></p>
</body>
</html>"""

REGISTER_HTML = """<!DOCTYPE html>
<html>
<head><title>Register - TestbedApp</title></head>
<body>
<h1>Register</h1>
<form action="/register" method="post">
  <input type="hidden" name="csrf_token" value="def456uvw">
  <label>Username: <input name="username" type="text"></label><br>
  <label>Email: <input name="email" type="email"></label><br>
  <label>Password: <input name="password" type="password"></label><br>
  <label>Confirm: <input name="password_confirm" type="password"></label><br>
  <button type="submit">Register</button>
</form>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head><title>Dashboard - TestbedApp</title></head>
<body>
<h1>Welcome, {{user}}!</h1>
<p>You are logged in.</p>
<nav>
  <a href="/profile/1">My Profile</a> |
  <a href="/settings">Settings</a> |
  <a href="/admin">Admin Panel</a> |
  <a href="/api/v1/users">API</a>
</nav>
</body>
</html>"""

PROFILE_HTML = """<!DOCTYPE html>
<html>
<head><title>Profile - TestbedApp</title></head>
<body>
<h1>User Profile</h1>
<p>Name: {{name}}</p>
<p>Email: {{email}}</p>
<p>Role: {{role}}</p>
<a href="/profile/1">User 1</a> | <a href="/profile/2">User 2</a> | <a href="/profile/3">User 3</a>
</body>
</html>"""

SETTINGS_HTML = """<!DOCTYPE html>
<html>
<head><title>Settings - TestbedApp</title></head>
<body>
<h1>Account Settings</h1>
<form action="/settings" method="post">
  <label>Email: <input name="email" type="email" value="user@test.com"></label><br>
  <label>Old Password: <input name="old_password" type="password"></label><br>
  <label>New Password: <input name="new_password" type="password"></label><br>
  <button type="submit">Update</button>
</form>
</body>
</html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Admin - TestbedApp</title></head>
<body>
<h1>Admin Panel</h1>
<nav>
  <a href="/admin/users">User Management</a> |
  <a href="/admin/config">Server Config</a> |
  <a href="/api/internal/debug">Debug</a>
</nav>
</body>
</html>"""

CHECKOUT_HTML = """<!DOCTYPE html>
<html>
<head><title>Checkout - TestbedApp</title></head>
<body>
<h1>Checkout</h1>
<form action="/checkout/confirm" method="post">
  <input type="hidden" name="csrf_token" value="chk789">
  <label>Card Number: <input name="card_number" type="text"></label><br>
  <label>Expiry: <input name="expiry" type="text"></label><br>
  <label>CVV: <input name="cvv" type="text"></label><br>
  <label>Amount: <input name="amount" type="text" value="99.99"></label><br>
  <button type="submit">Pay Now</button>
</form>
</body>
</html>"""

CHECKOUT_CONFIRM_HTML = """<!DOCTYPE html>
<html><body><h1>Order Confirmed</h1><p>Thank you!</p><a href="/">Home</a></body>
</html>"""

RESET_PASSWORD_HTML = """<!DOCTYPE html>
<html>
<head><title>Reset Password</title></head>
<body>
<h1>Reset Password</h1>
<form action="/reset-password" method="post">
  <label>Email: <input name="email" type="email"></label><br>
  <label>New Password: <input name="new_password" type="password"></label><br>
  <label>Confirm: <input name="new_password_confirm" type="password"></label><br>
  <button type="submit">Reset</button>
</form>
</body>
</html>"""

ROBOTS_TXT = """User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /.env
Disallow: /backup.sql
Sitemap: http://localhost:9999/sitemap.xml
"""

SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://localhost:9999/</loc></url>
  <url><loc>http://localhost:9999/login</loc></url>
  <url><loc>http://localhost:9999/register</loc></url>
  <url><loc>http://localhost:9999/api/v1/users</loc></url>
  <url><loc>http://localhost:9999/api/v2/users</loc></url>
  <url><loc>http://localhost:9999/health</loc></url>
  <url><loc>http://localhost:9999/graphql</loc></url>
</urlset>"""

ENV_FILE = """# Environment Variables
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASS=supersecret123
SECRET_KEY=d41d8cd98f00b204e9800998ecf8427e
API_KEY=sk_live_abcdef1234567890
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
"""

APP_JS = """
// TestbedApp Frontend
const API_BASE = "/api/v1";
const API_V2 = "/api/v2";

async function fetchUsers() {
    const res = await fetch(`${API_BASE}/users`);
    return res.json();
}

async function getUser(id) {
    const res = await fetch(`${API_BASE}/users/${id}`);
    return res.json();
}

async function searchUsers(query) {
    const res = await fetch(`${API_BASE}/search?q=${query}`);
    return res.json();
}

async function uploadFile(file) {
    const formData = new FormData();
    formData.append("file", file);
    return fetch(`${API_BASE}/upload`, { method: "POST", body: formData });
}

async function deleteUser(id) {
    return fetch(`${API_BASE}/users/${id}`, { method: "DELETE" });
}

async function updateUser(id, data) {
    return fetch(`${API_BASE}/users/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });
}

// Admin-only endpoints
async function getDebugInfo() {
    return fetch("/api/internal/debug");
}

async function getAdminConfig() {
    return fetch("/admin/config");
}

// GraphQL
async function gqlQuery(query) {
    return fetch("/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
    });
}

// Routes
const routes = {
    "/": "home",
    "/login": "login",
    "/dashboard": "dashboard",
    "/profile/:id": "profile",
    "/settings": "settings",
    "/admin": "admin",
    "/checkout": "checkout",
};
"""

CONFIG_JS = """
// App Configuration
const CONFIG = {
    apiUrl: "http://localhost:9999/api/v1",
    apiKey: "pk_test_1234567890abcdef",
    debugMode: true,
    analyticsId: "UA-12345678-1",
    sentryDsn: "https://abc123@sentry.io/456",
    stripeKey: "pk_test_TYooMQauvdEDq54NiTphI7jx",
};
"""

GRAPHQL_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "kind": "OBJECT", "name": "Query",
                    "fields": [
                        {"name": "users", "args": [{"name": "limit", "type": {"kind": "SCALAR", "name": "Int", "ofType": None}}],
                         "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "User"}}},
                        {"name": "user", "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID"}}}],
                         "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                        {"name": "search", "args": [{"name": "query", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}],
                         "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "User"}}},
                    ],
                },
                {
                    "kind": "OBJECT", "name": "Mutation",
                    "fields": [
                        {"name": "createUser", "args": [
                            {"name": "input", "type": {"kind": "INPUT_OBJECT", "name": "CreateUserInput", "ofType": None}},
                        ], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                        {"name": "deleteUser", "args": [
                            {"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID"}}},
                        ], "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None}},
                    ],
                },
                {
                    "kind": "OBJECT", "name": "User",
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                        {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        {"name": "role", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                    ],
                },
                {
                    "kind": "INPUT_OBJECT", "name": "CreateUserInput",
                    "inputFields": [
                        {"name": "name", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String"}}},
                        {"name": "email", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String"}}},
                        {"name": "password", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String"}}},
                    ],
                },
            ],
        }
    }
}


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), TestbedHandler)
    print(f"Testbed running on http://localhost:{PORT}")
    print("Endpoints: /, /login, /register, /dashboard, /profile/<id>,")
    print("  /settings, /admin, /admin/users, /admin/config,")
    print("  /api/v1/users, /api/v1/users/<id>, /api/v1/search,")
    print("  /api/v1/upload, /api/v2/users, /api/internal/debug,")
    print("  /graphql, /health, /robots.txt, /sitemap.xml,")
    print("  /.env, /backup.sql, /js/app.js, /js/config.js,")
    print("  /checkout, /reset-password")
    print("Login: alice/password or admin/admin123")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
