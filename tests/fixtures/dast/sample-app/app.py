# threatlint-ignore-file: TL-PY-SQL-FSTRING deliberately vulnerable DAST fixture; runs only in the threatlint sandbox
"""Deliberately vulnerable sample shop used by the DAST validation tests. Never deploy it.

/search reflects q without encoding (reflected XSS), /greet encodes name (safe), /items builds SQL from id by string
concatenation (SQL injection), /product uses a bound parameter (safe), /health reports readiness.
"""
import html
import json
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO items (name) VALUES ('kettle'), ('teapot'), ('mug');")


def search(params):
    term = params.get("q", "")
    return 200, "text/html", f"<html><body><h1>Results for {term}</h1><p>No products found.</p></body></html>"


def greet(params):
    name = html.escape(params.get("name", "guest"), quote=True)
    return 200, "text/html", f"<html><body><p>Hello, {name}!</p></body></html>"


def items(params):
    query = "SELECT id, name FROM items WHERE id = " + params.get("id", "1")
    try:
        rows = DB.execute(query).fetchall()
    except sqlite3.Error as exc:
        return 500, "text/plain", f"sqlite3.OperationalError: {exc}"
    return 200, "application/json", json.dumps([{"id": row[0], "name": row[1]} for row in rows])


def product(params):
    rows = DB.execute("SELECT id, name FROM items WHERE id = ?", (params.get("id", "1"),)).fetchall()
    return 200, "application/json", json.dumps([{"id": row[0], "name": row[1]} for row in rows])


ROUTES = {"/search": search, "/greet": greet, "/items": items, "/product": product,
          "/health": lambda params: (200, "application/json", '{"status": "ok"}')}


class Handler(BaseHTTPRequestHandler):
    server_version = "SampleShop/1.0"

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        route = ROUTES.get(url.path)
        status, ctype, body = route(dict(urllib.parse.parse_qsl(url.query))) if route else (404, "text/plain", "not found")
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer((os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "8000"))), Handler).serve_forever()
