#!/usr/bin/env python3
"""
CTF Cheat Sheet — Local CORS Proxy
====================================
Запустите этот скрипт, затем включите тумблер "Прокси" в HTTP-клиенте.
Все запросы из браузера будут идти через этот скрипт — CORS не нужен.

Запуск:
    python3 proxy.py
    python3 proxy.py --port 9876   # другой порт

Остановка: Ctrl+C
"""
import sys, json, ssl, urllib.request, urllib.parse, urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 9876
for i, a in enumerate(sys.argv):
    if a in ("--port", "-p") and i + 1 < len(sys.argv):
        PORT = int(sys.argv[i + 1])

# SSL context that accepts self-signed certs (common in CTF)
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

SKIP_HEADERS = {"host", "content-length", "origin", "referer", "transfer-encoding"}

class Proxy(BaseHTTPRequestHandler):

    def cors(self, status=200):
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()

    def do_OPTIONS(self):
        self.cors()

    def dispatch(self):
        # GET /proxy?url=http://target.com/path
        parsed = urllib.parse.urlparse(self.path)
        qs     = urllib.parse.parse_qs(parsed.query)
        target = qs.get("url", [""])[0]

        if not target:
            self.cors(400)
            self.wfile.write(b'{"error":"missing ?url= parameter"}')
            return

        length   = int(self.headers.get("Content-Length", 0) or 0)
        req_body = self.rfile.read(length) if length else None

        fwd = {k: v for k, v in self.headers.items()
               if k.lower() not in SKIP_HEADERS}

        try:
            req  = urllib.request.Request(target, data=req_body,
                                          headers=fwd, method=self.command)
            kw   = {"timeout": 15}
            if target.startswith("https"):
                kw["context"] = CTX
            with urllib.request.urlopen(req, **kw) as r:
                body    = r.read()
                result  = {
                    "status":     r.status,
                    "statusText": r.reason,
                    "headers":    dict(r.headers),
                    "body":       body.decode("utf-8", errors="replace"),
                    "size":       len(body),
                }
        except urllib.error.HTTPError as e:
            body   = e.read()
            result = {
                "status":     e.code,
                "statusText": e.reason,
                "headers":    dict(e.headers) if e.headers else {},
                "body":       body.decode("utf-8", errors="replace"),
                "size":       len(body),
            }
        except Exception as e:
            result = {"status": 0, "statusText": "Error", "error": str(e),
                      "headers": {}, "body": "", "size": 0}

        self.cors()
        self.wfile.write(json.dumps(result, ensure_ascii=False).encode())

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = dispatch

    def log_message(self, fmt, *args):
        method = args[0].split()[0] if args else "?"
        url    = args[0].split("url=")[-1][:60] if "url=" in args[0] else args[0][:60]
        print(f"  {method} {urllib.parse.unquote(url)[:80]}  →  {args[1] if len(args)>1 else ''}")

if __name__ == "__main__":
    srv = HTTPServer(("localhost", PORT), Proxy)
    print(f"\n  CTF CORS Proxy запущен → http://localhost:{PORT}")
    print(f"  Включите тумблер «Прокси» в CTF Cheat Sheet → HTTP Клиент\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Остановлен.")
