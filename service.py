"""跨境药研尽调资料室的服务入口。

- python3 service.py --check                 基础身份检查
- python3 service.py --data-dir ./data       启动受控资料室 HTTP API
- 不带 --data-dir 时仅提供原有 /health 健康检查
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE_ID = "biopharma-data-room"
SERVICE_NAME = "跨境药研尽调资料室"


def health_payload():
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


class Handler(BaseHTTPRequestHandler):
    """提供基础健康检查。"""

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        body = json.dumps(health_payload(), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--data-dir", help="受控资料室数据目录；提供时挂载完整 JSON API")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        print("基础检查通过")
        return
    if args.data_dir:
        from dataroom import DataRoom
        from dataroom.httpapi import build_server

        room = DataRoom(args.data_dir)
        server = build_server(room, host=args.host, port=args.port)
        print(f"{SERVICE_NAME} 已启动：{args.host}:{args.port}（数据目录 {args.data_dir}）")
        server.serve_forever()
        return
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
