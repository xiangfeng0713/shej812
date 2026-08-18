"""局域网测试服务：账号登录与共享任务数据。仅用于内测，勿用于生产。"""
from __future__ import annotations

import argparse
import json
import secrets
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT.parent / "work" / "test-workflow-data.json"
TEST_PASSWORD = "123456"
USERS = [
    {"username": "admin_xiangfeng", "name": "向峰", "role": "超级管理员 / 设计经理", "department": "管理端"},
    {"username": "requester_chen_guopeng", "name": "陈国朋", "role": "需求提交人", "department": "国内电商"},
    {"username": "requester_chen_lingyu", "name": "陈凌宇", "role": "需求提交人", "department": "海外电商"},
    {"username": "requester_liu_qiqi", "name": "刘琦琪", "role": "需求提交人", "department": "产品市场"},
    {"username": "requester_peng_yanglu", "name": "彭阳陆", "role": "需求提交人", "department": "线下物料"},
    {"username": "designer_wei_wendong", "name": "魏文东", "role": "设计师", "department": "设计部"},
    {"username": "designer_wu_suyin", "name": "吴素吟", "role": "设计师", "department": "设计部"},
    {"username": "designer_xu_dudu", "name": "徐都都", "role": "设计师", "department": "设计部"},
    {"username": "approver_zhou_xuehua", "name": "周雪华", "role": "部门负责人审批（唯一负责人）", "department": "管理端"},
]
USER_MAP = {user["username"]: user for user in USERS}
SESSIONS: dict[str, str] = {}


def safe_user(user: dict) -> dict:
    return {key: user[key] for key in ("username", "name", "role", "department")}


def read_data() -> dict:
    if not DATA_FILE.exists():
        return {"tasks": [], "events": []}
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def write_data(data: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = DATA_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(DATA_FILE)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, data: dict, status=HTTPStatus.OK, cookie: str | None = None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def current_user(self):
        cookies = SimpleCookie(self.headers.get("Cookie"))
        token = cookies.get("ai_star_session")
        username = SESSIONS.get(token.value) if token else None
        return USER_MAP.get(username) if username else None

    def require_user(self):
        user = self.current_user()
        if not user:
            self.send_json({"error": "请先登录测试账号。"}, HTTPStatus.UNAUTHORIZED)
        return user

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/me":
            user = self.current_user()
            self.send_json({"user": safe_user(user) if user else None})
            return
        if path == "/api/test-users":
            self.send_json({"users": [safe_user(user) for user in USERS]})
            return
        if path == "/api/tasks":
            if not self.require_user():
                return
            self.send_json(read_data())
            return
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        payload = self.read_json()
        if path == "/api/login":
            user = USER_MAP.get(str(payload.get("username", "")).strip())
            if not user or payload.get("password") != TEST_PASSWORD:
                self.send_json({"error": "账号或测试密码错误。"}, HTTPStatus.UNAUTHORIZED)
                return
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = user["username"]
            self.send_json({"user": safe_user(user)}, cookie=f"ai_star_session={token}; HttpOnly; SameSite=Lax; Path=/")
            return
        if path == "/api/logout":
            cookies = SimpleCookie(self.headers.get("Cookie"))
            token = cookies.get("ai_star_session")
            if token:
                SESSIONS.pop(token.value, None)
            self.send_json({"ok": True}, cookie="ai_star_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            return
        if path == "/api/tasks":
            user = self.require_user()
            if not user:
                return
            task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
            if not task.get("name"):
                self.send_json({"error": "任务名称不能为空。"}, HTTPStatus.BAD_REQUEST)
                return
            data = read_data()
            record = {
                "id": secrets.token_hex(8),
                "name": str(task["name"]).strip(),
                "department": task.get("department", user["department"]),
                "type": task.get("type", "图片"),
                "quantity": task.get("quantity", 0),
                "stage": task.get("stage", "填写需求"),
                "created_by": safe_user(user),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            data["tasks"].append(record)
            data["events"].append({"type": "task_created", "task_id": record["id"], "at": record["created_at"], "by": safe_user(user)})
            write_data(data)
            self.send_json({"task": record}, HTTPStatus.CREATED)
            return
        self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"AI视觉·无界舱测试服务已启动：http://0.0.0.0:{args.port}")
    print("测试账户数据仅供内测，首次使用前请阅读 docs/test-accounts.md")
    server.serve_forever()


if __name__ == "__main__":
    main()
