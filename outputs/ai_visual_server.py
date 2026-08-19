"""AI视觉·无界舱局域网服务：真实用户、人员库与共享需求数据。"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT.parent / "work" / "ai-visual-shared-data.json"
SESSIONS: dict[str, str] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(password: str, salt: str | None = None) -> dict[str, str]:
    raw_salt = base64.b64decode(salt) if salt else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw_salt, 210_000)
    return {"salt": base64.b64encode(raw_salt).decode("ascii"), "hash": base64.b64encode(digest).decode("ascii")}


def password_valid(password: str, user: dict) -> bool:
    if not password or not user.get("password"):
        return False
    stored = user["password"]
    actual = password_hash(password, stored["salt"])["hash"]
    return secrets.compare_digest(actual, stored["hash"])


def read_data() -> dict:
    if not DATA_FILE.exists():
        return {"users": [], "tasks": []}
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        data.setdefault("users", [])
        data.setdefault("tasks", [])
        return data
    except (json.JSONDecodeError, OSError):
        return {"users": [], "tasks": []}


def write_data(data: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = DATA_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(DATA_FILE)


def public_user(user: dict) -> dict:
    return {key: user.get(key, "") for key in ("id", "username", "name", "tag", "is_admin", "active")}


def active_users(data: dict) -> list[dict]:
    return [user for user in data["users"] if user.get("active", True)]


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, body: dict, status: HTTPStatus = HTTPStatus.OK, cookie: str | None = None):
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self) -> dict:
        size = int(self.headers.get("Content-Length", "0"))
        try:
            return json.loads(self.rfile.read(size).decode("utf-8")) if size else {}
        except json.JSONDecodeError:
            return {}

    def current_user(self, data: dict | None = None) -> dict | None:
        data = data or read_data()
        cookie = SimpleCookie(self.headers.get("Cookie"))
        token = cookie.get("ai_visual_session")
        user_id = SESSIONS.get(token.value) if token else None
        return next((user for user in data["users"] if user["id"] == user_id and user.get("active", True)), None)

    def require_user(self, data: dict | None = None) -> tuple[dict | None, dict]:
        data = data or read_data()
        user = self.current_user(data)
        if not user:
            self.send_json({"error": "请先登录。"}, HTTPStatus.UNAUTHORIZED)
        return user, data

    def require_admin(self, data: dict | None = None) -> tuple[dict | None, dict]:
        user, data = self.require_user(data)
        if user and not user.get("is_admin"):
            self.send_json({"error": "仅管理员可维护人员库。"}, HTTPStatus.FORBIDDEN)
            return None, data
        return user, data

    def do_GET(self):
        path = urlparse(self.path).path
        data = read_data()
        if path == "/api/bootstrap":
            self.send_json({"setup_required": not bool(data["users"])})
            return
        if path == "/api/me":
            user = self.current_user(data)
            self.send_json({"user": public_user(user) if user else None})
            return
        if path == "/api/users":
            user, data = self.require_user(data)
            if user:
                self.send_json({"users": [public_user(item) for item in active_users(data)]})
            return
        if path == "/api/tasks":
            user, data = self.require_user(data)
            if user:
                self.send_json({"tasks": data["tasks"]})
            return
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        payload = self.read_json()
        data = read_data()
        if path == "/api/bootstrap":
            if data["users"]:
                self.send_json({"error": "管理员已初始化。"}, HTTPStatus.CONFLICT)
                return
            password = str(payload.get("password", ""))
            if len(password) < 8:
                self.send_json({"error": "管理员密码至少需要 8 位。"}, HTTPStatus.BAD_REQUEST)
                return
            user = {"id": secrets.token_hex(12), "username": "xiangfeng", "name": "向峰", "tag": "管理", "is_admin": True, "active": True, "password": password_hash(password), "created_at": now()}
            data["users"].append(user)
            write_data(data)
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = user["id"]
            self.send_json({"user": public_user(user)}, HTTPStatus.CREATED, f"ai_visual_session={token}; HttpOnly; SameSite=Lax; Path=/")
            return
        if path == "/api/login":
            username = str(payload.get("username", "")).strip()
            user = next((item for item in data["users"] if item.get("username") == username and item.get("active", True)), None)
            if not user or not password_valid(str(payload.get("password", "")), user):
                self.send_json({"error": "账号或密码错误。"}, HTTPStatus.UNAUTHORIZED)
                return
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = user["id"]
            self.send_json({"user": public_user(user)}, cookie=f"ai_visual_session={token}; HttpOnly; SameSite=Lax; Path=/")
            return
        if path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie"))
            token = cookie.get("ai_visual_session")
            if token:
                SESSIONS.pop(token.value, None)
            self.send_json({"ok": True}, cookie="ai_visual_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            return
        if path == "/api/users":
            admin, data = self.require_admin(data)
            if not admin:
                return
            username = str(payload.get("username", "")).strip()
            name = str(payload.get("name", "")).strip()
            password = str(payload.get("password", ""))
            tag = str(payload.get("tag", "")).strip()
            if not username or not name or len(password) < 8:
                self.send_json({"error": "请填写账号、姓名和至少 8 位的初始密码。"}, HTTPStatus.BAD_REQUEST)
                return
            if any(item["username"] == username for item in data["users"]):
                self.send_json({"error": "该账号已存在。"}, HTTPStatus.CONFLICT)
                return
            user = {"id": secrets.token_hex(12), "username": username, "name": name, "tag": tag, "is_admin": False, "active": True, "password": password_hash(password), "created_at": now()}
            data["users"].append(user)
            write_data(data)
            self.send_json({"user": public_user(user)}, HTTPStatus.CREATED)
            return
        if path == "/api/tasks":
            user, data = self.require_user(data)
            if not user:
                return
            task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
            if not str(task.get("name", "")).strip():
                self.send_json({"error": "任务名称不能为空。"}, HTTPStatus.BAD_REQUEST)
                return
            record = {"id": secrets.token_hex(10), "name": str(task["name"]).strip(), "submitter": public_user(user), "department": str(task.get("department", "")), "type": str(task.get("type", "图片")), "quantity": int(task.get("quantity") or 0), "priority": str(task.get("priority", "常规")), "copy_link": str(task.get("copy_link", "")), "stage": "部门负责人审批", "created_at": now()}
            data["tasks"].append(record)
            write_data(data)
            self.send_json({"task": record}, HTTPStatus.CREATED)
            return
        self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/users/"):
            self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)
            return
        admin, data = self.require_admin()
        if not admin:
            return
        user_id = path.rsplit("/", 1)[-1]
        if user_id == admin["id"]:
            self.send_json({"error": "不能移除当前管理员。"}, HTTPStatus.BAD_REQUEST)
            return
        before = len(data["users"])
        data["users"] = [user for user in data["users"] if user["id"] != user_id]
        if len(data["users"]) == before:
            self.send_json({"error": "未找到该人员。"}, HTTPStatus.NOT_FOUND)
            return
        write_data(data)
        self.send_json({"ok": True})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"AI视觉·无界舱服务已启动：http://0.0.0.0:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
