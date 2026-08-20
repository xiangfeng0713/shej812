"""AI视觉·无界舱局域网服务：真实用户、人员库与共享需求数据。"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT.parent / "work" / "ai-visual-shared-data.json"
SESSIONS: dict[str, tuple[str, float]] = {}
SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_JSON_BYTES = 64 * 1024
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 10 * 60
LOGIN_BLOCK_SECONDS = 15 * 60
LOGIN_ATTEMPTS: dict[str, dict[str, float | int]] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = (user_id, time.time() + SESSION_TTL_SECONDS)
    return token


def login_is_allowed(client_ip: str) -> bool:
    record = LOGIN_ATTEMPTS.get(client_ip)
    if not record:
        return True
    current = time.time()
    if current < record.get("blocked_until", 0):
        return False
    if current - record.get("first_at", current) > LOGIN_WINDOW_SECONDS:
        LOGIN_ATTEMPTS.pop(client_ip, None)
    return True


def record_login_failure(client_ip: str) -> None:
    current = time.time()
    record = LOGIN_ATTEMPTS.get(client_ip, {"count": 0, "first_at": current, "blocked_until": 0})
    if current - record["first_at"] > LOGIN_WINDOW_SECONDS:
        record = {"count": 0, "first_at": current, "blocked_until": 0}
    record["count"] += 1
    if record["count"] >= LOGIN_MAX_ATTEMPTS:
        record["blocked_until"] = current + LOGIN_BLOCK_SECONDS
    LOGIN_ATTEMPTS[client_ip] = record


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


def user_by_name(data: dict, name: str) -> dict | None:
    return next((user for user in active_users(data) if user["name"] == name), None)


def user_by_id(data: dict, user_id: str) -> dict | None:
    return next((user for user in active_users(data) if user["id"] == user_id), None)


def admin_user(data: dict) -> dict | None:
    return next((user for user in active_users(data) if user.get("is_admin")), None)


def stage_assignees(data: dict, task: dict, action: str, payload: dict) -> tuple[str, list[str]]:
    submitter_id = task["submitter"]["id"]
    stored_owner = task.get("design_owner", {}) or {}
    stored_partner = task.get("coop_designer", {}) or {}
    owner = user_by_id(data, str(stored_owner.get("id", ""))) or user_by_name(data, str(payload.get("design_owner", stored_owner.get("name", ""))))
    partner = user_by_id(data, str(stored_partner.get("id", ""))) or user_by_name(data, str(payload.get("coop_designer", stored_partner.get("name", ""))))
    admin = admin_user(data)
    if action == "approval_pass":
        return "设计需求分配", [admin["id"]] if admin else []
    if action == "approval_return":
        task["resubmit_stage"] = "部门负责人审批"
        task["resubmit_assignee_ids"] = [task["approver"]["id"]]
        return "填写需求", [submitter_id]
    if action == "allocation_confirm":
        if not owner:
            raise ValueError("请选择设计负责人。")
        task["design_owner"] = public_user(owner)
        task["coop_designer"] = public_user(partner) if partner else None
        return "需求校对", [user["id"] for user in (owner, partner) if user]
    if action == "proof_pass":
        if not owner:
            raise ValueError("请先完成设计负责人分配。")
        return "需求交付", [owner["id"]]
    if action == "proof_return":
        if not owner:
            raise ValueError("请先完成设计负责人分配。")
        task["resubmit_stage"] = "需求校对"
        task["resubmit_assignee_ids"] = [user["id"] for user in (owner, partner) if user]
        return "填写需求", [submitter_id]
    if action == "resubmit":
        return task.pop("resubmit_stage", "部门负责人审批"), task.pop("resubmit_assignee_ids", [task["approver"]["id"]])
    if action == "delivery_confirm":
        return "初稿审核", [admin["id"]] if admin else []
    if action == "review_pass":
        return "需求方验收 / 评分", [submitter_id]
    if action == "review_return":
        if not owner:
            raise ValueError("请先完成设计负责人分配。")
        return "需求交付", [owner["id"]]
    if action == "acceptance_pass":
        return "验收完结", []
    if action == "acceptance_return":
        if not owner:
            raise ValueError("请先完成设计负责人分配。")
        return "需求交付", [owner["id"]]
    raise ValueError("不支持的流程操作。")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        super().end_headers()

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

    def read_json(self) -> dict | None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json({"error": "请求格式错误。"}, HTTPStatus.BAD_REQUEST)
            return None
        if size < 0 or size > MAX_JSON_BYTES:
            self.send_json({"error": "请求数据过大。"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
        try:
            return json.loads(self.rfile.read(size).decode("utf-8")) if size else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json({"error": "请求格式错误。"}, HTTPStatus.BAD_REQUEST)
            return None

    def current_user(self, data: dict | None = None) -> dict | None:
        data = data or read_data()
        cookie = SimpleCookie(self.headers.get("Cookie"))
        token = cookie.get("ai_visual_session")
        session = SESSIONS.get(token.value) if token else None
        if not session:
            return None
        user_id, expires_at = session
        if time.time() >= expires_at:
            SESSIONS.pop(token.value, None)
            return None
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
                my_tasks = [task for task in data["tasks"] if user["id"] in task.get("assignee_ids", [])]
                submitted_tasks = [task for task in data["tasks"] if task.get("submitter", {}).get("id") == user["id"]]
                processed_tasks = [
                    task for task in data["tasks"]
                    if any(entry.get("by", {}).get("id") == user["id"] and entry.get("action") != "submitted" for entry in task.get("history", []))
                ]
                self.send_json({"tasks": data["tasks"], "my_tasks": my_tasks, "submitted_tasks": submitted_tasks, "processed_tasks": processed_tasks})
            return
        if path not in {"/", "/ai-starrail-design-console.html"} and not path.startswith("/inspiration-assets/"):
            self.send_json({"error": "资源不存在。"}, HTTPStatus.NOT_FOUND)
            return
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        payload = self.read_json()
        if payload is None:
            return
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
            token = create_session(user["id"])
            self.send_json({"user": public_user(user)}, HTTPStatus.CREATED, f"ai_visual_session={token}; HttpOnly; SameSite=Lax; Path=/")
            return
        if path == "/api/login":
            username = str(payload.get("username", "")).strip()
            client_ip = self.client_address[0]
            if not login_is_allowed(client_ip):
                self.send_json({"error": "登录失败次数过多，请 15 分钟后再试。"}, HTTPStatus.TOO_MANY_REQUESTS)
                return
            user = next((item for item in data["users"] if item.get("username") == username and item.get("active", True)), None)
            if not user or not password_valid(str(payload.get("password", "")), user):
                record_login_failure(client_ip)
                self.send_json({"error": "账号或密码错误。"}, HTTPStatus.UNAUTHORIZED)
                return
            LOGIN_ATTEMPTS.pop(client_ip, None)
            token = create_session(user["id"])
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
            submitter = user_by_name(data, str(task.get("submitter", "")))
            approver = user_by_name(data, str(task.get("approver", "")))
            if not submitter:
                self.send_json({"error": "请选择提交人姓名。"}, HTTPStatus.BAD_REQUEST)
                return
            if not approver:
                self.send_json({"error": "请选择需求内部审批人。"}, HTTPStatus.BAD_REQUEST)
                return
            created_at = now()
            record = {"id": secrets.token_hex(10), "name": str(task["name"]).strip(), "submitter": public_user(submitter), "created_by": public_user(user), "approver": public_user(approver), "department": str(task.get("department", "")), "type": str(task.get("type", "图片")), "quantity": int(task.get("quantity") or 0), "priority": str(task.get("priority", "常规")), "copy_link": str(task.get("copy_link", "")), "stage": "部门负责人审批", "assignee_ids": [approver["id"]], "history": [{"action": "submitted", "by": public_user(user), "at": created_at}], "created_at": created_at, "updated_at": created_at}
            record.update({
                "submit_date": str(task.get("submit_date", "")),
                "submit_time": str(task.get("submit_time", "")),
                "delivery_date": str(task.get("delivery_date", "")),
                "delivery_time": str(task.get("delivery_time", "")),
                "image_spec": str(task.get("image_spec", "")),
            })
            data["tasks"].append(record)
            write_data(data)
            self.send_json({"task": record}, HTTPStatus.CREATED)
            return
        if path.startswith("/api/tasks/") and path.endswith("/priority"):
            user, data = self.require_user(data)
            if not user:
                return
            task_id = path.removeprefix("/api/tasks/").removesuffix("/priority").strip("/")
            task = next((item for item in data["tasks"] if item["id"] == task_id), None)
            if not task:
                self.send_json({"error": "未找到该任务。"}, HTTPStatus.NOT_FOUND)
                return
            is_submitter = user["id"] in {
                task.get("submitter", {}).get("id"),
                task.get("created_by", {}).get("id"),
            }
            if not user.get("is_admin") and not is_submitter:
                self.send_json({"error": "仅任务提交人或超级管理员可以调整优先级。"}, HTTPStatus.FORBIDDEN)
                return
            priority = str(payload.get("priority", "")).strip()
            if priority not in {"常规", "中等", "加急"}:
                self.send_json({"error": "请选择常规、中等或加急。"}, HTTPStatus.BAD_REQUEST)
                return
            task["priority"] = priority
            task["pinned"] = True
            task["updated_at"] = now()
            task.setdefault("history", []).append({
                "action": "priority_adjusted",
                "by": public_user(user),
                "comment": priority,
                "at": task["updated_at"],
            })
            write_data(data)
            self.send_json({"task": task})
            return
        self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/tasks/"):
            self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)
            return
        user, data = self.require_user()
        if not user:
            return
        task_id = path.rsplit("/", 1)[-1]
        task = next((item for item in data["tasks"] if item["id"] == task_id), None)
        if not task:
            self.send_json({"error": "未找到该任务。"}, HTTPStatus.NOT_FOUND)
            return
        is_admin_override = user.get("is_admin") and user["id"] not in task.get("assignee_ids", [])
        if not is_admin_override and user["id"] not in task.get("assignee_ids", []):
            self.send_json({"error": "该任务当前不在你的待办中。"}, HTTPStatus.FORBIDDEN)
            return
        payload = self.read_json()
        if payload is None:
            return
        previous_stage = task["stage"]
        try:
            task["stage"], task["assignee_ids"] = stage_assignees(data, task, str(payload.get("action", "")), payload)
        except ValueError as error:
            self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
            return
        comment = str(payload.get("comment", "")).strip()
        if str(payload.get("action", "")) == "delivery_confirm":
            task.update({
                "shared_path": str(payload.get("shared_path", "")).strip(),
                "final_delivery_date": str(payload.get("final_delivery_date", "")).strip(),
                "final_delivery_time": str(payload.get("final_delivery_time", "")).strip(),
            })
        if comment:
            task["last_return"] = {"comment": comment, "by": public_user(user), "at": now()}
        task.setdefault("history", []).append({"action": str(payload.get("action", "")), "from_stage": previous_stage, "to_stage": task["stage"], "by": public_user(user), "comment": comment, "admin_override": bool(is_admin_override), "at": now()})
        task["updated_at"] = now()
        write_data(data)
        self.send_json({"task": task})

    def do_PATCH(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/users/"):
            self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)
            return
        admin, data = self.require_admin()
        if not admin:
            return
        user_id = path.rsplit("/", 1)[-1]
        user = next((item for item in data["users"] if item["id"] == user_id), None)
        if not user:
            self.send_json({"error": "未找到该人员。"}, HTTPStatus.NOT_FOUND)
            return
        payload = self.read_json()
        username = str(payload.get("username", "")).strip()
        name = str(payload.get("name", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not name:
            self.send_json({"error": "账号和姓名不能为空。"}, HTTPStatus.BAD_REQUEST)
            return
        if any(item["id"] != user_id and item["username"] == username for item in data["users"]):
            self.send_json({"error": "该账号已存在。"}, HTTPStatus.CONFLICT)
            return
        if password and len(password) < 8:
            self.send_json({"error": "新密码至少需要 8 位。"}, HTTPStatus.BAD_REQUEST)
            return
        user["username"] = username
        user["name"] = name
        user["tag"] = str(payload.get("tag", "")).strip()
        if password:
            user["password"] = password_hash(password)
        write_data(data)
        self.send_json({"user": public_user(user)})

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
