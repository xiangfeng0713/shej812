"""AI视觉·无界舱局域网服务：真实用户、人员库与共享需求数据。"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT.parent / "work" / "ai-visual-shared-data.json"
REVIEW_UPLOAD_DIR = ROOT.parent / "work" / "review-imports"
REVIEW_CASE_IMAGE_DIR = ROOT.parent / "work" / "review-case-images"
SESSIONS: dict[str, tuple[str, float]] = {}
SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_JSON_BYTES = 64 * 1024
MAX_REVIEW_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_REVIEW_CASE_UPLOAD_BYTES = 70 * 1024 * 1024
MAX_REVIEW_CASE_IMAGE_BYTES = 15 * 1024 * 1024
MAX_REVIEW_CASE_VIDEO_BYTES = 50 * 1024 * 1024
REVIEW_CASE_IMAGE_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}
REVIEW_CASE_VIDEO_TYPES = {
    "video/mp4": ".mp4",
    "video/webm": ".webm",
}
REVIEW_UPLOAD_TYPES = {"图片运营数据", "视频运营数据", "AI图片数据", "案例与行动"}
DEFAULT_IMAGE_REVIEW_METRICS = (
    {"id": "domestic_stay", "group": "国内渠道", "label": "平均停留时长", "unit": "秒", "compare": "gte", "target": "18"},
    {"id": "domestic_roi", "group": "国内渠道", "label": "店铺综合推广 ROI", "unit": "", "compare": "gte", "target": "4"},
    {"id": "domestic_conversion", "group": "国内渠道", "label": "付费点击转化率", "unit": "%", "compare": "gte", "target": "4.5"},
    {"id": "overseas_221b_click", "group": "海外渠道", "label": "亚马逊 221B 点击率", "unit": "%", "compare": "gte", "target": "0.8"},
    {"id": "overseas_221b_conversion", "group": "海外渠道", "label": "亚马逊 221B 转化率", "unit": "%", "compare": "gte", "target": "5.20"},
    {"id": "overseas_221d_click", "group": "海外渠道", "label": "亚马逊 221D 点击率", "unit": "%", "compare": "gte", "target": "0.8"},
    {"id": "overseas_221d_conversion", "group": "海外渠道", "label": "亚马逊 221D 转化率", "unit": "%", "compare": "gte", "target": "5.20"},
)
DEFAULT_VIDEO_REVIEW_METRICS = (
    {"id": "domestic_completion", "group": "国内渠道", "label": "完播率", "unit": "%", "compare": "gt", "target": "18"},
    {"id": "domestic_stay", "group": "国内渠道", "label": "视频人均停留时长", "unit": "s", "compare": "gt", "target": "20"},
    {"id": "domestic_ctr", "group": "国内渠道", "label": "曝光点击率", "unit": "%", "compare": "gt", "target": "7"},
    {"id": "overseas_tk_views", "group": "海外渠道", "label": "TK 播放量", "unit": "", "compare": "gte", "target": "10000"},
    {"id": "overseas_gmv", "group": "海外渠道", "label": "GMV", "unit": "", "compare": "gte", "target": "xxxx"},
)
REVIEW_METRIC_GROUPS = {"国内渠道", "海外渠道"}
MAX_REVIEW_METRICS = 30
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
        return {"users": [], "tasks": [], "review_uploads": [], "review_cases": [], "review_case_editor_ids": []}
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        data.setdefault("users", [])
        data.setdefault("tasks", [])
        data.setdefault("review_uploads", [])
        data.setdefault("review_cases", [])
        data.setdefault("review_case_editor_ids", [])
        return data
    except (json.JSONDecodeError, OSError):
        return {"users": [], "tasks": [], "review_uploads": [], "review_cases": [], "review_case_editor_ids": []}


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


def normalize_review_case(payload: dict) -> dict:
    month = str(payload.get("month", "")).strip()
    category = str(payload.get("category", "")).strip()
    media_type = str(payload.get("media_type", "image")).strip()
    task_id = str(payload.get("task_id", "")).strip()
    point = str(payload.get("point", "")).strip()
    try:
        slot = int(payload.get("slot", 0))
    except (TypeError, ValueError):
        slot = 0
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
        raise ValueError("请选择正确的案例月份。")
    if category not in {"excellent", "improvement"}:
        raise ValueError("案例类型不正确。")
    if media_type not in {"image", "video"}:
        raise ValueError("案例媒体类型不正确。")
    if (media_type == "image" and slot not in range(1, 6)) or (media_type == "video" and slot != 6):
        raise ValueError("案例卡位不正确。")
    if not re.fullmatch(r"[0-9a-f]{20}", task_id):
        raise ValueError("请选择关联任务。")
    if not point or len(point) > 1200:
        raise ValueError("请填写不超过 1200 个字符的案例要点。")
    return {"month": month, "category": category, "media_type": media_type, "slot": slot, "task_id": task_id, "point": point}


def review_case_task(data: dict, task_id: str) -> dict:
    task = next((item for item in data.get("tasks", []) if item.get("id") == task_id), None)
    if not task:
        raise ValueError("关联任务不存在，请重新选择。")
    return {
        "id": task["id"],
        "name": str(task.get("name", "")),
        "department": str(task.get("department", "")),
        "type": str(task.get("type", "")),
    }


def valid_review_case_image(mime_type: str, content: bytes) -> bool:
    if mime_type == "image/jpeg":
        return content.startswith(b"\xff\xd8\xff")
    if mime_type == "image/png":
        return content.startswith(b"\x89PNG\r\n\x1a\n")
    if mime_type == "image/webp":
        return len(content) >= 12 and content.startswith(b"RIFF") and content[8:12] == b"WEBP"
    return False


def valid_review_case_video(mime_type: str, content: bytes) -> bool:
    if mime_type == "video/mp4":
        return len(content) >= 12 and content[4:8] == b"ftyp"
    if mime_type == "video/webm":
        return content.startswith(b"\x1a\x45\xdf\xa3")
    return False


def user_by_id(data: dict, user_id: str) -> dict | None:
    return next((user for user in active_users(data) if user["id"] == user_id), None)


def admin_user(data: dict) -> dict | None:
    return next((user for user in active_users(data) if user.get("is_admin")), None)


def stage_assignees(data: dict, task: dict, action: str, payload: dict) -> tuple[str, list[str]]:
    submitter_id = task["submitter"]["id"]
    stored_owner = task.get("design_owner", {}) or {}
    owner = user_by_id(data, str(stored_owner.get("id", ""))) or user_by_name(data, str(payload.get("design_owner", stored_owner.get("name", ""))))
    stored_partners = task.get("coop_designers") or ([] if not task.get("coop_designer") else [task["coop_designer"]])
    requested_partners = payload.get("coop_designers", stored_partners)
    if not isinstance(requested_partners, list):
        requested_partners = [requested_partners]
    partners = []
    for partner_value in requested_partners:
        if isinstance(partner_value, dict):
            partner = user_by_id(data, str(partner_value.get("id", ""))) or user_by_name(data, str(partner_value.get("name", "")))
        else:
            partner = user_by_name(data, str(partner_value))
        if partner and partner["id"] != (owner or {}).get("id") and all(existing["id"] != partner["id"] for existing in partners):
            partners.append(partner)
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
        task["coop_designers"] = [public_user(partner) for partner in partners]
        # Retain the legacy field so existing task records and old views stay compatible.
        task["coop_designer"] = task["coop_designers"][0] if task["coop_designers"] else None
        return "需求校对", [owner["id"], *[partner["id"] for partner in partners]]
    if action == "proof_pass":
        if not owner:
            raise ValueError("请先完成设计负责人分配。")
        return "需求交付", [owner["id"]]
    if action == "proof_return":
        if not owner:
            raise ValueError("请先完成设计负责人分配。")
        task["resubmit_stage"] = "需求校对"
        task["resubmit_assignee_ids"] = [owner["id"], *[partner["id"] for partner in partners]]
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
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        super().end_headers()

    def list_directory(self, path: str):
        """Never expose a browsable file list on the LAN service."""
        self.send_json({"error": "资源不存在。"}, HTTPStatus.NOT_FOUND)
        return None

    def require_same_origin(self) -> bool:
        """Reject browser requests posted from a different website (CSRF guard)."""
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != self.headers.get("Host", ""):
            self.send_json({"error": "不允许跨站请求。"}, HTTPStatus.FORBIDDEN)
            return False
        return True

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

    def read_review_upload(self) -> tuple[dict[str, str], tuple[str, bytes] | None] | None:
        """Parse one small admin-only spreadsheet upload without serving it back."""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self.send_json({"error": "请使用文件上传格式。"}, HTTPStatus.BAD_REQUEST)
            return None
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = -1
        if size <= 0 or size > MAX_REVIEW_UPLOAD_BYTES:
            self.send_json({"error": "上传文件不能为空且不能超过 5 MB。"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
        raw = self.rfile.read(size)
        try:
            message = BytesParser(policy=default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + raw
            )
        except Exception:
            self.send_json({"error": "无法读取上传文件。"}, HTTPStatus.BAD_REQUEST)
            return None
        fields: dict[str, str] = {}
        uploaded: tuple[str, bytes] | None = None
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if filename:
                uploaded = (Path(filename).name, payload)
            elif name:
                fields[name] = payload.decode("utf-8", errors="replace").strip()
        return fields, uploaded

    def read_review_case_upload(self) -> tuple[dict[str, str], list[tuple[str, str, bytes]]] | None:
        """Parse a small set of case images plus text fields."""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self.send_json({"error": "请使用案例图片上传格式。"}, HTTPStatus.BAD_REQUEST)
            return None
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = -1
        if size <= 0 or size > MAX_REVIEW_CASE_UPLOAD_BYTES:
            self.send_json({"error": "案例上传内容不能为空且总大小不能超过 70 MB。"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
        try:
            message = BytesParser(policy=default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + self.rfile.read(size)
            )
        except Exception:
            self.send_json({"error": "无法读取案例上传内容。"}, HTTPStatus.BAD_REQUEST)
            return None
        fields: dict[str, str] = {}
        images: list[tuple[str, str, bytes]] = []
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if filename:
                images.append((Path(filename).name, part.get_content_type(), payload))
            elif name:
                fields[name] = payload.decode("utf-8", errors="replace").strip()
        return fields, images

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

    def require_review_case_editor(self, data: dict | None = None) -> tuple[dict | None, dict]:
        user, data = self.require_user(data)
        if user and not user.get("is_admin") and user.get("id") not in data.get("review_case_editor_ids", []):
            self.send_json({"error": "当前账号没有案例上传与维护权限。"}, HTTPStatus.FORBIDDEN)
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
        if path == "/api/review-uploads":
            user, data = self.require_user(data)
            if user:
                uploads = data.get("review_uploads", [])[-20:]
                self.send_json({"uploads": list(reversed(uploads))})
            return
        if path == "/api/review-settings":
            user, data = self.require_user(data)
            if user:
                query = parse_qs(urlparse(self.path).query)
                month = str(query.get("month", [datetime.now().strftime("%Y-%m")])[0])
                if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
                    self.send_json({"error": "复盘月份格式不正确。"}, HTTPStatus.BAD_REQUEST)
                    return
                settings = data.get("review_settings", {})
                image_metrics = settings.get("image_metrics")
                if not isinstance(image_metrics, list):
                    saved = settings.get("image_targets", {})
                    legacy = {"stay": "domestic_stay", "roi": "domestic_roi", "conversion": "domestic_conversion"}
                    saved = {legacy.get(key, key): value for key, value in saved.items()}
                    image_metrics = [dict(metric) for metric in DEFAULT_IMAGE_REVIEW_METRICS]
                    for metric in image_metrics:
                        if metric["id"] in saved:
                            metric["target"] = str(saved[metric["id"]]).replace("秒", "").replace("%", "").strip()
                else:
                    image_metrics = [dict(metric) for metric in image_metrics]
                video_metrics = settings.get("video_metrics")
                if not isinstance(video_metrics, list):
                    saved = settings.get("video_targets", {})
                    video_metrics = [dict(metric) for metric in DEFAULT_VIDEO_REVIEW_METRICS]
                    for metric in video_metrics:
                        if metric["id"] in saved:
                            metric["target"] = str(saved[metric["id"]]).strip()
                else:
                    video_metrics = [dict(metric) for metric in video_metrics]
                image_actuals = settings.get("image_actuals", {}).get(month, {})
                image_actuals = {metric["id"]: str(image_actuals.get(metric["id"], "")) for metric in image_metrics}
                video_actuals = settings.get("video_actuals", {}).get(month, {})
                video_actuals = {metric["id"]: str(video_actuals.get(metric["id"], "")) for metric in video_metrics}
                image_notes = settings.get("image_notes", {}).get(month, {})
                video_notes = settings.get("video_notes", {}).get(month, {})
                self.send_json({
                    "month": month,
                    "image_metrics": image_metrics,
                    "image_actuals": image_actuals,
                    "image_notes": {"anomaly": str(image_notes.get("anomaly", "")), "improvement": str(image_notes.get("improvement", ""))},
                    "video_metrics": video_metrics,
                    "video_actuals": video_actuals,
                    "video_notes": {"anomaly": str(video_notes.get("anomaly", "")), "improvement": str(video_notes.get("improvement", ""))},
                })
            return
        if path == "/api/review-case-permissions":
            user, data = self.require_user(data)
            if user:
                editor_ids = [
                    user_id
                    for user_id in data.get("review_case_editor_ids", [])
                    if user_by_id(data, user_id)
                ]
                self.send_json({
                    "editor_ids": editor_ids,
                    "can_edit": bool(user.get("is_admin") or user.get("id") in editor_ids),
                    "can_manage": bool(user.get("is_admin")),
                })
            return
        if path == "/api/review-cases":
            user, data = self.require_user(data)
            if user:
                query = parse_qs(urlparse(self.path).query)
                month = str(query.get("month", [datetime.now().strftime("%Y-%m")])[0])
                if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
                    self.send_json({"error": "案例月份格式不正确。"}, HTTPStatus.BAD_REQUEST)
                    return
                cases = [item for item in data.get("review_cases", []) if item.get("month") == month]
                cases.sort(key=lambda item: (item.get("category", ""), int(item.get("slot", 0))))
                self.send_json({"month": month, "cases": cases})
            return
        if path.startswith("/api/review-case-images/"):
            user, data = self.require_user(data)
            if not user:
                return
            image_id = path.rsplit("/", 1)[-1]
            if not re.fullmatch(r"[a-f0-9]{24}", image_id):
                self.send_json({"error": "案例图片不存在。"}, HTTPStatus.NOT_FOUND)
                return
            image = next(
                (
                    image
                    for case in data.get("review_cases", [])
                    for image in case.get("images", [])
                    if image.get("id") == image_id
                ),
                None,
            )
            if not image:
                self.send_json({"error": "案例图片不存在。"}, HTTPStatus.NOT_FOUND)
                return
            suffix = str(image.get("suffix", ""))
            if suffix not in {*REVIEW_CASE_IMAGE_TYPES.values(), *REVIEW_CASE_VIDEO_TYPES.values()}:
                self.send_json({"error": "案例图片不存在。"}, HTTPStatus.NOT_FOUND)
                return
            file_path = REVIEW_CASE_IMAGE_DIR / f"{image_id}{suffix}"
            if not file_path.is_file():
                self.send_json({"error": "案例图片文件缺失。"}, HTTPStatus.NOT_FOUND)
                return
            file_size = file_path.stat().st_size
            start, end = 0, file_size - 1
            response_status = HTTPStatus.OK
            range_header = self.headers.get("Range", "")
            if range_header:
                match = re.fullmatch(r"bytes=(\d+)-(\d*)", range_header.strip())
                if not match:
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.end_headers()
                    return
                start = int(match.group(1))
                end = min(int(match.group(2)) if match.group(2) else file_size - 1, file_size - 1)
                if start > end or start >= file_size:
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.end_headers()
                    return
                response_status = HTTPStatus.PARTIAL_CONTENT
            length = end - start + 1
            self.send_response(response_status)
            self.send_header("Content-Type", image.get("mime", "application/octet-stream"))
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            if response_status == HTTPStatus.PARTIAL_CONTENT:
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
            self.send_header("Cache-Control", "private, max-age=300")
            self.end_headers()
            with file_path.open("rb") as media_file:
                media_file.seek(start)
                remaining = length
                while remaining:
                    chunk = media_file.read(min(64 * 1024, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
            return
        if path.startswith("/inspiration-assets/"):
            # These are static thumbnails used by the browser after the page is
            # rendered.  Keep them available so image loading is not coupled to
            # the in-memory session lifecycle; directory browsing remains off.
            super().do_GET()
            return
        if path not in {"/", "/ai-starrail-design-console.html"}:
            self.send_json({"error": "资源不存在。"}, HTTPStatus.NOT_FOUND)
            return
        super().do_GET()

    def do_POST(self):
        if not self.require_same_origin():
            return
        path = urlparse(self.path).path
        if path == "/api/review-case-permissions":
            data = read_data()
            admin, data = self.require_admin(data)
            if not admin:
                return
            payload = self.read_json()
            if payload is None:
                return
            incoming = payload.get("editor_ids", [])
            if not isinstance(incoming, list) or len(incoming) > len(data.get("users", [])):
                self.send_json({"error": "授权账号数据不正确。"}, HTTPStatus.BAD_REQUEST)
                return
            active_ids = {user["id"] for user in active_users(data) if not user.get("is_admin")}
            editor_ids = list(dict.fromkeys(str(user_id) for user_id in incoming if str(user_id) in active_ids))
            data["review_case_editor_ids"] = editor_ids
            write_data(data)
            self.send_json({"editor_ids": editor_ids, "can_edit": True, "can_manage": True})
            return
        if path == "/api/review-uploads":
            data = read_data()
            admin, data = self.require_admin(data)
            if not admin:
                return
            parsed = self.read_review_upload()
            if not parsed:
                return
            fields, uploaded = parsed
            if not uploaded:
                self.send_json({"error": "请选择 Excel 或 CSV 文件。"}, HTTPStatus.BAD_REQUEST)
                return
            upload_type = fields.get("type", "")
            month = fields.get("month", "")
            filename, content = uploaded
            suffix = Path(filename).suffix.lower()
            if upload_type not in REVIEW_UPLOAD_TYPES or not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
                self.send_json({"error": "请填写正确的复盘月份和数据类型。"}, HTTPStatus.BAD_REQUEST)
                return
            if suffix not in {".xlsx", ".csv"} or not filename or len(filename) > 120:
                self.send_json({"error": "仅支持文件名不超过 120 个字符的 XLSX 或 CSV 文件。"}, HTTPStatus.BAD_REQUEST)
                return
            if suffix == ".xlsx" and not content.startswith(b"PK"):
                self.send_json({"error": "该 XLSX 文件格式无效。"}, HTTPStatus.BAD_REQUEST)
                return
            upload_id = secrets.token_hex(12)
            REVIEW_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            (REVIEW_UPLOAD_DIR / f"{upload_id}{suffix}").write_bytes(content)
            record = {
                "id": upload_id,
                "name": filename,
                "type": upload_type,
                "month": month,
                "size": len(content),
                "uploaded_by": public_user(admin),
                "uploaded_at": now(),
            }
            data.setdefault("review_uploads", []).append(record)
            write_data(data)
            self.send_json({"upload": record}, HTTPStatus.CREATED)
            return
        if path == "/api/review-cases":
            data = read_data()
            editor, data = self.require_review_case_editor(data)
            if not editor:
                return
            parsed = self.read_review_case_upload()
            if not parsed:
                return
            fields, uploads = parsed
            try:
                values = normalize_review_case(fields)
                values["task"] = review_case_task(data, values["task_id"])
            except ValueError as error:
                self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
                return
            occupied = any(
                item.get("month") == values["month"]
                and item.get("category") == values["category"]
                and item.get("media_type", "image") == values["media_type"]
                and int(item.get("slot", 0)) == values["slot"]
                for item in data.get("review_cases", [])
            )
            if occupied:
                self.send_json({"error": "该案例卡位已有内容，请直接编辑或先删除。"}, HTTPStatus.CONFLICT)
                return
            if len(uploads) != 1:
                self.send_json({"error": "每个案例卡位请上传 1 个图片或视频文件。"}, HTTPStatus.BAD_REQUEST)
                return
            filename, mime_type, content = uploads[0]
            if values["media_type"] == "image":
                if mime_type not in REVIEW_CASE_IMAGE_TYPES or not content or len(content) > MAX_REVIEW_CASE_IMAGE_BYTES or not valid_review_case_image(mime_type, content):
                    self.send_json({"error": "仅支持单张不超过 15 MB 的 JPG、PNG 或 WEBP 图片。"}, HTTPStatus.BAD_REQUEST)
                    return
                suffix = REVIEW_CASE_IMAGE_TYPES[mime_type]
            else:
                if mime_type not in REVIEW_CASE_VIDEO_TYPES or not content or len(content) > MAX_REVIEW_CASE_VIDEO_BYTES or not valid_review_case_video(mime_type, content):
                    self.send_json({"error": "仅支持不超过 50 MB 的 MP4 或 WEBM 视频。"}, HTTPStatus.BAD_REQUEST)
                    return
                suffix = REVIEW_CASE_VIDEO_TYPES[mime_type]
            REVIEW_CASE_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
            media_id = secrets.token_hex(12)
            file_path = REVIEW_CASE_IMAGE_DIR / f"{media_id}{suffix}"
            try:
                file_path.write_bytes(content)
            except OSError:
                file_path.unlink(missing_ok=True)
                self.send_json({"error": "案例媒体文件保存失败。"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            created_at = now()
            record = {
                "id": secrets.token_hex(12),
                **values,
                "images": [{"id": media_id, "name": Path(filename).name[:120], "mime": mime_type, "suffix": suffix}],
                "created_by": public_user(editor),
                "created_at": created_at,
                "updated_at": created_at,
            }
            data.setdefault("review_cases", []).append(record)
            write_data(data)
            self.send_json({"case": record}, HTTPStatus.CREATED)
            return
        payload = self.read_json()
        if payload is None:
            return
        data = read_data()
        if path == "/api/review-settings":
            admin, data = self.require_admin(data)
            if not admin:
                return
            section = str(payload.get("section", "image")).strip()
            month = str(payload.get("month", "")).strip()
            metric_pattern = re.compile(r"\d{1,12}(?:\.\d{1,4})?")
            if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
                self.send_json({"error": "请选择正确的复盘月份。"}, HTTPStatus.BAD_REQUEST)
                return
            if section not in {"image", "video"}:
                self.send_json({"error": "复盘数据类型不正确。"}, HTTPStatus.BAD_REQUEST)
                return
            metrics_incoming = payload.get(f"{section}_metrics")
            actual_incoming = payload.get(f"{section}_actuals")
            notes_incoming = payload.get(f"{section}_notes")
            if not isinstance(metrics_incoming, list) or not isinstance(actual_incoming, dict) or not isinstance(notes_incoming, dict):
                self.send_json({"error": "请填写指标、当月实际值和改善说明。"}, HTTPStatus.BAD_REQUEST)
                return
            if not metrics_incoming or len(metrics_incoming) > MAX_REVIEW_METRICS:
                self.send_json({"error": f"每个板块须保留 1 至 {MAX_REVIEW_METRICS} 个指标。"}, HTTPStatus.BAD_REQUEST)
                return
            metrics = []
            ids = set()
            for item in metrics_incoming:
                if not isinstance(item, dict):
                    self.send_json({"error": "指标数据格式不正确。"}, HTTPStatus.BAD_REQUEST)
                    return
                metric_id = str(item.get("id", "")).strip()
                group = str(item.get("group", "")).strip()
                label = str(item.get("label", "")).strip()
                unit = str(item.get("unit", "")).strip()
                compare = str(item.get("compare", "gte")).strip()
                target = str(item.get("target", "")).strip()
                if (
                    not re.fullmatch(r"[a-z0-9_]{3,40}", metric_id)
                    or metric_id in ids
                    or group not in REVIEW_METRIC_GROUPS
                    or not label
                    or len(label) > 40
                    or len(unit) > 10
                    or compare not in {"gt", "gte"}
                    or (not metric_pattern.fullmatch(target) and target.casefold() != "xxxx")
                ):
                    self.send_json({"error": "指标名称、渠道、目标值或单位不正确。"}, HTTPStatus.BAD_REQUEST)
                    return
                ids.add(metric_id)
                metrics.append({"id": metric_id, "group": group, "label": label, "unit": unit, "compare": compare, "target": target})
            actuals = {metric["id"]: str(actual_incoming.get(metric["id"], "")).strip() for metric in metrics}
            if any(value and not metric_pattern.fullmatch(value) for value in actuals.values()):
                self.send_json({"error": "当月实际值仅支持数字，可暂时留空。"}, HTTPStatus.BAD_REQUEST)
                return
            notes = {
                "anomaly": str(notes_incoming.get("anomaly", "")).strip(),
                "improvement": str(notes_incoming.get("improvement", "")).strip(),
            }
            if any(len(value) > 2000 for value in notes.values()):
                self.send_json({"error": "异常说明和改善方向每项不超过 2000 个字符。"}, HTTPStatus.BAD_REQUEST)
                return
            settings = data.setdefault("review_settings", {})
            settings[f"{section}_metrics"] = metrics
            settings.setdefault(f"{section}_actuals", {})[month] = actuals
            settings.setdefault(f"{section}_notes", {})[month] = notes
            response = {
                "month": month,
                f"{section}_metrics": metrics,
                f"{section}_actuals": actuals,
                f"{section}_notes": notes,
            }
            settings["updated_by"] = public_user(admin)
            settings["updated_at"] = now()
            write_data(data)
            self.send_json(response)
            return
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
            # Keep lockouts scoped to the attempted account.  On a LAN several
            # colleagues can share one outward-facing IP; an IP-only counter
            # would otherwise block a correct login after somebody else mistypes
            # a different account.
            login_key = f"{client_ip}:{username.casefold()}"
            if not login_is_allowed(login_key):
                self.send_json({"error": "登录失败次数过多，请 15 分钟后再试。"}, HTTPStatus.TOO_MANY_REQUESTS)
                return
            user = next((item for item in data["users"] if item.get("username") == username and item.get("active", True)), None)
            if not user or not password_valid(str(payload.get("password", "")), user):
                record_login_failure(login_key)
                self.send_json({"error": "账号或密码错误。"}, HTTPStatus.UNAUTHORIZED)
                return
            LOGIN_ATTEMPTS.pop(login_key, None)
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
            reason = str(payload.get("reason", "")).strip()
            if not reason:
                self.send_json({"error": "请填写临时优先处理原因。"}, HTTPStatus.BAD_REQUEST)
                return
            if task.get("stage") == "验收完结" or not task.get("assignee_ids"):
                self.send_json({"error": "该任务已完结，当前没有负责人可通知。"}, HTTPStatus.BAD_REQUEST)
                return
            recipients = [user_by_id(data, user_id) for user_id in task.get("assignee_ids", [])]
            recipients = [person for person in recipients if person]
            task["priority"] = priority
            task["pinned"] = True
            task["updated_at"] = now()
            task["priority_notification"] = {
                "priority": priority,
                "by": public_user(user),
                "recipient_ids": [person["id"] for person in recipients],
                "reason": reason,
                "at": task["updated_at"],
            }
            task.setdefault("history", []).append({
                "action": "priority_adjusted",
                "by": public_user(user),
                "comment": reason,
                "at": task["updated_at"],
            })
            write_data(data)
            self.send_json({"task": task, "notified_users": [public_user(person) for person in recipients]})
            return
        self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        if not self.require_same_origin():
            return
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
        if not self.require_same_origin():
            return
        path = urlparse(self.path).path
        if path.startswith("/api/review-cases/"):
            editor, data = self.require_review_case_editor()
            if not editor:
                return
            case_id = path.rsplit("/", 1)[-1]
            case = next((item for item in data.get("review_cases", []) if item.get("id") == case_id), None)
            if not case:
                self.send_json({"error": "未找到该复盘案例。"}, HTTPStatus.NOT_FOUND)
                return
            payload = self.read_json()
            if payload is None:
                return
            try:
                values = normalize_review_case(payload)
                values["task"] = review_case_task(data, values["task_id"])
            except ValueError as error:
                self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
                return
            occupied = any(
                item.get("id") != case_id
                and item.get("month") == values["month"]
                and item.get("category") == values["category"]
                and item.get("media_type", "image") == values["media_type"]
                and int(item.get("slot", 0)) == values["slot"]
                for item in data.get("review_cases", [])
            )
            if occupied:
                self.send_json({"error": "该案例卡位已有内容。"}, HTTPStatus.CONFLICT)
                return
            case.update(values)
            case["updated_by"] = public_user(editor)
            case["updated_at"] = now()
            write_data(data)
            self.send_json({"case": case})
            return
        if not path.startswith("/api/users/"):
            self.send_json({"error": "接口不存在。"}, HTTPStatus.NOT_FOUND)
            return
        actor, data = self.require_user()
        if not actor:
            return
        user_id = path.rsplit("/", 1)[-1]
        user = next((item for item in data["users"] if item["id"] == user_id), None)
        if not user:
            self.send_json({"error": "未找到该人员。"}, HTTPStatus.NOT_FOUND)
            return
        if not actor.get("is_admin") and actor["id"] != user_id:
            self.send_json({"error": "只能修改自己的账号资料。"}, HTTPStatus.FORBIDDEN)
            return
        payload = self.read_json()
        # Ordinary users can only rotate their own password. Account identity and
        # job information remain managed by the administrator.
        username = user["username"] if not actor.get("is_admin") else str(payload.get("username", "")).strip()
        name = user["name"] if not actor.get("is_admin") else str(payload.get("name", "")).strip()
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
        if actor.get("is_admin"):
            user["tag"] = str(payload.get("tag", "")).strip()
        if password:
            user["password"] = password_hash(password)
        write_data(data)
        self.send_json({"user": public_user(user)})

    def do_DELETE(self):
        if not self.require_same_origin():
            return
        path = urlparse(self.path).path
        if path.startswith("/api/review-cases/"):
            editor, data = self.require_review_case_editor()
            if not editor:
                return
            case_id = path.rsplit("/", 1)[-1]
            cases = data.get("review_cases", [])
            case = next((item for item in cases if item.get("id") == case_id), None)
            if not case:
                self.send_json({"error": "未找到该复盘案例。"}, HTTPStatus.NOT_FOUND)
                return
            allowed_suffixes = {*REVIEW_CASE_IMAGE_TYPES.values(), *REVIEW_CASE_VIDEO_TYPES.values()}
            for image in case.get("images", []):
                image_id = str(image.get("id", ""))
                suffix = str(image.get("suffix", ""))
                if re.fullmatch(r"[0-9a-f]{24}", image_id) and suffix in allowed_suffixes:
                    try:
                        (REVIEW_CASE_IMAGE_DIR / f"{image_id}{suffix}").unlink(missing_ok=True)
                    except OSError:
                        pass
            data["review_cases"] = [item for item in cases if item.get("id") != case_id]
            write_data(data)
            self.send_json({"ok": True})
            return
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
