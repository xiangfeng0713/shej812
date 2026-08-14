"""Local intranet server for AI视觉·无界舱.

Run with:
  set AGNES_API_KEY=your_key
  python server.py

The API key stays in the server process and is never sent to the browser.
"""

import json
import os
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 12 * 1024 * 1024
SYSTEM_PROMPT = """你是一名资深视觉设计验收助手。仅根据上传的验收图片评分，
评分范围 1-5 分。重点评价：视觉完成度、信息清晰度、版式层级、品牌一致性、交付可用性。
不要臆测图片中无法判断的业务事实。必须只输出 JSON：
{"score":数字,"level":"优秀|良好|合格|需优化","dimensions":{"视觉完成度":数字,"信息清晰度":数字,"版式层级":数字,"品牌一致性":数字,"交付可用性":数字},"summary":"不超过80字","suggestions":["建议1","建议2"]}
"""


class AppHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Keep static file access inside the outputs directory.
        return str(ROOT / Path(super().translate_path(path)).name) if path.count("/") == 1 else super().translate_path(path)

    def do_POST(self):
        if self.path != "/api/agnes-score":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= MAX_REQUEST_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "图片或请求内容过大（上限 12MB）。"})
            return

        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            image = data.get("image", "")
            if not isinstance(image, str) or not image.startswith("data:image/"):
                raise ValueError("请上传有效图片。")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        api_key = os.getenv("AGNES_API_KEY")
        if not api_key:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "服务端尚未配置 AGNES_API_KEY。"})
            return

        base_url = os.getenv("AGNES_BASE_URL", "https://api.agnes-ai.cn/v1").rstrip("/")
        payload = {
            "model": "agnes-2.5-flash",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "请对这张需求方验收图片进行自动评分。"},
                        {"type": "image_url", "image_url": {"url": image}},
                    ],
                },
            ],
            "temperature": 0.2,
        }
        request = Request(
            f"{base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                upstream = json.loads(response.read().decode("utf-8"))
            content = upstream["choices"][0]["message"]["content"]
            self._json(HTTPStatus.OK, {"result": content})
        except HTTPError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": f"评分服务返回 {exc.code}。"})
        except (URLError, TimeoutError, KeyError, IndexError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_GATEWAY, {"error": "评分服务暂不可用，请稍后重试。"})

    def _json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    os.chdir(ROOT)
    print("AI视觉·无界舱运行于 http://0.0.0.0:8080")
    ThreadingHTTPServer(("0.0.0.0", 8080), AppHandler).serve_forever()
