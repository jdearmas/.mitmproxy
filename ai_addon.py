"""
mitmproxy AI addon — loaded automatically via config.yaml.

Registers :ai.* commands in the mitmproxy console TUI.
Supports multiple AI providers:
  - claude-code (default) — uses the `claude` CLI and your existing subscription.
    No API key needed. Set ai_provider=claude-code.
  - Anthropic (Claude API) — set ai_provider=anthropic, uses ANTHROPIC_API_KEY
  - OpenAI (GPT) — set ai_provider=openai, uses OPENAI_API_KEY
  - OpenAI-compatible (Ollama, LM Studio, etc.) — set ai_provider=openai,
    ai_base_url=http://localhost:11434/v1

Commands:
    :ai.prompt "question"       — ask the AI about current traffic context
    :ai.addon "description"     — generate and hot-load a mitmproxy addon
    :ai.addons                  — list loaded AI addons
    :ai.code addon_name         — view generated addon source
    :ai.remove addon_name       — unload an AI addon
    :ai.flows addon_name        — search flows tagged by an addon
"""

import ast
import asyncio
import concurrent.futures
import json
import logging
import os
import re
import shutil
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Optional
from urllib.parse import urlparse, parse_qs

from mitmproxy import command, ctx, http

logger = logging.getLogger("mitmproxy.ai")

ADDON_SYSTEM_PROMPT = """You are an expert mitmproxy addon developer. Write a Python addon class
called DynamicAddon that implements the described behaviour using mitmproxy hooks.

Rules:
- The class MUST be named exactly DynamicAddon.
- Use only stdlib + mitmproxy imports.
- Available hooks (use only what you need):
    request(self, flow: http.HTTPFlow)
    response(self, flow: http.HTTPFlow)
    error(self, flow: http.HTTPFlow)
    tls_start_client(self, tls_handshake)
    tls_start_server(self, tls_handshake)
- Modify headers via flow.request.headers[key] = value
- Modify body via flow.request.text = "..." or flow.response.text = "..."
- Kill a flow with flow.kill()
- Redirect via flow.request.url = "https://..."
- Log with: import logging; logger = logging.getLogger("mitmproxy.ai"); logger.info(...)
- Do NOT use print().
- Return ONLY raw Python source code — no markdown fences, no commentary.

MANDATORY — flow tagging:
In EVERY hook that receives a flow argument, the FIRST line must be:
    flow.comment = "ai:{addon_name}"
This tags the flow so :ai.flows can find which flows this addon touched.

Example:
from mitmproxy import http
import logging
logger = logging.getLogger("mitmproxy.ai")

class DynamicAddon:
    def request(self, flow: http.HTTPFlow):
        flow.comment = "ai:{addon_name}"
        pass
"""

PROMPT_SYSTEM = """You are an AI assistant embedded in the mitmproxy intercepting proxy TUI.
You can see the user's current traffic context (focused flow details).
Answer questions about HTTP traffic, suggest security findings, explain API behavior.
Be concise — your response will be displayed in a terminal overlay."""


def _create_client(provider: str, base_url: str, api_key: str):
    if provider == "claude-code":
        claude_bin = shutil.which("claude")
        if not claude_bin:
            raise RuntimeError(
                "claude CLI not found on PATH. "
                "Install Claude Code: https://docs.anthropic.com/en/docs/claude-code"
            )
        return ("claude-code", claude_bin)
    elif provider == "anthropic":
        from anthropic import AsyncAnthropic
        kwargs = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        return ("anthropic", AsyncAnthropic(**kwargs))
    else:
        from openai import AsyncOpenAI
        kwargs = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        return ("openai", AsyncOpenAI(**kwargs))


async def _claude_code_call(claude_bin: str, system: str, user_msg: str, model: str) -> str:
    cmd = [
        claude_bin, "-p",
        "--output-format", "text",
        "--system-prompt", system,
        "--allowedTools", "",
        "--bare",
    ]
    if model:
        cmd.extend(["--model", model])
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(input=user_msg.encode()),
        timeout=120,
    )
    if proc.returncode != 0:
        err = stderr.decode().strip()
        raise RuntimeError(f"claude CLI exited {proc.returncode}: {err}")
    return stdout.decode().strip()


async def _llm_call(client_tuple, model: str, system: str, user_msg: str, max_tokens: int = 4096) -> str:
    provider, client = client_tuple
    if provider == "claude-code":
        return await _claude_code_call(client, system, user_msg, model)
    elif provider == "anthropic":
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        )
        for block in response.content:
            if hasattr(block, "text"):
                return block.text
        return ""
    else:
        response = await client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
        )
        return response.choices[0].message.content or ""


def _flow_to_dict(f, body_limit=2000):
    """Convert a mitmproxy flow to a JSON-serializable dict."""
    if not isinstance(f, http.HTTPFlow):
        return None
    result = {
        "id": f.id,
        "method": f.request.method,
        "url": f.request.pretty_url,
        "request_headers": dict(f.request.headers),
        "comment": f.comment or "",
    }
    req_body = f.request.get_text(strict=False)
    if req_body:
        result["request_body"] = req_body[:body_limit] if body_limit else req_body
    if f.response:
        result["status_code"] = f.response.status_code
        result["response_headers"] = dict(f.response.headers)
        resp_body = f.response.get_text(strict=False)
        if resp_body:
            result["response_body"] = resp_body[:body_limit] if body_limit else resp_body
    return result


class _ControlHandler(BaseHTTPRequestHandler):
    """Request handler for the control API. Runs in a background thread."""

    def log_message(self, format, *args):
        pass

    def _json_response(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    def _parse_path(self):
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def do_GET(self):
        path, qs = self._parse_path()
        addon = self.server.ai_addon

        if path == "/status":
            self._json_response({
                "status": "ok",
                "proxy_port": ctx.options.listen_port,
                "flows": len(ctx.master.view),
                "ai_addons": list(addon.generated_addons.keys()),
            })

        elif path == "/flows":
            limit = int(qs.get("limit", ["50"])[0])
            flows = []
            for f in list(ctx.master.view)[-limit:]:
                d = _flow_to_dict(f)
                if d:
                    flows.append(d)
            self._json_response(flows)

        elif path.startswith("/flows/"):
            flow_id = path.split("/flows/", 1)[1]
            for f in ctx.master.view:
                if f.id == flow_id:
                    d = _flow_to_dict(f, body_limit=0)
                    if d:
                        return self._json_response(d)
            self._json_response({"error": "flow not found"}, 404)

        elif path == "/search":
            query = qs.get("q", [""])[0]
            domain = qs.get("domain", [""])[0]
            method = qs.get("method", [""])[0]
            tag = qs.get("tag", [""])[0]
            limit = int(qs.get("limit", ["50"])[0])
            results = []
            for f in ctx.master.view:
                if not isinstance(f, http.HTTPFlow):
                    continue
                if domain and domain not in f.request.pretty_url:
                    continue
                if method and f.request.method.upper() != method.upper():
                    continue
                if tag and (not f.comment or tag not in f.comment):
                    continue
                if query:
                    haystack = f.request.pretty_url
                    body = f.request.get_text(strict=False) or ""
                    resp_body = ""
                    if f.response:
                        resp_body = f.response.get_text(strict=False) or ""
                    if query.lower() not in (haystack + body + resp_body).lower():
                        continue
                d = _flow_to_dict(f)
                if d:
                    results.append(d)
                if len(results) >= limit:
                    break
            self._json_response(results)

        elif path == "/addons":
            self._json_response({"addons": list(addon.generated_addons.keys())})

        elif path.endswith("/code") and path.startswith("/addon/"):
            name = path.split("/addon/", 1)[1].rsplit("/code", 1)[0]
            entry = addon.generated_addons.get(name)
            if not entry:
                return self._json_response({"error": "not found"}, 404)
            self._json_response({"name": name, "code": entry[1]})

        elif path.endswith("/flows") and path.startswith("/addon/"):
            name = path.split("/addon/", 1)[1].rsplit("/flows", 1)[0]
            tag = f"ai:{name}"
            results = []
            for f in ctx.master.view:
                if isinstance(f, http.HTTPFlow) and f.comment and tag in f.comment:
                    d = _flow_to_dict(f)
                    if d:
                        results.append(d)
            self._json_response(results)

        else:
            self._json_response({"error": "not found"}, 404)

    def do_POST(self):
        path, _ = self._parse_path()
        addon = self.server.ai_addon

        if path == "/addon":
            body = self._read_json()
            description = body.get("description", "")
            code = body.get("code")
            name = body.get("name") or _slugify(description)
            if code:
                try:
                    result = addon._load_addon_code(name, code)
                    self._json_response({"status": "ok", "name": name, "message": result})
                except Exception as e:
                    self._json_response({"status": "error", "message": str(e)}, 400)
            elif description:
                try:
                    result = addon._run_async(addon._create_addon_async(description, name))
                    self._json_response({"status": "ok", "name": name, "message": result})
                except Exception as e:
                    self._json_response({"status": "error", "message": str(e)}, 500)
            else:
                self._json_response({"status": "error", "message": "provide description or code"}, 400)

        elif path.startswith("/replay/"):
            flow_id = path.split("/replay/", 1)[1]
            body = self._read_json()
            for f in ctx.master.view:
                if f.id == flow_id and isinstance(f, http.HTTPFlow):
                    replay_flow = f.copy()
                    if body.get("method"):
                        replay_flow.request.method = body["method"]
                    if body.get("headers"):
                        for k, v in body["headers"].items():
                            replay_flow.request.headers[k] = v
                    if body.get("body") is not None:
                        replay_flow.request.text = body["body"]
                    ctx.master.commands.execute("replay.client @shown")
                    return self._json_response({"status": "ok", "message": "replay queued"})
            self._json_response({"error": "flow not found"}, 404)

        else:
            self._json_response({"error": "not found"}, 404)

    def do_DELETE(self):
        path, _ = self._parse_path()
        addon = self.server.ai_addon

        if path.startswith("/addon/"):
            name = path.split("/addon/", 1)[1]
            result = addon.remove_addon(name)
            self._json_response({"message": result})
        else:
            self._json_response({"error": "not found"}, 404)


class ControlServer:
    """HTTP API exposing the live mitmproxy session to external tools (Claude Code).
    Uses stdlib http.server in a background thread — zero external dependencies."""

    def __init__(self, ai_addon):
        self.ai_addon = ai_addon
        self._server = None
        self._thread = None

    def start(self, port):
        self._server = HTTPServer(("127.0.0.1", port), _ControlHandler)
        self._server.ai_addon = self.ai_addon
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        ctx.log.info(f"[AI] Control server listening on http://127.0.0.1:{port}")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None


class AIAddon:
    def __init__(self):
        self._client_tuple = None
        self.generated_addons: dict[str, tuple[object, str]] = {}
        self._control_server = None

    def _get_client(self):
        if self._client_tuple is None:
            self._client_tuple = _create_client(
                ctx.options.ai_provider,
                ctx.options.ai_base_url,
                ctx.options.ai_api_key,
            )
        return self._client_tuple

    def load(self, loader):
        loader.add_option(
            "ai_provider", str, "claude-code",
            "AI provider: 'claude-code' (uses claude CLI + your subscription), "
            "'anthropic' (API key), 'openai' (also works for Ollama, LM Studio, etc.).",
        )
        loader.add_option(
            "ai_model", str, "",
            "AI model name. Leave empty for provider default. "
            "Examples: claude-sonnet-4-6, gpt-4o, llama3.",
        )
        loader.add_option(
            "ai_base_url", str, "",
            "Custom API base URL. For Ollama: http://localhost:11434/v1. Leave empty for default.",
        )
        loader.add_option(
            "ai_api_key", str, "",
            "API key override. Only needed for anthropic/openai providers. "
            "Defaults to ANTHROPIC_API_KEY or OPENAI_API_KEY env var.",
        )
        loader.add_option(
            "ai_control_port", int, 8081,
            "Port for the AI control API. Claude Code connects here. Set 0 to disable.",
        )

    def configure(self, updated):
        if any(k in updated for k in ("ai_provider", "ai_base_url", "ai_api_key")):
            self._client_tuple = None

    def running(self):
        port = ctx.options.ai_control_port
        if port:
            self._control_server = ControlServer(self)
            self._control_server.start(port)

    def done(self):
        if self._control_server:
            self._control_server.stop()

    def _build_flow_context(self) -> Optional[dict]:
        try:
            f = ctx.master.view.focus.flow
        except Exception:
            return None
        if not f:
            return None
        result = {
            "url": f.request.pretty_url,
            "method": f.request.method,
            "request_headers": dict(f.request.headers),
        }
        req_body = f.request.get_text(strict=False)
        if req_body:
            result["request_body"] = req_body[:2000]
        if f.response:
            result["status"] = f.response.status_code
            result["response_headers"] = dict(f.response.headers)
            resp_body = f.response.get_text(strict=False)
            if resp_body:
                result["response_body"] = resp_body[:2000]
        return result

    def _run_async(self, coro):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=120)
        else:
            return asyncio.run(coro)

    @command.command("ai.prompt")
    def prompt(self, text: str) -> str:
        """Ask the AI about the current traffic context."""
        ctx.log.info(f"[AI] Prompting: {text[:80]}...")
        try:
            return self._run_async(self._prompt_async(text))
        except Exception as e:
            return f"AI error: {e}"

    def _effective_model(self) -> str:
        model = ctx.options.ai_model
        if model:
            return model
        provider = ctx.options.ai_provider
        if provider == "anthropic":
            return "claude-sonnet-4-6"
        elif provider == "openai":
            return "gpt-4o"
        return ""

    async def _prompt_async(self, text: str) -> str:
        flow_ctx = self._build_flow_context()
        system = PROMPT_SYSTEM
        if flow_ctx:
            system += f"\n\nCurrent focused flow:\n{json.dumps(flow_ctx, indent=2)}"
        return await _llm_call(self._get_client(), self._effective_model(), system, text)

    @command.command("ai.addon")
    def create_addon(self, description: str) -> str:
        """Generate and hot-load a mitmproxy addon from a natural language description."""
        name = _slugify(description)
        ctx.log.info(f"[AI] Generating addon '{name}'...")
        try:
            return self._run_async(self._create_addon_async(description, name))
        except Exception as e:
            return f"AI addon generation failed: {e}"

    def _load_addon_code(self, name: str, code: str) -> str:
        """Load pre-written addon code directly (used by control server)."""
        code = code.strip()
        if code.startswith("```"):
            lines = code.splitlines()
            code = "\n".join(
                lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
            ).strip()
        ast.parse(code)
        ns: dict = {}
        exec(compile(code, f"<ai:{name}>", "exec"), ns)
        addon_class = ns.get("DynamicAddon")
        if addon_class is None:
            raise ValueError("Code does not define a DynamicAddon class")
        instance = addon_class()
        if name in self.generated_addons:
            try:
                ctx.master.addons.remove(self.generated_addons[name][0])
            except Exception:
                pass
        ctx.master.addons.add(instance)
        self.generated_addons[name] = (instance, code)
        ctx.log.info(f"[AI] Addon '{name}' loaded via control API.")
        return f"Addon '{name}' is live."

    async def _create_addon_async(self, description: str, name: str) -> str:
        system = ADDON_SYSTEM_PROMPT.replace("{addon_name}", name)
        code = await _llm_call(self._get_client(), self._effective_model(), system, description)
        code = code.strip()
        if code.startswith("```"):
            lines = code.splitlines()
            code = "\n".join(
                lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
            ).strip()

        ast.parse(code)

        ns: dict = {}
        exec(compile(code, f"<ai:{name}>", "exec"), ns)
        addon_class = ns.get("DynamicAddon")
        if addon_class is None:
            return f"Error: generated code has no DynamicAddon class.\n\n{code}"

        instance = addon_class()

        if name in self.generated_addons:
            old_instance = self.generated_addons[name][0]
            try:
                ctx.master.addons.remove(old_instance)
            except Exception:
                pass

        ctx.master.addons.add(instance)
        self.generated_addons[name] = (instance, code)
        ctx.log.info(f"[AI] Addon '{name}' loaded. Flows tagged 'ai:{name}'.")
        return f"Addon '{name}' is live. Flows tagged 'ai:{name}'.\n\nGenerated code:\n{code}"

    @command.command("ai.addons")
    def list_addons(self) -> str:
        """List all AI-generated addons currently loaded."""
        if not self.generated_addons:
            return "No AI addons loaded."
        lines = [f"  {name}" for name in self.generated_addons]
        return "Loaded AI addons:\n" + "\n".join(lines)

    @command.command("ai.code")
    def show_code(self, name: str) -> str:
        """Show the source code of an AI-generated addon."""
        entry = self.generated_addons.get(name)
        if not entry:
            names = ", ".join(self.generated_addons.keys()) or "(none)"
            return f"No addon named '{name}'. Loaded: {names}"
        return entry[1]

    @command.command("ai.remove")
    def remove_addon(self, name: str) -> str:
        """Remove an AI-generated addon."""
        entry = self.generated_addons.get(name)
        if not entry:
            names = ", ".join(self.generated_addons.keys()) or "(none)"
            return f"No addon named '{name}'. Loaded: {names}"
        try:
            ctx.master.addons.remove(entry[0])
        except Exception:
            pass
        del self.generated_addons[name]
        ctx.log.info(f"[AI] Addon '{name}' removed.")
        return f"Removed addon '{name}'."

    @command.command("ai.mcp")
    def mcp_info(self) -> str:
        """Show how to connect Claude Code to this TUI session."""
        ctl_port = ctx.options.ai_control_port
        lines = [
            "Connect Claude Code to this mitmproxy session:",
            "",
            f"  Control API: http://127.0.0.1:{ctl_port}",
            "",
            "  Add this MCP server to Claude Code settings:",
            "  {",
            '    "mcpServers": {',
            '      "mitmproxy-live": {',
            '        "command": "python3",',
            f'        "args": ["{os.path.expanduser("~/.mitmproxy/mcp_bridge.py")}"]',
            "      }",
            "    }",
            "  }",
            "",
            "  Then in Claude Code, the mitmproxy-live tools operate on this TUI's traffic.",
        ]
        return "\n".join(lines)

    @command.command("ai.flows")
    def show_flows(self, name: str) -> str:
        """Show flows tagged by a specific AI addon."""
        tag = f"ai:{name}"
        matches = []
        for f in ctx.master.view:
            if hasattr(f, "comment") and f.comment and tag in f.comment:
                if isinstance(f, http.HTTPFlow):
                    status = f.response.status_code if f.response else "?"
                    matches.append(
                        f"  {f.id[:8]}  {f.request.method:6s}  {status}  {f.request.pretty_url[:80]}"
                    )
        if not matches:
            return f"No flows tagged '{tag}' yet."
        return f"Flows tagged '{tag}':\n" + "\n".join(matches)

    @command.command("ai.filter")
    def filter_ai_flows(self, name: str = "") -> None:
        """Set the view filter to show only AI-tagged flows.
        With a name, filters to a specific addon. Without, shows all AI flows."""
        if name:
            filt = f"~comment ai:{name}"
        else:
            filt = "~comment ai:"
        ctx.options.update(view_filter=filt)
        ctx.log.info(f"[AI] View filter set: {filt}")

    @command.command("ai.filter.clear")
    def filter_clear(self) -> None:
        """Clear the AI view filter, showing all flows again."""
        ctx.options.update(view_filter=None)
        ctx.log.info("[AI] View filter cleared.")

    @command.command("ai.dashboard")
    def dashboard(self) -> str:
        """Show AI activity dashboard: loaded addons, tagged flow counts, control API status."""
        lines = ["AI Dashboard", "=" * 50, ""]

        # Control API status
        ctl_port = ctx.options.ai_control_port
        if ctl_port:
            lines.append(f"Control API:  http://127.0.0.1:{ctl_port}")
        else:
            lines.append("Control API:  disabled")
        lines.append(f"AI Provider:  {ctx.options.ai_provider}")
        model = self._effective_model()
        lines.append(f"AI Model:     {model or '(provider default)'}")
        lines.append("")

        # Addons
        lines.append("Loaded Addons:")
        if self.generated_addons:
            for name, (instance, code) in self.generated_addons.items():
                # Count flows
                count = 0
                tag = f"ai:{name}"
                for f in ctx.master.view:
                    if isinstance(f, http.HTTPFlow) and f.comment and tag in f.comment:
                        count += 1
                hook_names = []
                for hook in ("request", "response", "error"):
                    if hasattr(instance, hook) and callable(getattr(instance, hook)):
                        hook_names.append(hook)
                hooks_str = ", ".join(hook_names) or "none"
                lines.append(f"  {name}")
                lines.append(f"    hooks: {hooks_str}  |  flows: {count}")
                lines.append(f"    code: {len(code.splitlines())} lines")
        else:
            lines.append("  (none)")
        lines.append("")

        # Overall AI flow stats
        ai_flow_count = 0
        addon_counts: dict[str, int] = {}
        for f in ctx.master.view:
            if isinstance(f, http.HTTPFlow) and f.comment and f.comment.startswith("ai:"):
                ai_flow_count += 1
                addon_name = f.comment.split("ai:", 1)[1].split()[0] if "ai:" in f.comment else "unknown"
                addon_counts[addon_name] = addon_counts.get(addon_name, 0) + 1
        lines.append(f"Total AI-tagged flows: {ai_flow_count} / {len(ctx.master.view)}")
        if addon_counts:
            for aname, cnt in sorted(addon_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  ai:{aname}: {cnt}")
        lines.append("")

        # Quick commands
        lines.append("Quick Commands:")
        lines.append("  :ai.filter                — show only AI flows")
        lines.append("  :ai.filter <name>         — show flows from one addon")
        lines.append("  :ai.filter.clear          — show all flows")
        lines.append("  :ai.addon \"description\"   — generate + load addon")
        lines.append("  :ai.code <name>           — view addon source")
        lines.append("  :ai.remove <name>         — unload addon")

        return "\n".join(lines)


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower().strip())
    slug = slug.strip("_")[:40]
    return slug or "unnamed"


addons = [AIAddon()]
