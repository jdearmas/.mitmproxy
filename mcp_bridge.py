#!/usr/bin/env python3
"""
MCP bridge: connects Claude Code to a running mitmproxy TUI session.

This is a stdio MCP server that proxies tool calls to the mitmproxy AI addon's
control API (http://127.0.0.1:8081 by default). Add to Claude Code settings:

{
  "mcpServers": {
    "mitmproxy-live": {
      "command": "python3",
      "args": ["~/.mitmproxy/mcp_bridge.py"]
    }
  }
}

The control API is authenticated. This bridge reads the bearer token from
$MITMPROXY_CONTROL_TOKEN, else from ~/.mitmproxy/control_token, which the
addon creates 0600 on first start.

Requires: pip install mcp httpx
"""

import json
import os
import sys
import httpx

CONTROL_URL = os.environ.get("MITMPROXY_CONTROL_URL", "http://127.0.0.1:8081")
TOKEN_PATH = os.environ.get(
    "MITMPROXY_CONTROL_TOKEN_FILE", os.path.expanduser("~/.mitmproxy/control_token")
)

# MCP protocol over stdio — minimal implementation
# Handles initialize, tools/list, tools/call


def _auth_token():
    token = os.environ.get("MITMPROXY_CONTROL_TOKEN", "").strip()
    if token:
        return token
    try:
        with open(TOKEN_PATH, "r") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _http(method, path, **kwargs):
    """Synchronous HTTP call to the control server."""
    token = _auth_token()
    if not token:
        return {
            "error": (
                f"No control token. Expected {TOKEN_PATH} (created by the addon on "
                "first start) or $MITMPROXY_CONTROL_TOKEN. Is mitmproxy running?"
            )
        }
    url = f"{CONTROL_URL}{path}"
    headers = {**kwargs.pop("headers", {}), "Authorization": f"Bearer {token}"}
    try:
        resp = httpx.request(method, url, timeout=120, headers=headers, **kwargs)
        if resp.status_code in (401, 403):
            return {
                "error": (
                    f"Control API rejected the token ({resp.status_code}). "
                    f"The addon may have regenerated {TOKEN_PATH}."
                )
            }
        return resp.json()
    except httpx.ConnectError:
        return {"error": f"Cannot connect to mitmproxy control API at {CONTROL_URL}. Is mitmproxy running with the AI addon?"}
    except Exception as e:
        return {"error": str(e)}


TOOLS = [
    {
        "name": "get_traffic_summary",
        "description": "Get recent HTTP flows from the live mitmproxy TUI session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max flows to return", "default": 50},
            },
        },
    },
    {
        "name": "inspect_flow",
        "description": "Get full details of a specific flow (headers, body, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_id": {"type": "string", "description": "The flow ID"},
            },
            "required": ["flow_id"],
        },
    },
    {
        "name": "search_traffic",
        "description": "Search captured traffic by keyword, domain, method, or addon tag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Keyword to search in URL/body"},
                "domain": {"type": "string", "description": "Filter by domain"},
                "method": {"type": "string", "description": "Filter by HTTP method"},
                "tag": {"type": "string", "description": "Filter by flow comment/tag (e.g. 'ai:my_addon')"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "create_addon",
        "description": "Create and hot-load a mitmproxy addon in the TUI. Provide a natural language description (AI generates code) OR provide code directly. The addon runs live in the TUI — you'll see its effects immediately.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "description": {"type": "string", "description": "Natural language description of what the addon should do"},
                "code": {"type": "string", "description": "Raw Python addon code (class DynamicAddon). Skips AI generation."},
                "name": {"type": "string", "description": "Addon name (auto-generated from description if omitted)"},
            },
        },
    },
    {
        "name": "list_addons",
        "description": "List all AI-generated addons currently loaded in the mitmproxy TUI.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "remove_addon",
        "description": "Remove an AI-generated addon from the running mitmproxy TUI.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Addon name to remove"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "get_addon_code",
        "description": "View the source code of an AI-generated addon.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Addon name"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "get_addon_flows",
        "description": "Get all flows tagged/modified by a specific AI addon.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Addon name"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "replay_flow",
        "description": "Replay a captured flow with optional modifications. The replayed request goes through the TUI so you see it there.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_id": {"type": "string", "description": "Flow ID to replay"},
                "method": {"type": "string", "description": "Override HTTP method"},
                "headers": {"type": "object", "description": "Headers to add/override"},
                "body": {"type": "string", "description": "Override request body"},
            },
            "required": ["flow_id"],
        },
    },
    {
        "name": "get_status",
        "description": "Check the connection status to the mitmproxy TUI and get session info.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def handle_tool_call(name, args):
    if name == "get_traffic_summary":
        return _http("GET", "/flows", params={"limit": args.get("limit", 50)})
    elif name == "inspect_flow":
        return _http("GET", f"/flows/{args['flow_id']}")
    elif name == "search_traffic":
        params = {}
        if args.get("query"):
            params["q"] = args["query"]
        if args.get("domain"):
            params["domain"] = args["domain"]
        if args.get("method"):
            params["method"] = args["method"]
        if args.get("tag"):
            params["tag"] = args["tag"]
        params["limit"] = args.get("limit", 50)
        return _http("GET", "/search", params=params)
    elif name == "create_addon":
        payload = {}
        if args.get("description"):
            payload["description"] = args["description"]
        if args.get("code"):
            payload["code"] = args["code"]
        if args.get("name"):
            payload["name"] = args["name"]
        return _http("POST", "/addon", json=payload)
    elif name == "list_addons":
        return _http("GET", "/addons")
    elif name == "remove_addon":
        return _http("DELETE", f"/addon/{args['name']}")
    elif name == "get_addon_code":
        return _http("GET", f"/addon/{args['name']}/code")
    elif name == "get_addon_flows":
        return _http("GET", f"/addon/{args['name']}/flows")
    elif name == "replay_flow":
        payload = {}
        if args.get("method"):
            payload["method"] = args["method"]
        if args.get("headers"):
            payload["headers"] = args["headers"]
        if args.get("body") is not None:
            payload["body"] = args["body"]
        return _http("POST", f"/replay/{args['flow_id']}", json=payload)
    elif name == "get_status":
        return _http("GET", "/status")
    else:
        return {"error": f"Unknown tool: {name}"}


def main():
    """Run as stdio MCP server."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method = msg.get("method", "")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "mitmproxy-live",
                        "version": "1.0.0",
                    },
                },
            }
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS},
            }
        elif method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            result = handle_tool_call(tool_name, tool_args)
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {"type": "text", "text": json.dumps(result, indent=2)}
                    ],
                },
            }
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {},
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
