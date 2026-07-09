"""
Flow Diff addon for mitmproxy TUI.

Mark two or more flows with 'm' in the flow list, then press 't' to open
a side-by-side diff view comparing their requests and responses pairwise.
"""

import difflib
import logging

import urwid

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.tools.console import layoutwidget
from mitmproxy.tools.console import signals
from mitmproxy.tools.console.keymap import Contexts
from mitmproxy.utils import strutils

logger = logging.getLogger(__name__)


def _format_request(flow: http.HTTPFlow) -> list[str]:
    lines = []
    req = flow.request
    lines.append(f"{req.method} {req.url} {req.http_version}")
    for k, v in req.headers.fields:
        lines.append(
            f"{strutils.bytes_to_escaped_str(k)}: {strutils.bytes_to_escaped_str(v)}"
        )
    lines.append("")
    if req.raw_content:
        for line in req.raw_content.decode("utf-8", errors="replace").splitlines():
            lines.append(line)
    return lines


def _format_response(flow: http.HTTPFlow) -> list[str]:
    lines = []
    resp = flow.response
    if not resp:
        lines.append("[no response]")
        return lines
    lines.append(f"{resp.http_version} {resp.status_code} {resp.reason}")
    for k, v in resp.headers.fields:
        lines.append(
            f"{strutils.bytes_to_escaped_str(k)}: {strutils.bytes_to_escaped_str(v)}"
        )
    lines.append("")
    if resp.raw_content:
        for line in resp.raw_content.decode("utf-8", errors="replace").splitlines():
            lines.append(line)
    return lines


def _side_by_side(a_lines, b_lines, a_label, b_label):
    """Build side-by-side diff rows as urwid widgets."""
    sm = difflib.SequenceMatcher(None, a_lines, b_lines)
    rows = []

    rows.append(
        urwid.Columns([
            urwid.AttrMap(urwid.Text(a_label, wrap="clip"), "heading"),
            ("fixed", 1, urwid.AttrMap(urwid.Text("│"), "heading")),
            urwid.AttrMap(urwid.Text(b_label, wrap="clip"), "heading"),
        ])
    )

    for op, a1, a2, b1, b2 in sm.get_opcodes():
        if op == "equal":
            for i in range(a2 - a1):
                rows.append(_diff_row(a_lines[a1 + i], b_lines[b1 + i], "text"))
        elif op == "replace":
            n = max(a2 - a1, b2 - b1)
            for i in range(n):
                left = a_lines[a1 + i] if (a1 + i) < a2 else ""
                right = b_lines[b1 + i] if (b1 + i) < b2 else ""
                rows.append(_diff_row(left, right, "changed"))
        elif op == "delete":
            for i in range(a1, a2):
                rows.append(_diff_row(a_lines[i], "", "deleted"))
        elif op == "insert":
            for i in range(b1, b2):
                rows.append(_diff_row("", b_lines[i], "inserted"))

    if not any(op != "equal" for op, *_ in sm.get_opcodes()):
        rows.append(
            urwid.Columns([
                urwid.AttrMap(urwid.Text("(identical)", wrap="clip"), "highlight"),
                ("fixed", 1, urwid.Text("│")),
                urwid.AttrMap(urwid.Text("(identical)", wrap="clip"), "highlight"),
            ])
        )

    return rows


_DIFF_STYLES = {
    "text": ("text", "text", "text"),
    "changed": ("error", "text", "option_active"),
    "deleted": ("error", "text", "text"),
    "inserted": ("text", "text", "option_active"),
}


def _diff_row(left, right, kind):
    left_attr, div_attr, right_attr = _DIFF_STYLES[kind]
    return urwid.Columns([
        urwid.AttrMap(urwid.Text(left, wrap="clip"), left_attr),
        ("fixed", 1, urwid.AttrMap(urwid.Text("│"), div_attr)),
        urwid.AttrMap(urwid.Text(right, wrap="clip"), right_attr),
    ])


def _flow_label(f, idx):
    if isinstance(f, http.HTTPFlow):
        return f"[{idx + 1}] {f.request.method} {f.request.url}"
    return f"[{idx + 1}] {type(f).__name__}"


class FlowDiffView(urwid.Frame, layoutwidget.LayoutWidget):
    keyctx = "flowdiff"
    title = "Flow Diff"

    def __init__(self, master, flows):
        self.master = master
        self.diff_flows = flows
        body = self._build_diff()
        super().__init__(body)

    def _build_diff(self):
        widgets = []

        http_flows = [f for f in self.diff_flows if isinstance(f, http.HTTPFlow)]
        if len(http_flows) < 2:
            widgets.append(urwid.Text(("error", "Need at least 2 marked HTTP flows to diff.")))
            return self._scrollable(widgets)

        for i in range(len(http_flows) - 1):
            fa, fb = http_flows[i], http_flows[i + 1]
            la = _flow_label(fa, i)
            lb = _flow_label(fb, i + 1)

            widgets.append(urwid.AttrMap(urwid.Text(f"{'=' * 80}"), "title"))
            widgets.append(urwid.AttrMap(urwid.Text(f"  {la}  vs  {lb}"), "title"))
            widgets.append(urwid.AttrMap(urwid.Text(f"{'=' * 80}"), "title"))
            widgets.append(urwid.Text(""))

            widgets.append(urwid.AttrMap(urwid.Text(" Request "), "heading"))
            widgets.extend(_side_by_side(
                _format_request(fa), _format_request(fb),
                f"[{i + 1}] request", f"[{i + 2}] request",
            ))
            widgets.append(urwid.Text(""))

            widgets.append(urwid.AttrMap(urwid.Text(" Response "), "heading"))
            widgets.extend(_side_by_side(
                _format_response(fa), _format_response(fb),
                f"[{i + 1}] response", f"[{i + 2}] response",
            ))
            widgets.append(urwid.Text(""))

        return self._scrollable(widgets)

    def _scrollable(self, widgets):
        walker = urwid.SimpleFocusListWalker(widgets)
        listbox = urwid.ListBox(walker)
        return listbox

    def keypress(self, size, key):
        if key in ("q", "esc"):
            signals.pop_view_state.send()
            return None
        if key in ("j", "page down"):
            return super().keypress(size, "page down")
        if key in ("k", "page up"):
            return super().keypress(size, "page up")
        if key == "m_start":
            self.body.set_focus(0)
            return None
        if key == "m_end":
            self.body.set_focus(len(self.body.body) - 1)
            return None
        return super().keypress(size, key)

    def focus_changed(self):
        pass


class FlowDiffAddon:
    @command.command("flowdiff.view")
    def view_diff(self) -> None:
        """Show a side-by-side diff of all marked flows."""
        marked = [f for f in ctx.master.view._store.values() if f.marked]
        if len(marked) < 2:
            signals.status_message.send(
                message="Mark at least 2 flows with 'm', then press 't' to diff.",
                expire=3,
            )
            return

        view = FlowDiffView(ctx.master, marked)
        ctx.master.window.stacks[ctx.master.window.pane].windows["flowdiff"] = view
        ctx.master.switch_view("flowdiff")

    def running(self):
        Contexts.add("flowdiff")
        ctx.master.keymap.add(
            "t", "flowdiff.view", ["flowlist"], "Diff marked flows"
        )


addons = [FlowDiffAddon()]
