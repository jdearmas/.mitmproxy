"""
Scope addon for mitmproxy.

Point it at a scope file (e.g. a HackerOne structured-scope CSV export) and it
registers two filter flags:

* ``~inscope``     — in scope **and** eligible for a bug bounty.
* ``~inscope-all`` — everything in scope (whether or not it pays a bounty).

``~inscope`` is a subset of ``~inscope-all``.

Usage
-----
Set the scope file via option (config.yaml or the options editor)::

    scope_file: /path/to/scope.csv

or from the TUI command bar / mitmdump::

    : scope.load /path/to/scope.csv

Then filter with the flags anywhere a filter is accepted, e.g. set the view
filter with ``f ~inscope`` in the flow list, or run ``: scope.only`` /
``: scope.only-all``. They compose like any other flag: ``~inscope & ~m POST``,
``!~inscope-all``, ``~inscope-all & !~inscope``.

Scope file formats
------------------
* HackerOne structured-scope CSV (``identifier``, ``asset_type``,
  ``eligible_for_submission``, ``eligible_for_bounty``, ...). ``~inscope-all``
  covers rows eligible for submission; ``~inscope`` narrows that to rows also
  eligible for a bounty. A single ``identifier`` cell may hold several
  comma-separated targets.
* Any CSV with an identifier-ish column (``identifier``/``url``/``host``/
  ``domain``/``target``/``asset``). Without eligibility columns, both flags
  cover every row.
* A plain text list, one target per line.

Recognised targets: exact hosts (``api.example.com``), wildcards
(``*.example.com``), full URLs (``https://example.com/app`` scopes that path
subtree) and CIDR / IP ranges (``10.0.0.0/8``). Asset types that can't appear
on the wire (mobile app IDs, source-code repos, free-text "OTHER" entries) are
skipped.
"""

import csv
import ipaddress
import logging
import os
from urllib.parse import urlsplit

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy import flow as mflow
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import types

logger = logging.getLogger(__name__)

# Asset types from HackerOne (or similar) that we cannot match against live
# HTTP/DNS traffic and therefore ignore for scoping.
_NON_WIRE_ASSET_TYPES = {
    "GOOGLE_PLAY_APP_ID",
    "APPLE_STORE_APP_ID",
    "WINDOWS_APP_STORE_APP_ID",
    "SOURCE_CODE",
    "OTHER",
    "SMART_CONTRACT",
    "DOWNLOADABLE_EXECUTABLES",
    "HARDWARE",
    "AI_MODEL",
    "TESTFLIGHT",
}

# Columns we'll accept as the target identifier, in order of preference.
_IDENTIFIER_COLUMNS = ("identifier", "asset_identifier", "asset", "url", "host", "domain", "target")


class ScopeSet:
    """A compiled set of scope targets that answers "is this flow in it?"."""

    def __init__(self) -> None:
        self.exact_hosts: set[str] = set()
        self.wildcard_bases: set[str] = set()
        self.networks: list = []  # ipaddress networks
        self.path_rules: list[tuple[str, str]] = []  # (host, path_prefix)
        self.skipped: int = 0

    @property
    def loaded(self) -> bool:
        return bool(self.exact_hosts or self.wildcard_bases or self.networks or self.path_rules)

    @property
    def size(self) -> int:
        return len(self.exact_hosts) + len(self.wildcard_bases) + len(self.networks) + len(self.path_rules)

    def add_target(self, token: str, asset_type: str = "") -> bool:
        """Add a single scope target. Returns True if it produced a matcher."""
        token = token.strip().strip("\"'").lower().rstrip(".")
        if not token or token.startswith("#"):
            return False

        at = (asset_type or "").upper()
        if at in _NON_WIRE_ASSET_TYPES:
            return False

        # CIDR / IP range (also covers a bare "1.2.3.4/32").
        if "/" in token and at not in {"URL", "WILDCARD"}:
            net = _try_network(token)
            if net is not None:
                self.networks.append(net)
                return True

        host, path = _split_host_path(token)
        if not host:
            return False

        # A bare IP or CIDR that reached here (e.g. asset_type CIDR).
        net = _try_network(host)
        if net is not None and not path:
            self.networks.append(net)
            return True

        if host.startswith("*."):
            self.wildcard_bases.add(host[2:])
        elif host.startswith("*"):
            base = host.lstrip("*").lstrip(".")
            if base:
                self.wildcard_bases.add(base)
        elif path and path not in ("", "/"):
            # URL that scopes only a path subtree.
            self.path_rules.append((host, path))
        else:
            self.exact_hosts.add(host)
        return True

    def matches(self, f: mflow.Flow) -> bool:
        host = _flow_host(f)
        if not host:
            return False

        if host in self.exact_hosts:
            return True

        for base in self.wildcard_bases:
            if host == base or host.endswith("." + base):
                return True

        if self.networks:
            ip = _try_ip(host)
            if ip is not None and any(ip in net for net in self.networks):
                return True

        if self.path_rules:
            path = _flow_path(f)
            for h, prefix in self.path_rules:
                if host == h and path.startswith(prefix):
                    return True

        return False


class Scope:
    """The two tiers consulted by the filter flags, plus their source."""

    def __init__(self) -> None:
        self.source: str = ""
        self.all = ScopeSet()  # ~inscope-all : everything in scope
        self.bounty = ScopeSet()  # ~inscope     : in scope AND bounty-eligible


# Current scope consulted by the filters.
_SCOPE = Scope()


def _try_network(token: str):
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def _try_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _split_host_path(token: str) -> tuple[str, str]:
    """Return (host, path) for a target that may be a bare host or a URL."""
    if "://" in token:
        parts = urlsplit(token)
        return (parts.hostname or "").lower(), parts.path
    if token.startswith("//"):
        parts = urlsplit("http:" + token)
        return (parts.hostname or "").lower(), parts.path
    if "/" in token:
        host, _, rest = token.partition("/")
        # A wildcard path like "*/xmlrpc.php" has no real host to scope.
        if not host or host == "*":
            return "", ""
        return host.split(":", 1)[0], "/" + rest
    return token.split(":", 1)[0], ""


def _flow_host(f: mflow.Flow) -> str:
    if isinstance(f, http.HTTPFlow):
        if f.request:
            return (f.request.pretty_host or "").lower().rstrip(".")
    elif isinstance(f, dns.DNSFlow):
        if f.request and f.request.questions:
            return f.request.questions[0].name.lower().rstrip(".")
    if f.server_conn and f.server_conn.address:
        return str(f.server_conn.address[0]).lower().rstrip(".")
    return ""


def _flow_path(f: mflow.Flow) -> str:
    if isinstance(f, http.HTTPFlow) and f.request:
        return f.request.path or "/"
    return "/"


class FInScope(flowfilter._Action):
    code = "inscope"
    help = "Match flows in scope and eligible for a bug bounty"

    def __call__(self, f: mflow.Flow) -> bool:
        return _SCOPE.bounty.matches(f)


class FInScopeAll(flowfilter._Action):
    code = "inscope-all"
    help = "Match flows anywhere in scope (bounty-eligible or not)"

    def __call__(self, f: mflow.Flow) -> bool:
        return _SCOPE.all.matches(f)


# Longer code first so MatchFirst prefers ~inscope-all over the ~inscope prefix.
_FILTERS = [FInScopeAll, FInScope]


def _register_filters() -> None:
    """Teach mitmproxy's filter grammar about our flags (idempotent)."""
    existing = {getattr(c, "code", None) for c in flowfilter.filter_unary}
    added = [cls for cls in _FILTERS if cls.code not in existing]
    if not added:
        return
    flowfilter.filter_unary = list(flowfilter.filter_unary) + added
    flowfilter.bnf = flowfilter._make()
    for cls in added:
        flowfilter.help.append((f"~{cls.code}", cls.help))
    flowfilter.help.sort()


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in ("true", "yes", "1")


def _load_scope_file(path: str) -> Scope | None:
    """Parse a scope file into a fresh Scope, or None on failure."""
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        logger.error(f"scope: file not found: {path}")
        return None

    sc = Scope()
    sc.source = path
    eligible_only = ctx.options.scope_eligible_only if _option_defined("scope_eligible_only") else True

    try:
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fp:
            sample = fp.read(4096)
            fp.seek(0)
            has_header = "," in sample and any(
                col in sample.lower() for col in _IDENTIFIER_COLUMNS
            )
            if has_header:
                _load_csv(fp, sc, eligible_only)
            else:
                _load_lines(fp, sc)
    except OSError as e:
        logger.error(f"scope: could not read {path}: {e}")
        return None

    if not sc.all.loaded:
        logger.warning(f"scope: no matchable targets found in {path}")
    return sc


def _load_csv(fp, sc: Scope, eligible_only: bool) -> None:
    reader = csv.DictReader(fp)
    fields = {(name or "").strip().lower(): name for name in (reader.fieldnames or [])}
    id_col = next((fields[c] for c in _IDENTIFIER_COLUMNS if c in fields), None)
    if id_col is None:
        logger.warning("scope: no identifier column found; reading first column")
    type_col = fields.get("asset_type")
    submission_col = fields.get("eligible_for_submission")
    bounty_col = fields.get("eligible_for_bounty")

    for row in reader:
        # Which tiers does this row belong to?
        if submission_col and eligible_only:
            in_all = _truthy(row.get(submission_col, ""))
        else:
            in_all = True
        if bounty_col:
            in_bounty = _truthy(row.get(bounty_col, ""))
        else:
            # No bounty column — treat the whole scope as bounty-eligible.
            in_bounty = in_all
        if not (in_all or in_bounty):
            continue

        raw = row.get(id_col) if id_col else next(iter(row.values()), "")
        asset_type = (row.get(type_col) or "") if type_col else ""
        if not raw:
            continue
        # A single cell may hold several comma-separated targets.
        for token in str(raw).split(","):
            if not token.strip():
                continue
            hit = False
            if in_all:
                hit |= sc.all.add_target(token, asset_type)
            if in_bounty:
                hit |= sc.bounty.add_target(token, asset_type)
            if not hit:
                sc.all.skipped += 1


def _load_lines(fp, sc: Scope) -> None:
    for line in fp:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        added = sc.all.add_target(line)
        sc.bounty.add_target(line)
        if not added:
            sc.all.skipped += 1


def _option_defined(name: str) -> bool:
    try:
        return name in ctx.options
    except Exception:
        return False


class ScopeAddon:
    def load(self, loader) -> None:
        loader.add_option(
            "scope_file",
            str,
            "",
            "Path to a scope file (HackerOne structured-scope CSV, any CSV with "
            "an identifier column, or a plain host-per-line list). Enables the "
            "~inscope and ~inscope-all filters.",
        )
        loader.add_option(
            "scope_eligible_only",
            bool,
            True,
            "When loading a HackerOne CSV, ~inscope-all only covers rows "
            "eligible for submission (disable to include every row).",
        )
        _register_filters()

    def configure(self, updated) -> None:
        if "scope_file" in updated or "scope_eligible_only" in updated:
            path = ctx.options.scope_file
            if path:
                self._apply(_load_scope_file(path))
            elif "scope_file" in updated:
                global _SCOPE
                _SCOPE = Scope()
                logger.info("scope: cleared")

    def _apply(self, sc: Scope | None) -> None:
        global _SCOPE
        if sc is None:
            return
        _SCOPE = sc
        a, b = sc.all, sc.bounty
        logger.info(
            f"scope: loaded from {sc.source} — ~inscope-all: {a.size} target(s) "
            f"({len(a.exact_hosts)} host, {len(a.wildcard_bases)} wildcard, "
            f"{len(a.networks)} net, {len(a.path_rules)} path); "
            f"~inscope (bounty): {b.size} target(s)"
            + (f"; {a.skipped} skipped" if a.skipped else "")
        )

    @command.command("scope.load")
    def scope_load(self, path: types.Path) -> None:
        """Load a scope file and enable the ~inscope / ~inscope-all filters."""
        ctx.options.update(scope_file=str(path))

    @command.command("scope.clear")
    def scope_clear(self) -> None:
        """Clear the loaded scope."""
        ctx.options.update(scope_file="")

    @command.command("scope.only")
    def scope_only(self) -> None:
        """Set the flow-list view filter to ~inscope (bounty-eligible)."""
        if not _SCOPE.bounty.loaded:
            logger.warning("scope: no bounty-eligible scope loaded; set scope_file first")
            return
        ctx.options.update(view_filter="~inscope")

    @command.command("scope.only-all")
    def scope_only_all(self) -> None:
        """Set the flow-list view filter to ~inscope-all (everything in scope)."""
        if not _SCOPE.all.loaded:
            logger.warning("scope: no scope loaded; set scope_file first")
            return
        ctx.options.update(view_filter="~inscope-all")

    @command.command("scope.info")
    def scope_info(self) -> str:
        """Report the currently loaded scope."""
        if not _SCOPE.all.loaded and not _SCOPE.bounty.loaded:
            return "scope: nothing loaded (set scope_file)"
        a, b = _SCOPE.all, _SCOPE.bounty
        return (
            f"scope: from {_SCOPE.source} — "
            f"~inscope-all {a.size} target(s) "
            f"({len(a.exact_hosts)} exact, {len(a.wildcard_bases)} wildcard, "
            f"{len(a.networks)} net, {len(a.path_rules)} path); "
            f"~inscope {b.size} bounty-eligible target(s)"
        )


addons = [ScopeAddon()]
