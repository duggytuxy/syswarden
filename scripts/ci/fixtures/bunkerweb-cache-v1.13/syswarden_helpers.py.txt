#!/usr/bin/env python3
"""Pure, dependency-free helpers shared by the SysWarden plugin jobs.

Kept free of any BunkerWeb (`/usr/share/bunkerweb/...`) or third-party imports so the
logic can be unit-tested with pytest outside the scheduler image (see tests/). The job
scripts import these and keep all the I/O (requests / Redis / instance API / JOB cache)
to themselves.
"""

from contextlib import suppress
from hashlib import sha256
from ipaddress import ip_address, ip_network
from itertools import islice
from os import getenv
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path
from re import fullmatch
from secrets import token_urlsafe
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Default port of SysWarden's HA API (`[integrations.ha] peer_port`).
SYSWARDEN_DEFAULT_PORT = 62026

# Bounds SysWarden enforces on a temporary ban. TTL comes from firewall.MinimumBanTTL /
# MaximumBanTTL, the two byte caps from maxHAReasonBytes / maxHASourceBytes, and the batch
# size from maxHABansPerRequest. A payload outside any of them is answered with a 400, so
# the plugin clamps rather than letting a whole batch be refused.
SYSWARDEN_MIN_TTL = 1
SYSWARDEN_MAX_TTL = 30 * 24 * 3600
SYSWARDEN_MAX_REASON_BYTES = 512
SYSWARDEN_MAX_SOURCE_BYTES = 64
SYSWARDEN_MAX_BANS_PER_REQUEST = 500
SYSWARDEN_MAX_IPS_PER_REQUEST = 1024

# IANA special-purpose blocks SysWarden refuses as a firewall mutation target, copied
# verbatim from deniedFirewallTargetPrefixes in syswarden-core/utils/target_policy.go
# (v4.03.2). Sources upstream cites: iana-ipv4-special-registry, iana-ipv6-special-registry.
# Mirrored rather than approximated with ipaddress' own is_private/is_reserved, which draw
# the line in a different place: being stricter than the peer would silently stop bans it
# would have accepted, being looser would put the batch-killing 400 back.
SYSWARDEN_DENIED_TARGET_PREFIXES = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::/96",
    "::1/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "2620:4f:8000::/48",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fec0::/10",
    "fe80::/10",
    "ff00::/8",
)

_DENIED_TARGET_NETWORKS = tuple(ip_network(prefix) for prefix in SYSWARDEN_DENIED_TARGET_PREFIXES)

# How long an address must stay absent from every peer before the plugin drops its claim.
# SysWarden replicates the static blocklist between peers on its own cron, roughly every
# 30 minutes, and that run can also be started by hand or already be in flight. A single
# clean pass is convergence, not proof, so the claim is held well past one such period.
# Upstream shipped the verifiable local fence (`native_sync_fence_v1`) in v4.03.2; until a
# peer can attest to it, no finite window here proves the migration is over.
SYSWARDEN_LEGACY_GRACE = 3600

# The local cluster fence of v4.03.2 (ha_fence.go). `native_sync_fence_v1` is the capability
# a peer advertises on /ha/status; the proof itself is the dynamic `native_sync_fence` object.
# The two scopes are different strings and are not interchangeable: the status object is scoped
# to the mutations it fences, the manifest to what the operator asserts he enumerated.
SYSWARDEN_FENCE_CAPABILITY = "native_sync_fence_v1"
SYSWARDEN_FENCE_VERSION = 1
SYSWARDEN_FENCE_SCHEMA_VERSION = 1
SYSWARDEN_FENCE_STATUS_SCOPE = "legacy_ips_mutations"
SYSWARDEN_FENCE_MANIFEST_SCOPE = "one_receiving_api_endpoint_per_syswarden_node"
SYSWARDEN_FENCE_STATE_DRAINED = "active_drained"
SYSWARDEN_FENCE_STATE_INACTIVE = "inactive"

# Shapes upstream validates, mirrored here so a malformed manifest or a malformed proof is
# refused before it can be used as evidence: haFenceUUIDv4RE, haFenceProofRE and
# validHAFenceCondition in ha_fence.go / ha_fence_manifest.go.
_FENCE_TOKEN_PATTERN = r"[A-Za-z0-9_-]{43}"
_FENCE_CONDITION_PREFIX = "sw-fence-v1-"
_FENCE_UUID4_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_SHA256_PATTERN = r"[0-9a-f]{64}"

# The charset SysWarden accepts for `source` (validHASource in ha_api.go).
_SOURCE_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-")


def get_env_secret(primary: str, fallback: str = "", default: str = "") -> str:
    """Resolve a secret value, supporting the Docker-secret ``<NAME>_FILE`` convention.

    For each candidate env name (``primary`` then ``fallback``) we try ``<NAME>_FILE``
    (read the file), then ``<NAME>`` (raw value). BunkerWeb's scheduler does not apply
    the ``_FILE`` convention to job env itself, so the plugin does it here. Returns
    ``default`` when nothing is set.
    """
    for name in (primary, fallback):
        if not name:
            continue
        file_path = getenv(f"{name}_FILE")
        if file_path:
            with suppress(OSError):
                value = Path(file_path).read_text(encoding="utf-8").strip()
                if value:
                    return value
        value = getenv(name)
        if value:
            return value.strip() if isinstance(value, str) else value
    return default


def parse_peers(value: Optional[str], default_port: int = SYSWARDEN_DEFAULT_PORT) -> Tuple[List[str], List[str]]:
    """Turn the ``SYSWARDEN_PEERS`` setting into base URLs.

    Accepts ``host``, ``host:port``, a bare IPv6 literal (``2001:db8::1``) and a
    bracketed one with a port (``[2001:db8::1]:62026``). A bare IPv6 literal cannot
    carry a port — the colons are the address — so it always gets ``default_port``.

    Returns ``(urls, errors)`` rather than raising: one malformed entry must not stop
    the plugin from talking to the peers that are fine. The caller logs ``errors``.
    """
    urls: List[str] = []
    errors: List[str] = []
    for entry in (value or "").split():
        host, port = entry, str(default_port)
        if entry.startswith("["):
            host, sep_found, rest = entry[1:].partition("]")
            if not sep_found:
                errors.append(f"{entry} (unclosed '[')")
                continue
            if rest:
                if not rest.startswith(":"):
                    errors.append(f"{entry} (trailing data after ']')")
                    continue
                port = rest[1:]
        elif entry.count(":") == 1:
            host, _, port = entry.partition(":")

        if not host:
            errors.append(f"{entry} (empty host)")
            continue
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            errors.append(f"{entry} (invalid port)")
            continue
        if not 1 <= port_number <= 65535:
            errors.append(f"{entry} (port out of range)")
            continue

        # A URL authority needs the brackets back for IPv6.
        authority = f"[{host}]" if ":" in host else host
        urls.append(f"https://{authority}:{port_number}")
    return urls, errors


def parse_ban_key(key) -> Optional[Dict[str, str]]:
    """Extract ``{"ip", "service"}`` from a BunkerWeb Redis ban key.

    Global bans use ``bans_ip_<IP>``; service bans use ``bans_service_<service>_ip_<IP>``.
    Returns None if the key is not a ban key. ``service`` is ``""`` for a global ban.
    """
    if isinstance(key, bytes):
        key = key.decode("utf-8", "replace")
    if key.startswith("bans_service_") and "_ip_" in key:
        service, _, ip = key.removeprefix("bans_service_").rpartition("_ip_")
        if not ip:
            return None
        return {"ip": ip, "service": service}
    if key.startswith("bans_ip_"):
        ip = key.removeprefix("bans_ip_")
        return {"ip": ip, "service": ""} if ip else None
    return None


def canonical_address(value: Optional[str]) -> str:
    """Render an address the way SysWarden stores it, or ``""`` if it would be refused.

    Mirrors Go's ``canonicalHAAddress``: ``netip`` parsing, IPv4-mapped and zoned
    addresses rejected, a network masked to its prefix. Two reasons this has to happen
    before anything goes on the wire. A single refused entry makes SysWarden reject the
    *entire* batch of up to 500 bans, so one malformed address would stop every ban that
    minute. And an address that differs only in case (``2001:DB8::1``) is accepted but
    stored canonicalized, so without this the next pass sees it as both "to add" and "to
    remove" and oscillates forever.
    """
    text = (value or "").strip()
    if not text:
        return ""
    try:
        if "/" in text:
            network = ip_network(text, strict=False)
            return "" if network.version == 6 and network[0].ipv4_mapped else str(network)
        address = ip_address(text)
    except ValueError:
        return ""
    if address.version == 6 and (address.ipv4_mapped or "%" in text):
        return ""
    return str(address)


def firewall_target(value: Optional[str]) -> str:
    """Render an address SysWarden will accept as a ban target, or ``""`` if it refuses it.

    Mirrors ``CanonicalFirewallMutationTarget`` (utils/target_policy.go), added in v4.03.2
    and run over every ``POST /ha/sync`` by ``validateHAMutationTargets``. This is a
    different and stricter question than :func:`canonical_address`, which only asks how
    SysWarden *stores* an address: a CIDR or an RFC1918 host is storable but is no longer a
    legal mutation target, so the two must not be merged. The pull direction still needs the
    permissive one, since a downloaded blocklist is full of CIDRs.

    Why it has to happen before the wire: ``validateHAMutationTargets`` returns on the first
    refusal, before any mutation, so **one** refused address answers the whole batch of up to
    500 with a 400. Since v4.03.2 that is reachable from ordinary traffic — BunkerWeb behind
    a proxy bans RFC1918 addresses routinely.

    Three of upstream's rules are deliberately not mirrored, because they depend on state
    only the peer has: its own interface addresses, its configured HA peer prefixes, and its
    whitelist. A 400 therefore stays possible and the caller must still isolate on it.
    """
    text = value or ""
    # Upstream refuses surrounding whitespace outright rather than trimming it, and refuses
    # anything carrying a prefix length: a mutation target is one host, never a network.
    if not text or text.strip() != text or "/" in text:
        return ""
    try:
        address = ip_address(text)
    except ValueError:
        return ""
    if address.version == 6 and (address.ipv4_mapped or address.scope_id or "%" in text):
        return ""
    # netip.Addr.IsGlobalUnicast() is false only for the unspecified, loopback and multicast
    # forms. Private and link-local unicast stay "global unicast" there and are caught by the
    # table instead, so reproducing the table is what makes this faithful.
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        return ""
    if any(address in network for network in _DENIED_TARGET_NETWORKS):
        return ""
    return str(address)


def split_push_targets(details: Dict[str, Dict]) -> Tuple[Dict[str, Dict], List[str]]:
    """Split a ban set into ``(pushable, refused)`` against :func:`firewall_target`.

    Keys are already canonical here, so this only removes entries; it never rewrites one.
    A refused address is dropped from the ban set entirely rather than merely skipped at
    send time, which is what lets the ordinary diff clean up after an upgrade: an address we
    pushed before v4.03.2 is still on the peer, no longer counts as banned, and so becomes a
    plain ``to_remove``. DELETE is not validated upstream, so that cleanup lands — and it is
    what the v4.03.2 notes ask for, "keep unsafe historical entries detectable and removable
    without allowing them to be reintroduced".
    """
    pushable: Dict[str, Dict] = {}
    refused: List[str] = []
    for ip, detail in details.items():
        if firewall_target(ip):
            pushable[ip] = detail
        else:
            refused.append(ip)
    return pushable, sorted(refused)


def normalize_ban(record: Dict) -> Optional[Dict]:
    """Normalize one ban into ``{"ip", "service", "ban_scope", "ttl", "reason"}``.

    Accepts both shapes the plugin reads: a Redis-derived dict (ip/service only) and a
    record from ``GET /bans`` on the instance API (``ip, service, ban_scope, exp,
    permanent, reason, ...``). ``ttl`` is the remaining lifetime in seconds, or None when
    the ban is permanent or carries no expiry — callers must treat None as "never
    expires", never as "expired".
    """
    ip = canonical_address(str(record.get("ip") or ""))
    if not ip:
        return None
    service = str(record.get("service") or "").strip()
    ban_scope = str(record.get("ban_scope") or ("service" if service else "global")).strip()

    ttl = None
    if not record.get("permanent"):
        exp = record.get("exp", record.get("ttl"))
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            # Redis answers -1 for a key with no expiry and -2 for one that vanished
            # between the scan and the read; the instance API answers 0 for an expired
            # ban. Only the first of those is a ban, and pushing the others would ban an
            # address BunkerWeb no longer bans — permanently so, on a peer without TTLs.
            if exp == -1:
                ttl = None
            elif exp <= 0:
                return None
            else:
                ttl = int(exp)
    return {"ip": ip, "service": service, "ban_scope": ban_scope, "ttl": ttl, "reason": str(record.get("reason") or "").strip()}


def select_bans(records: Iterable[Dict], scope_filter: Sequence[str] = (), min_ttl: int = 0) -> Dict[str, Dict]:
    """Merge ban records into ``{ip: {"ttl", "reason"}}``, ready to push.

    Deduplicates on ``(ip, ban_scope, service)`` the way BunkerWeb's own bans page does,
    then flattens to IPs: SysWarden's blocklist is host-wide, so a per-service scope has
    no meaning once the ban reaches nftables. The mapping is keyed by IP, so iterating it
    (or wrapping it in ``set()``) still yields exactly the addresses to ban.

    ``scope_filter`` limits which *services* are propagated; global bans always pass,
    since they are not tied to a service. ``min_ttl`` drops short-lived bans (rate-limit
    noise) — a permanent ban (``ttl is None``) is never dropped by it.

    When several bans collide on one IP, the longest one wins: a permanent ban (``ttl is
    None``) beats every dated one, so a shorter service ban can never cut it short.
    """
    allowed = {service for service in scope_filter if service}
    seen: Set[Tuple[str, str, str]] = set()
    bans: Dict[str, Dict] = {}
    for record in records:
        ban = normalize_ban(record)
        if not ban:
            continue
        if allowed and ban["service"] and ban["service"] not in allowed:
            continue
        if min_ttl > 0 and ban["ttl"] is not None and ban["ttl"] < min_ttl:
            continue
        key = (ban["ip"], ban["ban_scope"], ban["service"])
        if key in seen:
            continue
        seen.add(key)
        current = bans.get(ban["ip"])
        if current is None or (current["ttl"] is not None and (ban["ttl"] is None or ban["ttl"] > current["ttl"])):
            bans[ban["ip"]] = {"ttl": ban["ttl"], "reason": ban["reason"]}
    return bans


def extract_instance_bans(responses: Any, expected: int) -> Optional[List[Dict]]:
    """Return a complete BunkerWeb instance inventory, or ``None`` when partial."""
    if not isinstance(responses, dict) or len(responses) != expected:
        return None
    records: List[Dict] = []
    for response in responses.values():
        if not isinstance(response, dict):
            return None
        instance_bans = response.get("msg")
        if not isinstance(instance_bans, list):
            instance_bans = response.get("data")
        # An empty ban list never arrives as one. BunkerWeb normalises the envelope in
        # api.lua's do_api_call() before it reaches the wire: a non-empty list moves to
        # `data` and `msg` keeps the status word, but an empty list collapses to `msg: ""`
        # with no `data` at all. Reading that envelope as a partial inventory made the job
        # refuse to reconcile at exactly the moment the last ban was lifted, so the peer
        # kept that address forever. Only the successful empty envelope is translated:
        # anything else is a payload this job does not understand, and guessing at it would
        # delete bans it cannot see.
        if instance_bans is None and response.get("status") == "success" and response.get("msg") == "":
            instance_bans = []
        if not isinstance(instance_bans, list) or any(not isinstance(entry, dict) for entry in instance_bans):
            return None
        records.extend(instance_bans)
    return records


def clamp_ttl(ttl: Optional[int], minimum: int = SYSWARDEN_MIN_TTL, maximum: int = SYSWARDEN_MAX_TTL) -> int:
    """Fit a BunkerWeb ban lifetime into the window SysWarden accepts.

    A permanent ban (``ttl is None``) becomes ``maximum`` because SysWarden has no
    permanent provenance-aware ban state. Once that entry expires, the next pass adds it
    again if BunkerWeb still holds the ban.
    """
    if ttl is None or ttl > maximum:
        return maximum
    return max(int(ttl), minimum)


def sanitize_reason(reason: Optional[str], default: str = "BunkerWeb ban") -> str:
    """Make a ban reason acceptable to SysWarden's ``validHAReason``.

    Control and non-printable characters are dropped and the result is truncated on
    *bytes*, since that is what SysWarden counts. An empty result falls back to
    ``default`` rather than failing the whole batch on a 400.
    """
    text = "".join(character for character in (reason or "") if character.isprintable()).strip()
    if not text:
        text = default
    encoded = text.encode("utf-8")[:SYSWARDEN_MAX_REASON_BYTES]
    return encoded.decode("utf-8", "ignore").strip() or default


def valid_source(source: Optional[str]) -> bool:
    """Whether an explicit provenance tag satisfies SysWarden's ``validHASource``."""
    return isinstance(source, str) and 1 <= len(source) <= SYSWARDEN_MAX_SOURCE_BYTES and all(character in _SOURCE_ALLOWED for character in source)


def build_ban_batch(bans: Dict[str, Dict], source: str) -> List[Dict]:
    """Turn ``{ip: {"ttl", "reason"}}`` into the ``bans`` array of a temporary POST.

    Every entry carries exactly the four fields SysWarden requires — it rejects an object
    holding anything else — with the TTL clamped and the reason sanitized.
    """
    if not valid_source(source):
        raise ValueError("invalid SysWarden ban source")
    return [{"ip": ip, "ttl": clamp_ttl(bans[ip].get("ttl")), "reason": sanitize_reason(bans[ip].get("reason", "")), "source": source} for ip in sorted(bans)]


def build_unban_batch(ips: Iterable[str], source: str) -> List[Dict]:
    """Turn IPs into the ``bans`` array of a temporary DELETE (``ip`` and ``source`` only)."""
    if not valid_source(source):
        raise ValueError("invalid SysWarden ban source")
    return [{"ip": ip, "source": source} for ip in sorted(ips)]


def canonical_set(values: Iterable[str]) -> Set[str]:
    """Canonicalize a peer's addresses so both sides of a comparison use one spelling.

    Our own side is canonicalized in ``normalize_ban``. Doing only that would move the
    oscillation rather than fix it: an address the peer spells differently would show up
    as both "to add" and "to remove" on every pass. Anything unparsable is dropped, since
    it can match nothing we would ever send.
    """
    return {canonical for canonical in (canonical_address(value) for value in values) if canonical}


def provenance_ips(bans: Iterable, source: str) -> Set[str]:
    """The addresses a peer reports as banned under our own provenance tag.

    The v4.03+ peer holds ownership, so the plugin needs no local deletion registry.
    """
    return canonical_set(str(ban.get("ip") or "") for ban in bans if isinstance(ban, dict) and ban.get("source") == source)


def supports_ban_sync(capabilities: Iterable[str]) -> bool:
    """A mutation peer must advertise both halves of the v4.03 BunkerWeb contract."""
    available = set(capabilities)
    return {"sync_ttl", "sync_provenance"} <= available


def plan_peer(
    banned: Iterable[str], remote: Iterable[str], ours: Iterable[str], owned: Iterable[str], provenance: bool
) -> Tuple[List[str], List[str], List[str]]:
    """Decide what to send one peer: ``(to_add, to_remove, stale_legacy)``.

    On a v4.03+ peer the ledger filtered on our own ``source`` is the ownership, so the
    diff is against ``ours``. On a peer that predates provenance there is no ledger, so the
    reference is its static blocklist crossed with our durable registry: ``/ha/sync`` writes
    into a blocklist shared with operator entries and real HA peers, and deleting anything
    we did not write would wipe them.

    ``stale_legacy`` only exists for a provenance peer. Expiring bans and the static
    blocklist are disjoint stores upstream, and a legacy push wrote the second one, which is
    reachable only through the legacy dialect. Upstream confirmed on 2026-08-18 that a
    provenance DELETE will never clear it, because that store carries no provenance at all,
    so this separate `DELETE {"ips"}` is the sanctioned cleanup and not a workaround.
    """
    banned, remote, ours, owned = set(banned), set(remote), set(ours), set(owned)
    if provenance:
        to_add, to_remove = banned - ours, ours - banned
        # What we pushed before this peer understood provenance: still in its static store,
        # absent from its ledger, and no longer banned here.
        stale_legacy = sorted(((owned & remote) - ours) - banned)
    else:
        to_add, to_remove = banned - remote, (remote & owned) - banned
        stale_legacy = []
    return sorted(to_add), sorted(to_remove), stale_legacy


def cap_items(ips: Iterable[str], max_items: int) -> Tuple[List[str], int]:
    """Sort and truncate to ``max_items``. Returns ``(kept, dropped_count)``.

    Sorting first makes the truncation deterministic: the same overflowing ban set
    yields the same pushed subset on every pass, instead of a set-iteration lottery
    that would churn the peer's blocklist.
    """
    ordered = sorted(ips)
    if max_items <= 0 or len(ordered) <= max_items:
        return ordered, 0
    return ordered[:max_items], len(ordered) - max_items


def membership_digest(peers: Iterable[str]) -> str:
    """A stable digest of the peer perimeter the registry was built against.

    Upstream requires the continuous-absence clock to restart whenever the cluster view
    changes, membership included. Epoch, fence state and server identity are the other three
    triggers; none of them is observable until `native_sync_fence_v1` ships, so this is the
    only one the plugin can enforce today.
    """
    return sha256("\n".join(sorted(set(peers))).encode()).hexdigest()


def next_registry(
    pushed_ok: Iterable[str],
    owned: Dict[str, Optional[float]],
    seen_remote: Iterable[str],
    still_banned: Iterable[str],
    now: float,
    complete: bool,
) -> Dict[str, Optional[float]]:
    """The ownership registry to persist after a pass.

    ``owned`` maps an address to the moment it was first seen absent from every peer, or to
    ``None`` when the clock is not running. An entry is dropped only once that clock has run
    for ``SYSWARDEN_LEGACY_GRACE`` uninterrupted.

    Releasing on the DELETE receipt instead would be wrong, and permanently so: SysWarden
    peers replicate the static blocklist between themselves, so an entry deleted on one peer
    can be pushed back by another. Once released, the address leaves the registry,
    ``plan_peer`` never lists it again, and it stays in that peer's kernel forever.

    ``complete`` is false when the pass could not see the whole cluster. The clock is then
    **reset**, not paused: an hour of continuous absence must never span a period during
    which the view was partial. Callers must therefore still persist the result of a failed
    pass, or a stale start time would survive and mature into a wrongful release.
    """
    seen_remote, still_banned = set(seen_remote), set(still_banned)
    # Ownership is a receipt: only a successful push claims an address, and a just-pushed
    # address is held by a peer right now, so its clock is not running.
    registry: Dict[str, Optional[float]] = {ip: None for ip in pushed_ok}
    for ip, since in owned.items():
        if ip in registry:
            continue
        if not complete or ip in seen_remote or ip in still_banned:
            registry[ip] = None
            continue
        started = now if since is None else since
        if now - started < SYSWARDEN_LEGACY_GRACE:
            registry[ip] = started
    return dict(sorted(registry.items()))


def resurrected(owned: Dict[str, Optional[float]], seen_remote: Iterable[str]) -> List[str]:
    """Addresses whose release clock was running and that a peer reports again.

    Each one is SysWarden's own ha-sync, or an operator, writing back an entry this plugin
    had deleted. Worth a bounded warning rather than a silent retry: once the local fence
    ships, a reappearance while every peer proves it is fenced stops being attributable to
    HA replication and becomes an operator decision instead of another automatic delete.
    """
    seen_remote = set(seen_remote)
    return sorted(ip for ip, since in owned.items() if since is not None and ip in seen_remote)


def load_registry(raw: Any) -> Tuple[Dict[str, Optional[float]], str]:
    """Read ``pushed.json`` into ``(claims, membership)``, tolerating older layouts.

    A bare list is what the first versions wrote, and a flat mapping is what the grace
    window introduced; both load with no membership recorded, which forces one reset.
    """
    if isinstance(raw, list):
        return {entry: None for entry in raw if isinstance(entry, str)}, ""
    if not isinstance(raw, dict):
        return {}, ""
    claims, membership = raw.get("claims"), raw.get("membership")
    if not isinstance(claims, dict):
        claims, membership = raw, ""
    return (
        {ip: since for ip, since in claims.items() if isinstance(ip, str) and (since is None or isinstance(since, (int, float)))},
        membership if isinstance(membership, str) else "",
    )


def chunked(items: Sequence[str], size: int) -> List[List[str]]:
    """Split into batches of at most ``size`` (``size <= 0`` means one single batch)."""
    if size <= 0:
        return [list(items)] if items else []
    # islice rather than a slice expression: black formats `items[i : i + size]` with the
    # space flake8 then flags as E203.
    return [list(islice(items, index, index + size)) for index in range(0, len(items), size)]


def isolate_refused(items: Sequence[str], send) -> Tuple[List[str], List[str], Optional[Tuple[int, str]]]:
    """Send ``items`` through ``send``, halving on a 400 to find what the peer refuses.

    ``send(chunk)`` returns ``(ok, status_code, error)``. Returns ``(landed, rejected,
    failure)``, where ``failure`` is the ``(code, error)`` of the first refusal that is *not*
    a target rejection — that one stops the walk, since it says nothing about the payload.

    Since v4.03.2 a ``POST /ha/sync`` runs through ``validateHAMutationTargets``, which
    returns on the first protected address and mutates nothing. A 400 therefore condemns the
    whole body while naming none of it, and resending the same bytes can only fail the same
    way. Bisecting costs O(k log n) requests for k refused addresses where sending them one
    at a time would spend O(n) on every pass, forever, since a refused address stays banned
    in BunkerWeb and comes back next minute.
    """
    landed: List[str] = []
    rejected: List[str] = []
    failure: Optional[Tuple[int, str]] = None
    pending: List[List[str]] = [list(items)]
    while pending:
        chunk = pending.pop()
        if not chunk:
            continue
        ok, code, error = send(chunk)
        if ok:
            landed.extend(chunk)
            continue
        if code != 400:
            failure = (code, error)
            break
        if len(chunk) == 1:
            rejected.extend(chunk)
            continue
        middle = len(chunk) // 2
        # Second half first: pending is a stack, so pushing it first keeps the walk in the
        # original order, which keeps the logs and the tests deterministic.
        pending.extend((chunk[middle:], chunk[:middle]))
    return landed, rejected, failure


def check_line(line: bytes) -> Tuple[bool, bytes]:
    """Validate a single IP / CIDR line coming from a peer's blocklist."""
    with suppress(ValueError):
        if b"/" in line:
            ip_network(line.decode())
            return True, line
        ip_address(line.decode())
        return True, line
    return False, b""


def serialize_addresses(entries: Iterable[str]) -> Tuple[bytes, int, int]:
    """Validate and serialize one authoritative peer list in linear time."""
    valid: List[bytes] = []
    invalid = 0
    for entry in sorted(set(entries)):
        ok, data = check_line(entry.encode())
        if ok:
            valid.append(data)
        else:
            invalid += 1
    return (b"\n".join(valid) + (b"\n" if valid else b""), len(valid), invalid)


def extract_whitelist_ips(payload: Any) -> Optional[List[str]]:
    """Read the authoritative whitelist contract, distinguishing empty from malformed."""
    if not isinstance(payload, dict):
        return None
    whitelist = payload.get("whitelist")
    if not isinstance(whitelist, dict) or "ips" not in whitelist:
        return None
    ips = whitelist.get("ips")
    if ips is None:
        return []
    if not isinstance(ips, list) or any(not isinstance(entry, str) for entry in ips):
        return None
    return [entry.strip() for entry in ips if entry.strip()]


def normalize_fingerprint(value: Optional[str]) -> str:
    """Normalize a certificate fingerprint for comparison.

    Accepts what ``openssl x509 -fingerprint -sha256`` prints
    (``SHA256 Fingerprint=AB:CD:...``), a bare hex digest, or a ``sha256:`` prefixed
    one, and returns lowercase hex with no separator.
    """
    text = (value or "").strip()
    if "=" in text:
        text = text.split("=", 1)[1]
    text = text.strip().lower()
    for prefix in ("sha256:", "sha-256:"):
        text = text.removeprefix(prefix)
    return text.replace(":", "").replace(" ", "")


def _section(payload: Dict, key: str) -> Dict:
    """Return ``payload[key]`` when it is a dict, else an empty dict."""
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def parse_telemetry(payload: Dict, status: Optional[Dict] = None) -> Dict:
    """Flatten a ``/ha/telemetry`` (+ optional ``/ha/status``) payload for the web UI.

    Every field is optional: the shape is a contract of the SysWarden version being
    talked to, and a missing section must degrade the card, never raise.
    """
    payload = payload if isinstance(payload, dict) else {}
    status = status if isinstance(status, dict) else {}
    system = _section(payload, "system")
    layer3 = _section(payload, "layer3")
    waf = _section(payload, "waf")
    whitelist = _section(payload, "whitelist")

    return {
        "hostname": status.get("hostname") or system.get("hostname") or "",
        "os": status.get("os") or system.get("os") or "",
        "version": status.get("version") or payload.get("github_release") or "",
        "status": status.get("status") or "",
        "global_blocked": layer3.get("global_blocked", 0),
        "geoip_blocked": layer3.get("geoip_blocked", 0),
        "asn_blocked": layer3.get("asn_blocked", 0),
        "l7_banned": layer3.get("l7_banned", 0),
        "waf_total_banned": waf.get("total_banned", 0),
        "waf_total_detected": waf.get("total_detected", 0),
        "waf_active_signatures": waf.get("active_signatures", 0),
        "whitelist_active_ips": whitelist.get("active_ips", 0),
        "whitelist_ips": [entry for entry in (whitelist.get("ips") or []) if isinstance(entry, str)],
        "top_attackers": waf.get("top_attackers") or [],
        "targeted_ports": waf.get("targeted_ports") or [],
        "services": system.get("services") or [],
        "ports": system.get("ports") or [],
    }


def canonical_proof_token(value: Any) -> bool:
    """A 43-character unpadded base64url token that survives a decode/encode round trip.

    The regex alone is not the contract: upstream decodes the token, checks it is 32 bytes,
    and re-encodes it, so a value like ``"d" * 43`` matches the pattern yet is answered 400.
    Accepting one here would mean sending a condition the peer refuses.
    """
    if not isinstance(value, str) or not fullmatch(_FENCE_TOKEN_PATTERN, value):
        return False
    try:
        raw = urlsafe_b64decode(value + "=")
    except Exception:
        return False
    return len(raw) == 32 and urlsafe_b64encode(raw).rstrip(b"=").decode() == value


def fence_challenge() -> str:
    """A fresh nonce for ``X-SysWarden-HA-Challenge``.

    32 random bytes in unpadded base64url, which is exactly the 43-character token
    `parseHAFenceChallenge` accepts. The peer echoes it inside the signed-off proof, so a
    replayed or cached `/ha/status` body can be told apart from a live one.
    """
    return token_urlsafe(32)


def load_manifest(raw: Any) -> Optional[Dict[str, Any]]:
    """Validate the fence manifest produced by ``syswarden ha-fence manifest create``.

    Returns the normalized manifest, or ``None`` when the envelope is not one this plugin
    may act on. The checks mirror `validateHAFenceManifest`, minus the two digests: upstream
    generates and validates those, and the roadmap is explicit that the partner compares the
    published values instead of reimplementing the canonicalization. Recomputing them here
    would only add a second way to reject a healthy peer.

    ``operator_asserted_complete`` is required rather than informative. A manifest built
    without ``--assert-complete`` describes a perimeter nobody vouched for, and a fence over
    an incomplete perimeter proves nothing.
    """
    if not isinstance(raw, dict):
        return None
    if raw.get("schema_version") != SYSWARDEN_FENCE_SCHEMA_VERSION:
        return None
    if raw.get("membership_scope") != SYSWARDEN_FENCE_MANIFEST_SCOPE or raw.get("operator_asserted_complete") is not True:
        return None
    epoch = raw.get("epoch")
    if not isinstance(epoch, str) or not fullmatch(_FENCE_UUID4_PATTERN, epoch):
        return None
    membership = raw.get("membership_sha256")
    writers_digest = raw.get("legacy_writer_inventory_sha256")
    for digest in (membership, writers_digest):
        if not isinstance(digest, str) or not fullmatch(_SHA256_PATTERN, digest):
            return None
    writer_ids = raw.get("legacy_writer_ids")
    if not isinstance(writer_ids, list) or any(not isinstance(entry, str) for entry in writer_ids):
        return None

    members = raw.get("members")
    if not isinstance(members, list) or not members:
        return None
    normalized: List[Dict[str, Any]] = []
    for member in members:
        if not isinstance(member, dict):
            return None
        # A bare IP literal in its canonical form, like upstream's canonicalHAFenceAddress:
        # canonical_address() is the ban-path normalizer and also accepts CIDRs, which would
        # build a nonsense endpoint URL here and describe a manifest upstream would refuse.
        address = member.get("address")
        try:
            parsed = ip_address(address) if isinstance(address, str) else None
        except ValueError:
            parsed = None
        # Canonical form only, and neither an IPv4-mapped nor a zoned address: upstream
        # rejects both because they let one host appear twice under two spellings, which
        # would put the same peer in the membership digest twice.
        if parsed is None or str(parsed) != address or getattr(parsed, "ipv4_mapped", None) or getattr(parsed, "scope_id", None):
            address = ""
        else:
            address = str(parsed)
        port = member.get("port")
        leaf = member.get("tls_leaf_certificate_sha256")
        if not address or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            return None
        if not isinstance(leaf, str) or not fullmatch(_SHA256_PATTERN, leaf):
            return None
        normalized.append({"address": address, "port": port, "tls_leaf_certificate_sha256": leaf})

    endpoints = {(member["address"], member["port"]) for member in normalized}
    leaves = {member["tls_leaf_certificate_sha256"] for member in normalized}
    # Upstream refuses both a duplicate endpoint and a duplicate leaf identity: two members
    # sharing one certificate means one stolen key impersonates both.
    if len(endpoints) != len(normalized) or len(leaves) != len(normalized):
        return None

    return {
        "epoch": epoch,
        "membership_sha256": membership,
        "legacy_writer_inventory_sha256": writers_digest,
        "legacy_writer_ids": list(writer_ids),
        "members": normalized,
    }


def manifest_peers(manifest: Dict[str, Any]) -> List[Tuple[str, str]]:
    """``members`` as ``(base_url, leaf_sha256)`` pairs.

    Once a manifest is mounted this list is the perimeter, not ``SYSWARDEN_PEERS``: the fence
    is only meaningful over the endpoints the operator enumerated and digested. The pin is
    per peer, on the exact leaf certificate, so a re-issued certificate under the same CA no
    longer passes silently.
    """
    peers = []
    for member in manifest.get("members", []):
        address = member["address"]
        host = f"[{address}]" if ":" in address else address
        peers.append((f"https://{host}:{member['port']}", member["tls_leaf_certificate_sha256"]))
    return peers


def fence_fingerprint(status: Any) -> Optional[Tuple[Any, Any, Any]]:
    """The triple that must not move between two reads: generation, server identity, condition.

    Returned even for a fence this plugin refuses to act on, because the point of comparing
    it is to notice the peer changed underneath a decision already taken.
    """
    proof = status.get("native_sync_fence") if isinstance(status, dict) else None
    if not isinstance(proof, dict):
        return None
    return (proof.get("generation"), proof.get("server_instance_id"), proof.get("condition"))


def fence_proof(status: Any, manifest: Dict[str, Any], challenge: str) -> Tuple[str, Optional[str], str]:
    """Read one peer's fence proof. Returns ``(verdict, condition, reason)``.

    ``verdict`` is one of:

    * ``fenced`` — the six conditions hold together, so the legacy cleanup may run and must
      carry ``condition`` in ``X-SysWarden-HA-Fence-Condition``.
    * ``inactive`` — no fence is engaged. The cleanup may run, and must **not** carry the
      header: `withLegacyMutation` answers 412 to a condition sent while the fence is
      inactive, so sending it defensively would break the very pass it means to protect.
    * ``unusable`` — anything else. Nothing legacy is sent to that peer this pass.

    The six conditions, in the order upstream states them: the body comes from an
    authenticated, uncached ``GET /ha/status`` (the caller's job, this function only sees its
    result), the challenge is echoed, epoch and membership match the manifest, the state is
    exactly ``active_drained``, both mutation counters are zero, and the identity triple is
    stable. A single missing proof is a broken fence, never an ambiguity.
    """
    if not isinstance(status, dict):
        return "unusable", None, "the status body is not an object"

    capabilities = status.get("capabilities")
    if not isinstance(capabilities, list) or SYSWARDEN_FENCE_CAPABILITY not in capabilities:
        return "unusable", None, f"the peer does not advertise {SYSWARDEN_FENCE_CAPABILITY}"

    proof = status.get("native_sync_fence")
    if not isinstance(proof, dict):
        return "unusable", None, "the peer advertises the fence but returned no proof object"

    if proof.get("version") != SYSWARDEN_FENCE_VERSION or proof.get("scope") != SYSWARDEN_FENCE_STATUS_SCOPE:
        return "unusable", None, "the fence proof is not the version and scope this plugin understands"

    if proof.get("challenge") != challenge:
        return "unusable", None, "the fence proof does not echo this pass's challenge"

    # Identity first, because it is state-independent: upstream refuses to publish any state
    # whose generation is zero (validateHAFenceState), and the server instance id comes out of
    # the same token generator as the condition, so both shapes hold in every state.
    generation = proof.get("generation")
    if type(generation) is not int or not 1 <= generation < 2**64:
        return "unusable", None, f"the fence proof carries no usable generation ({generation!r})"
    if not canonical_proof_token(proof.get("server_instance_id")):
        return "unusable", None, "the fence proof carries no usable server identity"

    # The state is read before the campaign identity, and that order matters. A peer that
    # never engaged a fence bootstraps to `inactive` with the three campaign digests empty
    # (prepareForServer in ha_fence.go), so comparing them first would turn every healthy
    # peer into an unusable one the moment a manifest is mounted.
    state = proof.get("state")
    if state == SYSWARDEN_FENCE_STATE_INACTIVE:
        # Upstream refuses to publish an inactive state that still carries campaign data, so
        # a peer reporting one is not a peer with no campaign: it is a peer whose fence file
        # this plugin cannot account for. Exact shapes, not truthiness: the four campaign
        # strings are always serialized as "" and the timestamp as null, so a missing key or
        # a falsey value of the wrong type is just as unaccountable.
        for field in ("epoch", "membership_sha256", "legacy_writer_inventory_sha256", "condition"):
            if proof.get(field, None) != "":
                return "unusable", None, f"the inactive fence reports {field}={proof.get(field, None)!r} instead of an empty string"
        if proof.get("drained_at", False) is not None:
            return "unusable", None, "the inactive fence carries a drain timestamp"
        return "inactive", None, "no fence is engaged on this peer"
    if state != SYSWARDEN_FENCE_STATE_DRAINED:
        return "unusable", None, f"the fence is in state {state!r}"

    if proof.get("epoch") != manifest["epoch"]:
        return "unusable", None, "the peer is fenced under another epoch than the manifest"
    if proof.get("membership_sha256") != manifest["membership_sha256"]:
        return "unusable", None, "the peer reports another membership than the manifest"
    if proof.get("legacy_writer_inventory_sha256") != manifest["legacy_writer_inventory_sha256"]:
        return "unusable", None, "the peer reports another legacy-writer inventory than the manifest"

    for counter in ("active_outbound_writers", "active_inbound_legacy_mutations"):
        value = proof.get(counter)
        # `is not int` on purpose: booleans are ints in Python, and False would otherwise
        # read as a drained counter.
        if type(value) is not int or value != 0:
            return "unusable", None, f"{counter} is {value!r}, the peer has not drained"

    condition = proof.get("condition")
    if not isinstance(condition, str) or not condition.startswith(_FENCE_CONDITION_PREFIX):
        return "unusable", None, "the fence proof carries no usable condition token"
    if not canonical_proof_token(condition.removeprefix(_FENCE_CONDITION_PREFIX)):
        return "unusable", None, "the fence condition is not a canonical token, upstream would refuse it"

    return "fenced", condition, "the peer proves a drained fence"


def cluster_fenced(verdicts: Iterable[str], expected_peers: int) -> bool:
    """True only when every peer of the perimeter proved a drained fence on this pass.

    ``verdicts`` holds one entry per peer that answered. A peer that could not be read leaves
    no verdict at all, which is why the count is compared to the perimeter: a partial view is
    a broken barrier, not a smaller one. This gates the two decisions that may only be taken
    under a complete fence — releasing a claim, and treating a reappearance as an operator
    decision rather than as HA replication.
    """
    verdicts = list(verdicts)
    return expected_peers > 0 and len(verdicts) == expected_peers and all(verdict == "fenced" for verdict in verdicts)


def fence_reason(code: int) -> str:
    """Plain sentence for the status codes the fence answers legacy mutations with.

    Straight from `withLegacyMutation`: without this the logs would only ever say "returned
    status 412", which is the one case an operator must not read as a network hiccup.
    """
    return {
        400: "the fence condition this plugin sent was malformed",
        412: "the fence moved: the condition no longer matches, nothing was written",
        423: "legacy writes are fenced on this peer",
        428: "this peer required a fence condition and none was sent",
        503: "the fence is transitioning, the mutation was not queued",
    }.get(code, "")


def delivery_status(status: int, cached_any: bool, pending: bool) -> Tuple[int, bool]:
    """Resolve a job's exit code so a successful cache write is never stranded.

    The scheduler ships ``/var/cache/bunkerweb`` to the BunkerWeb instances only when a job
    in the same batch exits ``1`` (``JobScheduler.run_pending``). So a job that caches a
    file and then exits ``>=2`` because a *later* item failed leaves that file in the
    scheduler's cache and the database only. On the next run its hash still matches, so
    nothing is re-cached, the job exits ``0``, and the file is never delivered — the
    instances keep enforcing the previous one indefinitely.

    Carrying a pending-delivery marker across runs closes that hole: the exit code becomes
    ``1`` on the first run that is not itself a failure.

    ``status`` is the exit code the job computed, ``cached_any`` whether this run wrote at
    least one cache file, ``pending`` whether a previous run left the marker behind.

    Returns ``(exit_status, keep_marker)``. The marker is cleared as soon as ``1`` is
    returned; if that ship then fails, the scheduler logs it and the next changed run
    delivers.
    """
    pending = pending or cached_any
    if status >= 2:
        return status, pending
    if pending:
        return 1, False
    return status, False
