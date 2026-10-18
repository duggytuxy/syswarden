#!/usr/bin/env python3

from contextlib import suppress
from json import loads
from os import getenv, sep
from os.path import dirname, join
from sys import exit as sys_exit, path as sys_path

# BunkerWeb deps + this job's own directory (for syswarden_helpers / syswarden_client).
sys_path.insert(0, dirname(__file__))
for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from logger import setup_logger  # type: ignore
from common_utils import bytes_hash  # type: ignore
from jobs import Job  # type: ignore

from syswarden_helpers import delivery_status, extract_whitelist_ips, load_registry, serialize_addresses  # type: ignore
from syswarden_client import call, extract_ips, get_peers, get_timeout, make_session  # type: ignore

LOGGER = setup_logger("SYSWARDEN.BLOCKLIST-DOWNLOAD", getenv("LOG_LEVEL", "INFO"))
status = 0
changed = False

# A cache file written while a *later* item of the same run fails would make the job
# exit >=2, and the scheduler ships /var/cache/bunkerweb to the instances only when a job
# exits 1. This marker carries that pending delivery over to the next run so a refreshed
# file can never sit in the scheduler's cache forever (see delivery_status()).
PENDING_MARKER = "pending_delivery"


def any_service_uses(setting: str) -> bool:
    """True when at least one service enables `setting` (multisite) or it is on globally."""
    if getenv("MULTISITE", "no") == "yes":
        return any(getenv(f"{server}_{setting}", getenv(setting, "no")) == "yes" for server in getenv("SERVER_NAME", "").split())
    return getenv(setting, "no") == "yes"


try:
    if getenv("USE_SYSWARDEN", "no") != "yes":
        LOGGER.info("SysWarden is not activated, skipping blocklist download...")
        sys_exit(0)

    use_blocklist = any_service_uses("USE_SYSWARDEN_BLOCKLIST")
    use_whitelist = any_service_uses("USE_SYSWARDEN_WHITELIST")
    if not use_blocklist and not use_whitelist:
        LOGGER.info("No service uses the SysWarden blocklist or whitelist, skipping download...")
        sys_exit(0)

    interval = getenv("SYSWARDEN_BLOCKLIST_INTERVAL", "hour")
    if interval not in ("hour", "day"):
        interval = "hour"

    JOB = Job(LOGGER, __file__)

    if (not use_blocklist or JOB.is_cached_file("blocklist.list", interval)) and (not use_whitelist or JOB.is_cached_file("whitelist.list", interval)):
        LOGGER.info("SysWarden lists are already in cache, skipping download...")
        sys_exit(0)

    peers = get_peers(LOGGER)
    timeout = get_timeout()
    session = make_session(LOGGER)

    blocklist = set()
    whitelist = set()
    complete = True

    for peer in peers:
        if use_blocklist:
            got, body = call(session, peer, "GET", "/ha/sync", timeout=timeout)
            entries = extract_ips(body) if got else None
            if entries is None:
                LOGGER.error(f"Can't read the blocklist of {peer}: {body}")
                complete = False
            else:
                blocklist.update(entries)

        if use_whitelist:
            # SysWarden exposes its whitelist only inside the telemetry payload; there is
            # no dedicated route for it yet.
            got, body = call(session, peer, "GET", "/ha/telemetry", timeout=timeout)
            entries = extract_whitelist_ips(body) if got else None
            if entries is None:
                LOGGER.error(f"Can't read the whitelist of {peer}: {body}")
                complete = False
            else:
                whitelist.update(entries)

    if not complete:
        LOGGER.error("The SysWarden list snapshot is incomplete, keeping every cached list unchanged")
        sys_exit(2)

    if use_blocklist and getenv("SYSWARDEN_BLOCKLIST_EXCLUDE_OWN", "yes") == "yes":
        # BunkerWeb already denies these at Layer 7; denying them again from a list it fed
        # itself adds nothing, and it makes the downloaded list look larger than it is.
        cached_owned = JOB.get_cache("pushed.json")
        if cached_owned:
            with suppress(BaseException):
                claims, _ = load_registry(loads(cached_owned.decode("utf-8", "replace") if isinstance(cached_owned, bytes) else cached_owned))
                before = len(blocklist)
                blocklist -= set(claims)
                if before != len(blocklist):
                    LOGGER.info(f"Excluded {before - len(blocklist)} entry(ies) this plugin pushed itself")

    prepared = []
    for name, entries, wanted in (("blocklist.list", blocklist, use_blocklist), ("whitelist.list", whitelist, use_whitelist)):
        if not wanted:
            continue
        content, kept, invalid = serialize_addresses(entries)
        if invalid:
            LOGGER.error(f"{name} contains {invalid} invalid entry(ies), keeping every cached list unchanged")
            status = 2
        prepared.append((name, content, kept))

    if status != 0:
        sys_exit(status)

    for name, content, kept in prepared:
        new_hash = bytes_hash(content)
        if new_hash == JOB.cache_hash(name):
            LOGGER.info(f"New {name} file is identical to cache file, reload is not needed")
            continue

        cached, err = JOB.cache_file(name, content, checksum=new_hash)
        if not cached:
            LOGGER.error(f"Error while caching {name}: {err}")
            status = 2
            continue

        LOGGER.info(f"Downloaded {kept} entry(ies) into {name}")
        changed = True

    # 1 asks the scheduler to reload nginx, which is what makes the new lists live.
    if status == 0 and changed:
        status = 1
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running syswarden-blocklist-download.py")

# Resolve the pending delivery outside the try/except above so an early sys_exit() — the
# "still fresh, nothing to do" path — cannot skip it either.
try:
    pending = JOB.get_cache(PENDING_MARKER) is not None
    status, keep_marker = delivery_status(status, changed, pending)
    if keep_marker:
        LOGGER.warning("A cached file is not delivered to the instances yet, retrying on the next run")
        if not pending:
            JOB.cache_file(PENDING_MARKER, b"1")
    elif pending:
        JOB.del_cache(PENDING_MARKER)
except NameError:
    # JOB was never created (the job failed before that): nothing was cached either.
    pass
except BaseException:
    LOGGER.exception("Exception while resolving the pending cache delivery in syswarden-blocklist-download.py")

sys_exit(status)
