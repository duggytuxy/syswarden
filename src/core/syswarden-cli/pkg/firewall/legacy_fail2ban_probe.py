"""Evaluate immutable Fail2ban configuration with the installed parser's bytes.

This helper never talks to the Fail2ban server or runs an action. It is invoked
with isolated Python, bounded input/output and a deadline by the Go adapter.
The parser is trusted installed code, not an untrusted-code sandbox.
"""

import base64
import configparser
import fnmatch
import glob
import importlib.abc
import importlib.util
import io
import json
import logging
import os
import posixpath
import resource
import re
import sys

ROOT = "/etc/fail2ban"
MAX_INPUT = 64 << 20
MAX_STREAM = 8 << 20
MAX_COMMANDS = 65536


class ProbeRefusal(Exception):
    pass


def refuse():
    raise ProbeRefusal("configuration evaluation refused")


def canonical(path):
    return (isinstance(path, str) and path.startswith(ROOT + "/")
            and posixpath.normpath(path) == path
            and not any(c in path for c in "\x00\r\n"))


def unique_object(items):
    value = {}
    for key, item in items:
        if key in value:
            refuse()
        value[key] = item
    return value


def action_properties(commands):
    """Resolve public CommandAction data without starting or calling an action."""
    from fail2ban.server.action import CommandAction
    actions = {}
    jails = {command[1] for command in commands if command[0] == "add"}
    if len(jails) > 128:
        refuse()
    for command in commands:
        if len(command) < 3 or command[0] not in ("set", "multi-set"):
            continue
        if command[2] == "addaction":
            if len(command) != 4 or command[0] != "set":
                refuse()
            key = (command[1], command[3])
            if key[0] not in jails or key in actions or len(actions) >= 4096:
                refuse()
            actions[key] = CommandAction(None, command[3])
        elif command[2] == "action":
            key = (command[1], command[3]) if len(command) >= 4 else None
            if key not in actions:
                refuse()
            if command[0] == "multi-set" and len(command) == 5:
                properties = command[4]
            elif command[0] == "set" and len(command) == 6:
                properties = [command[4:]]
            else:
                refuse()
            if not isinstance(properties, list) or len(properties) > 128:
                refuse()
            for entry in properties:
                if (not isinstance(entry, (tuple, list)) or len(entry) != 2
                        or not isinstance(entry[0], str)
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:?=-]{0,127}", entry[0])
                        or type(entry[1]) not in (str, int, bool)
                        or callable(getattr(actions[key], entry[0], None))):
                    refuse()
                # Use the installed class's public value conversion, including
                # time units. No callable property or action method is allowed.
                setattr(actions[key], entry[0], entry[1])
    grouped = {jail: [] for jail in sorted(jails)}
    for (jail, name), action in sorted(actions.items()):
        properties = []
        for key in sorted(dir(action)):
            if key.startswith("_") or callable(getattr(action, key)):
                continue
            value = getattr(action, key)
            if key in ("ESCAPE_CRE", "ESCAPE_VN_CRE"):
                if value is not getattr(CommandAction, key):
                    refuse()
                primitive = ["r", key]
            elif type(value) is str:
                primitive = ["s", value]
            elif type(value) is bool:
                primitive = ["b", value]
            elif type(value) is int and -(1 << 63) <= value < (1 << 63):
                primitive = ["i", value]
            elif value is None:
                primitive = ["n", None]
            else:
                refuse()
            properties.append([key, primitive])
        if len(properties) > 128:
            refuse()
        grouped[jail].append([name, properties])
    result = list(grouped.items())
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_STREAM:
        refuse()
    return encoded


class SnapshotModules(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, modules):
        self.modules = modules

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "fail2ban" and not fullname.startswith("fail2ban."):
            return None
        source = self.modules.get(fullname)
        if source is None:
            refuse()
        return importlib.util.spec_from_loader(
            fullname, self, is_package=source["package"])

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        source = self.modules[module.__name__]
        module.__file__ = source["path"]
        if source["package"]:
            module.__path__ = [posixpath.dirname(source["path"])]
        code = compile(source["content"], source["path"], "exec",
                       dont_inherit=True)
        exec(code, module.__dict__)


def evaluate(request):
    if set(request) != {"files", "directories", "modules"}:
        refuse()
    if not isinstance(request["files"], dict) or len(request["files"]) > 2048:
        refuse()
    files = {}
    for path, encoded in request["files"].items():
        if not canonical(path):
            refuse()
        files[path] = base64.b64decode(encoded, validate=True)
    if sum(map(len, files.values())) > 32 << 20:
        refuse()
    directories = request["directories"]
    if (not isinstance(directories, list) or len(directories) > 2048
            or len(set(directories)) != len(directories)
            or ROOT not in directories):
        refuse()
    directories = set(directories)
    if any(path != ROOT and not canonical(path) for path in directories):
        refuse()
    if (files.keys() & directories
            or any(posixpath.dirname(path) not in directories for path in files)
            or any(path != ROOT and posixpath.dirname(path) not in directories
                   for path in directories)):
        refuse()
    modules = request["modules"]
    if not isinstance(modules, dict) or not 1 <= len(modules) <= 512:
        refuse()
    module_bytes = 0
    for name, source in modules.items():
        if (name != "fail2ban" and not name.startswith("fail2ban.")
                or any(not part.isidentifier() for part in name.split("."))
                or set(source) != {"path", "package", "content"}
                or type(source["package"]) is not bool
                or not isinstance(source["path"], str)):
            refuse()
        source["content"] = base64.b64decode(source["content"], validate=True)
        module_bytes += len(source["content"])
    if module_bytes > 8 << 20:
        refuse()
    sys.meta_path.insert(0, SnapshotModules(modules))
    from fail2ban.client.configurator import Configurator
    from fail2ban.client.configreader import ConfigReaderUnshared
    from fail2ban.client.configparserinc import SafeConfigParserWithIncludes
    from fail2ban.version import version
    if version != "1.1.0":
        refuse()

    # Keep all parser interpolation and merge semantics upstream. Only the
    # configuration filesystem view changes; absolute includes retain their
    # real logical names, without reading the active files.
    denied = []
    original_exists = os.path.exists
    original_isfile = os.path.isfile
    original_glob = glob.glob
    original_reader = ConfigReaderUnshared.read
    original_includes = SafeConfigParserWithIncludes.read

    def checked(path):
        path = os.fspath(path)
        if not isinstance(path, str):
            denied.append(True)
            refuse()
        path = posixpath.normpath(path)
        if not canonical(path):
            denied.append(True)
            refuse()
        return path

    def snapshot_open(path, mode="r", buffering=-1, encoding=None,
                      errors=None, newline=None, **kwargs):
        path = checked(path)
        if mode != "r" or encoding not in (None, "utf-8") or kwargs:
            denied.append(True)
            refuse()
        if path not in files:
            raise FileNotFoundError(path)
        stream = io.TextIOWrapper(io.BytesIO(files[path]), encoding="utf-8",
                                  errors=errors, newline=newline)
        return stream

    def exists(path):
        if isinstance(path, str):
            normalized = posixpath.normpath(path)
            if normalized == ROOT or normalized.startswith(ROOT + "/"):
                return normalized in files or normalized in directories
        return original_exists(path)

    def isfile(path):
        if isinstance(path, str):
            normalized = posixpath.normpath(path)
            if normalized == ROOT or normalized.startswith(ROOT + "/"):
                return normalized in files
        return original_isfile(path)

    def snapshot_glob(pattern, *args, **kwargs):
        if isinstance(pattern, str) and pattern.startswith(ROOT + "/"):
            if args or kwargs:
                denied.append(True)
                refuse()
            parent, name = posixpath.split(pattern)
            parent = checked(parent)
            if any(c in parent for c in "*?["):
                denied.append(True)
                refuse()
            matches = []
            for path in sorted(files.keys() | directories):
                if posixpath.dirname(path) != parent:
                    continue
                base = posixpath.basename(path)
                if base.startswith(".") and not name.startswith("."):
                    continue
                if fnmatch.fnmatchcase(base, name):
                    matches.append(path)
            return matches
        # Log paths are only expanded and stat'ed, never read or written.
        return original_glob(pattern, *args, **kwargs)

    def reader(self, name):
        path = checked(posixpath.join(self.getBaseDir(), name))
        if any(c in path for c in "*?["):
            denied.append(True)
            refuse()
        return original_reader(self, name)

    def includes(self, names, *args, **kwargs):
        names = names if isinstance(names, list) else [names]
        for name in names:
            checked(name)
        return original_includes(self, names, *args, **kwargs)

    configparser.open = snapshot_open
    os.path.exists = exists
    os.path.isfile = isfile
    glob.glob = snapshot_glob
    ConfigReaderUnshared.read = reader
    SafeConfigParserWithIncludes.read = includes
    logging.getLogger("fail2ban").setLevel(logging.CRITICAL)

    # A parser regression must not execute actions, use the network, import
    # configuration plugins or fall back to reading external configuration.
    def audit(event, args):
        if (event == "open" or event.startswith(("subprocess.", "socket."))
                or event in {"os.system", "os.exec", "os.posix_spawn",
                             "os.fork", "os.forkpty", "os.remove", "os.rename",
                             "os.mkdir", "os.rmdir", "os.chmod", "os.chown",
                             "os.truncate", "os.link", "os.symlink"}):
            denied.append(True)
            refuse()
    sys.addaudithook(audit)

    views = {}
    for force in (False, True):
        parser = Configurator(force_enable=force)
        parser.setBaseDir(ROOT)
        parser.readAll()
        early = parser.getEarlyOptions()
        for key in ("socket", "pidfile"):
            value = early.get(key)
            if (not isinstance(value, str) or not value.startswith("/")
                    or posixpath.normpath(value) != value
                    or any(c in value for c in "\x00\r\n")):
                refuse()
            if key in views and views[key] != value:
                refuse()
            views[key] = value
        if not parser.getOptions(ignoreWrong=False):
            refuse()
        parser.convertToProtocol(allow_no_files=force)
        commands = parser.getConfigStream()
        if not commands or len(commands) > MAX_COMMANDS:
            refuse()
        for command in commands:
            if (not isinstance(command, list) or not command
                    or command[0] not in ("add", "set", "multi-set", "start")):
                refuse()
            # Python actions have arbitrary dependencies. Never infer that
            # removing an apparently unused file leaves such code unaffected.
            if (len(command) >= 5 and command[:1] == ["set"]
                    and command[2] == "addaction"):
                refuse()
        stream = "".join(repr(command) + "\n" for command in commands)
        if len(stream.encode("utf-8")) > MAX_STREAM or denied:
            refuse()
        views["all" if force else "enabled"] = stream
        views["actionsAll" if force else "actionsEnabled"] = action_properties(commands)
    views["version"] = version
    return views


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (768 << 20, 768 << 20))
    with os.fdopen(4, "rb") as snapshot:
        data = snapshot.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        refuse()
    request = json.loads(data, object_pairs_hook=unique_object)
    result = evaluate(request)
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Configuration streams and parser exceptions can contain secrets.
        # Keep errors constant; never echo input, expanded actions or paths.
        sys.stderr.write("Fail2ban snapshot evaluation refused.\n")
        sys.exit(1)
