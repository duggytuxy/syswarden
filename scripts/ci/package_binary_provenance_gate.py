#!/usr/bin/env python3
"""Verify that staged or packaged binaries attest the exact release source."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class ProvenanceError(ValueError):
    """Raised when packaged binary provenance is incomplete or inconsistent."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class FileDigest:
    sha256: str
    size: int


@dataclass(frozen=True)
class RetainedFile:
    path: Path
    descriptor: int
    identity: FileIdentity
    digest: FileDigest


BINARY_PATHS = (
    "opt/syswarden/bin/syswarden-cli",
    "opt/syswarden/bin/syswarden-core",
    "opt/syswarden/bin/syswarden-tui",
)
SIGNATURE_PATH = "opt/syswarden/signatures.json"
DIGEST_CONTRACT_PATHS = (*BINARY_PATHS, SIGNATURE_PATH)
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VCS_TIME_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def file_identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def open_regular(
    path: Path,
    parent_descriptor: int | None = None,
    leaf_name: str | None = None,
) -> tuple[int, FileIdentity]:
    if leaf_name is not None and (Path(leaf_name).name != leaf_name or "/" in leaf_name):
        raise ProvenanceError(f"invalid fixed payload leaf name: {leaf_name}")
    try:
        path_metadata = path.lstat()
        descriptor = os.open(
            leaf_name if leaf_name is not None else path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise ProvenanceError(f"cannot open required payload {path}: {exc}") from exc
    opened_metadata = os.fstat(descriptor)
    if not stat.S_ISREG(opened_metadata.st_mode):
        os.close(descriptor)
        raise ProvenanceError(f"required payload is not a regular file: {path}")
    if (path_metadata.st_dev, path_metadata.st_ino) != (
        opened_metadata.st_dev,
        opened_metadata.st_ino,
    ):
        os.close(descriptor)
        raise ProvenanceError(f"required payload identity changed while opening: {path}")
    if opened_metadata.st_size <= 0:
        os.close(descriptor)
        raise ProvenanceError(f"required payload is empty: {path}")
    return descriptor, file_identity(opened_metadata)


def digest_descriptor(descriptor: int) -> FileDigest:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        digest.update(chunk)
    return FileDigest(sha256=digest.hexdigest(), size=size)


def read_stable_digest(
    path: Path,
    parent_descriptor: int | None = None,
    leaf_name: str | None = None,
    retained_files: list[RetainedFile] | None = None,
) -> FileDigest:
    descriptor, identity_before = open_regular(path, parent_descriptor, leaf_name)
    try:
        digest = digest_descriptor(descriptor)
        identity_after = file_identity(os.fstat(descriptor))
        try:
            path_after = file_identity(path.lstat())
        except OSError as exc:
            raise ProvenanceError(
                f"required payload path changed while reading {path}: {exc}"
            ) from exc
        if (
            identity_before != identity_after
            or identity_before != path_after
            or digest.size != identity_before.size
        ):
            raise ProvenanceError(f"required payload changed while reading: {path}")
        if retained_files is not None:
            retained_files.append(
                RetainedFile(path, descriptor, identity_before, digest)
            )
            descriptor = -1
        return digest
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def revalidate_retained_file(retained: RetainedFile) -> None:
    try:
        descriptor_identity = file_identity(os.fstat(retained.descriptor))
        path_identity = file_identity(retained.path.lstat())
        digest = digest_descriptor(retained.descriptor)
    except OSError as exc:
        raise ProvenanceError(
            f"cannot revalidate required payload {retained.path}: {exc}"
        ) from exc
    if (
        descriptor_identity != retained.identity
        or path_identity != retained.identity
        or digest != retained.digest
    ):
        raise ProvenanceError(
            f"required payload changed before validation completed: {retained.path}"
        )


def digest_contract(root: Path, retained_files: list[RetainedFile]) -> str:
    digests: dict[str, FileDigest] = {}
    for retained in retained_files:
        try:
            relative = retained.path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ProvenanceError(
                f"retained payload is outside its root: {retained.path}"
            ) from exc
        if relative in digests:
            raise ProvenanceError(f"duplicate retained payload: {relative}")
        digests[relative] = retained.digest
    if set(digests) != set(DIGEST_CONTRACT_PATHS):
        raise ProvenanceError("retained payload digest inventory is incomplete")
    fields = ["v1"]
    for relative in DIGEST_CONTRACT_PATHS:
        digest = digests[relative]
        fields.append(f"{relative}={digest.sha256}:{digest.size}")
    return ";".join(fields)


def require_expected_digest_contract(actual: str, expected: str) -> None:
    fields = expected.split(";")
    if len(fields) != len(DIGEST_CONTRACT_PATHS) + 1 or fields[0] != "v1":
        raise ProvenanceError("expected payload digest contract is malformed")
    for relative, field in zip(DIGEST_CONTRACT_PATHS, fields[1:], strict=True):
        prefix = f"{relative}="
        if not field.startswith(prefix):
            raise ProvenanceError("expected payload digest contract is noncanonical")
        digest_and_size = field[len(prefix) :]
        digest, separator, size_text = digest_and_size.partition(":")
        if (
            separator != ":"
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or re.fullmatch(r"[1-9][0-9]*", size_text) is None
        ):
            raise ProvenanceError("expected payload digest contract is malformed")
    if actual != expected:
        raise ProvenanceError(
            "payload bytes differ from the digest contract validated before packaging"
        )


def run_tool(command: list[str], descriptor: int, label: str) -> str:
    descriptor_path = f"/proc/self/fd/{descriptor}"
    try:
        completed = subprocess.run(
            [*command, descriptor_path],
            check=False,
            capture_output=True,
            text=True,
            pass_fds=(descriptor,),
        )
    except OSError as exc:
        raise ProvenanceError(f"cannot execute {label}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        raise ProvenanceError(f"{label} failed: {detail}")
    return completed.stdout


def parse_build_settings(build_info: str) -> list[str]:
    settings: list[str] = []
    for line in build_info.splitlines():
        match = re.fullmatch(r"\s*build\s+(.+?)\s*", line)
        if match is not None:
            settings.append(match.group(1))
    return settings


def require_once(settings: list[str], expected: str, path: Path) -> None:
    if settings.count(expected) != 1:
        raise ProvenanceError(
            f"binary build information must contain exactly one {expected}: {path}"
        )


def validate_build_info(
    build_info: str,
    path: Path,
    revision: str,
    vcs_time: str,
) -> None:
    first_line = build_info.splitlines()[0] if build_info.splitlines() else ""
    if re.search(r":\s+go1\.26\.6\s*$", first_line) is None:
        raise ProvenanceError(f"binary was not built by exactly Go 1.26.6: {path}")
    settings = parse_build_settings(build_info)
    for expected in (
        "GOOS=linux",
        "GOARCH=amd64",
        "GOAMD64=v1",
        "CGO_ENABLED=0",
        "-trimpath=true",
        "vcs=git",
        f"vcs.revision={revision}",
        f"vcs.time={vcs_time}",
        "vcs.modified=false",
    ):
        require_once(settings, expected, path)
    vcs_settings = [
        setting
        for setting in settings
        if setting.startswith("vcs=") or setting.startswith("vcs.")
    ]
    expected_vcs_settings = [
        "vcs=git",
        f"vcs.revision={revision}",
        f"vcs.time={vcs_time}",
        "vcs.modified=false",
    ]
    if sorted(vcs_settings) != sorted(expected_vcs_settings):
        raise ProvenanceError(f"binary contains an unexpected VCS field: {path}")


def validate_binary(
    path: Path,
    mode: str,
    revision: str,
    vcs_time: str,
    reference: Path | None,
    parent_descriptor: int | None = None,
    reference_parent_descriptor: int | None = None,
    leaf_name: str | None = None,
    retained_files: list[RetainedFile] | None = None,
    reference_retained_files: list[RetainedFile] | None = None,
) -> None:
    descriptor, identity_before = open_regular(path, parent_descriptor, leaf_name)
    try:
        digest = digest_descriptor(descriptor)
        header = run_tool(["readelf", "--file-header"], descriptor, "readelf header")
        expected_type = "DYN" if mode == "pie" else "EXEC"
        if re.search(rf"^\s*Type:\s+{expected_type}\b", header, re.MULTILINE) is None:
            raise ProvenanceError(
                f"binary ELF type is not {expected_type} for {mode} mode: {path}"
            )
        if re.search(
            r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$",
            header,
            re.MULTILINE,
        ) is None:
            raise ProvenanceError(f"binary is not an AMD64 ELF artifact: {path}")
        if mode == "static":
            program_headers = run_tool(
                ["readelf", "--program-headers"], descriptor, "readelf program headers"
            )
            if re.search(r"\sINTERP\s", program_headers) is not None:
                raise ProvenanceError(f"static binary contains a PT_INTERP loader: {path}")
            file_output = run_tool(
                ["file", "--brief", "--dereference"],
                descriptor,
                "file inspection",
            )
            if "statically linked" not in file_output:
                raise ProvenanceError(f"static binary is dynamically linked: {path}")
        build_info = run_tool(["go", "version", "-m"], descriptor, "Go build-info inspection")
        validate_build_info(build_info, path, revision, vcs_time)
        identity_after = file_identity(os.fstat(descriptor))
        try:
            path_after = file_identity(path.lstat())
        except OSError as exc:
            raise ProvenanceError(
                f"binary path changed during provenance validation {path}: {exc}"
            ) from exc
        if (
            identity_before != identity_after
            or identity_before != path_after
            or digest.size != identity_before.size
        ):
            raise ProvenanceError(
                f"binary changed during provenance validation: {path}"
            )
        if reference is not None:
            reference_digest = read_stable_digest(
                reference,
                reference_parent_descriptor,
                leaf_name,
                reference_retained_files,
            )
            if digest != reference_digest:
                raise ProvenanceError(
                    f"packaged binary differs from its validated staging source: {path}"
                )
        if retained_files is not None:
            retained_files.append(
                RetainedFile(path, descriptor, identity_before, digest)
            )
            descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def require_directory(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise ProvenanceError(f"{label} must be an absolute path: {path}")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ProvenanceError(f"cannot inspect {label} {current}: {exc}") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ProvenanceError(f"{label} contains a non-directory ancestor: {current}")


def open_pinned_directory(
    path: Path,
    label: str,
    parent_descriptor: int | None = None,
    leaf_name: str | None = None,
) -> tuple[int, FileIdentity]:
    if leaf_name is not None and (Path(leaf_name).name != leaf_name or "/" in leaf_name):
        raise ProvenanceError(f"invalid fixed directory leaf name: {leaf_name}")
    try:
        path_metadata = path.lstat()
        descriptor = os.open(
            leaf_name if leaf_name is not None else path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise ProvenanceError(f"cannot pin {label} {path}: {exc}") from exc
    opened_metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(opened_metadata.st_mode):
        os.close(descriptor)
        raise ProvenanceError(f"{label} is not a directory: {path}")
    identity = file_identity(opened_metadata)
    if identity != file_identity(path_metadata):
        os.close(descriptor)
        raise ProvenanceError(f"{label} identity changed while opening: {path}")
    return descriptor, identity


def revalidate_pinned_directory(
    path: Path,
    descriptor: int,
    expected: FileIdentity,
    label: str,
) -> None:
    try:
        descriptor_identity = file_identity(os.fstat(descriptor))
        path_identity = file_identity(path.lstat())
    except OSError as exc:
        raise ProvenanceError(f"cannot revalidate {label} {path}: {exc}") from exc
    if descriptor_identity != expected or path_identity != expected:
        raise ProvenanceError(f"{label} identity changed during validation: {path}")


class PinnedPayloadRoot:
    """Hold no-follow descriptors for every fixed payload directory."""

    def __init__(self, root: Path, label: str) -> None:
        self.root = root
        self.label = label
        self.directories: list[tuple[Path, int, FileIdentity, str]] = []
        self.files: list[RetainedFile] = []
        self.syswarden_descriptor = -1
        self.binary_descriptor = -1

    def __enter__(self) -> PinnedPayloadRoot:
        require_directory(self.root, f"{self.label} root")
        try:
            root_descriptor, root_identity = open_pinned_directory(
                self.root, f"{self.label} root"
            )
            self.directories.append(
                (self.root, root_descriptor, root_identity, f"{self.label} root")
            )
            parent_descriptor = root_descriptor
            current = self.root
            for component in ("opt", "syswarden", "bin"):
                current /= component
                descriptor, identity = open_pinned_directory(
                    current,
                    f"{self.label} parent",
                    parent_descriptor,
                    component,
                )
                self.directories.append(
                    (current, descriptor, identity, f"{self.label} parent")
                )
                parent_descriptor = descriptor
                if component == "syswarden":
                    self.syswarden_descriptor = descriptor
                elif component == "bin":
                    self.binary_descriptor = descriptor
        except Exception:
            self.close()
            raise
        return self

    def revalidate(self) -> None:
        for retained in self.files:
            revalidate_retained_file(retained)
        for path, descriptor, identity, label in self.directories:
            revalidate_pinned_directory(path, descriptor, identity, label)

    def close(self) -> None:
        while self.files:
            os.close(self.files.pop().descriptor)
        while self.directories:
            _, descriptor, _, _ = self.directories.pop()
            os.close(descriptor)
        self.syswarden_descriptor = -1
        self.binary_descriptor = -1

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def read_pinned_source_digest(path: Path) -> FileDigest:
    require_directory(path.parent, "signatures source parent")
    descriptor, identity = open_pinned_directory(
        path.parent, "signatures source parent"
    )
    try:
        digest = read_stable_digest(path, descriptor, path.name)
        revalidate_pinned_directory(
            path.parent,
            descriptor,
            identity,
            "signatures source parent",
        )
        return digest
    finally:
        os.close(descriptor)


def validate_pinned_roots(
    payload: PinnedPayloadRoot,
    mode: str,
    revision: str,
    vcs_time: str,
    signatures_source: Path,
    reference: PinnedPayloadRoot | None,
    expected_digest_contract: str | None,
) -> str:
    for relative in BINARY_PATHS:
        leaf_name = Path(relative).name
        reference_path = reference.root / relative if reference is not None else None
        validate_binary(
            payload.root / relative,
            mode,
            revision,
            vcs_time,
            reference_path,
            payload.binary_descriptor,
            reference.binary_descriptor if reference is not None else None,
            leaf_name,
            payload.files,
            reference.files if reference is not None else None,
        )
    signatures_digest = read_stable_digest(
        payload.root / SIGNATURE_PATH,
        payload.syswarden_descriptor,
        Path(SIGNATURE_PATH).name,
        payload.files,
    )
    source_digest = read_pinned_source_digest(signatures_source)
    if signatures_digest != source_digest:
        raise ProvenanceError(
            "packaged signatures.json differs from the exact source commit"
        )
    if reference is not None:
        reference_digest = read_stable_digest(
            reference.root / SIGNATURE_PATH,
            reference.syswarden_descriptor,
            Path(SIGNATURE_PATH).name,
            reference.files,
        )
        if signatures_digest != reference_digest:
            raise ProvenanceError(
                "packaged signatures.json differs from its validated staging source"
            )
    payload.revalidate()
    if reference is not None:
        reference.revalidate()
    contract = digest_contract(payload.root, payload.files)
    if expected_digest_contract is not None:
        require_expected_digest_contract(contract, expected_digest_contract)
    return contract


def validate_root(
    root: Path,
    mode: str,
    revision: str,
    vcs_time: str,
    signatures_source: Path,
    reference_root: Path | None = None,
    expected_digest_contract: str | None = None,
) -> str:
    with PinnedPayloadRoot(root, "payload") as payload:
        if reference_root is None:
            return validate_pinned_roots(
                payload,
                mode,
                revision,
                vcs_time,
                signatures_source,
                None,
                expected_digest_contract,
            )
        with PinnedPayloadRoot(reference_root, "reference") as reference:
            return validate_pinned_roots(
                payload,
                mode,
                revision,
                vcs_time,
                signatures_source,
                reference,
                expected_digest_contract,
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("pie", "static"), required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--vcs-time", required=True)
    parser.add_argument("--signatures-source", type=Path, required=True)
    parser.add_argument("--reference-root", type=Path)
    parser.add_argument("--expected-digest-contract")
    parser.add_argument("--print-digest-contract", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if REVISION_PATTERN.fullmatch(args.revision) is None:
        print("ERROR: revision must be one lowercase 40-character Git object ID", file=sys.stderr)
        return 1
    if VCS_TIME_PATTERN.fullmatch(args.vcs_time) is None:
        print("ERROR: VCS time must use canonical UTC RFC 3339 seconds", file=sys.stderr)
        return 1
    try:
        contract = validate_root(
            args.root,
            args.mode,
            args.revision,
            args.vcs_time,
            args.signatures_source,
            args.reference_root,
            args.expected_digest_contract,
        )
    except ProvenanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.print_digest_contract:
        print(contract)
    else:
        print(f"Validated exact {args.mode} binary provenance: {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
