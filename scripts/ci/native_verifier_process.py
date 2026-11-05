#!/usr/bin/env python3
"""Bounded Linux subprocess capture for trusted native verification tools.

The command and environment are selected by trusted caller code. No shell,
package script or command from evidence JSON is accepted here.
"""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass

MAX_CHANNEL_BYTES = 1024 * 1024
MAX_SECONDS = 60
READ_BYTES = 16 * 1024


class VerifierProcessError(RuntimeError):
    """Native verification could not finish within its execution bounds."""


@dataclass(frozen=True)
class VerifierProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def capture(
    command: list[str], environment: dict[str, str], *,
    timeout: float = MAX_SECONDS, channel_limit: int = MAX_CHANNEL_BYTES,
) -> VerifierProcessResult:
    """Capture two independently bounded channels, retaining their exact bytes.

    A private process group is terminated before its leader is reaped, including
    on success, so inherited descendants cannot retain the verifier's pipes.
    This does not manage external container daemons or processes that deliberately
    escape their group; such adapters must own and verify their cleanup separately.
    Kernel execution stalls are outside a userspace hard-deadline guarantee.
    """
    if (not isinstance(command, list) or not command or
            any(not isinstance(value, str) or '\x00' in value for value in command) or
            not command[0] or not isinstance(environment, dict) or
            any(not isinstance(key, str) or not key or not isinstance(value, str) or
                "\x00" in key or "\x00" in value for key, value in environment.items()) or
            type(channel_limit) is not int or not 0 < channel_limit <= MAX_CHANNEL_BYTES or
            type(timeout) not in (int, float) or not 0 < timeout <= MAX_SECONDS):
        raise VerifierProcessError('native verifier selection or bounds are invalid')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise VerifierProcessError('native verifier requires default child-reaping behavior')
    deadline = time.monotonic() + timeout
    process = None
    leader_owned = False
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    failure = None
    result = None
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, start_new_session=True,
        )
        leader_owned = True
        with selectors.DefaultSelector() as selector:
            for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise VerifierProcessError('native verifier exceeded its deadline')
                for event, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(event.fd, READ_BYTES)
                    if not chunk:
                        selector.unregister(event.fileobj)
                        continue
                    channel = output[event.data]
                    if len(channel) + len(chunk) > channel_limit:
                        raise VerifierProcessError('native verifier output exceeded its channel bound')
                    channel.extend(chunk)
            # WNOWAIT retains the original PID until group cleanup. Polling with
            # Popen.poll() here could reap it before a later killpg operation.
            while True:
                if time.monotonic() >= deadline:
                    raise VerifierProcessError('native verifier exceeded its deadline')
                try:
                    exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    leader_owned = False
                    raise VerifierProcessError('native verifier leader ownership was lost') from None
                if exited is not None:
                    break
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    except (OSError, ValueError, VerifierProcessError) as error:
        failure = error if isinstance(error, VerifierProcessError) else VerifierProcessError('native verifier could not execute or capture output')
    finally:
        if process is not None:
            if leader_owned:
                # Refuse group signaling if another reaper took the leader even
                # when failure happened before the ordinary exit-observation loop.
                try:
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except (ChildProcessError, OSError):
                    leader_owned = False
                    failure = VerifierProcessError('native verifier leader ownership was lost')
            if leader_owned:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    failure = VerifierProcessError('native verifier process group could not be terminated')
                try:
                    code = process.wait(timeout=5)
                    result = VerifierProcessResult(code, bytes(output['stdout']), bytes(output['stderr']))
                except subprocess.TimeoutExpired:
                    failure = VerifierProcessError('native verifier leader did not terminate')
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    if failure is not None:
        raise failure
    if result is None:
        raise VerifierProcessError('native verifier did not produce an observed result')
    return result
