"""The memory agent: secrets held in memory only, behind a private Unix socket (ssh-agent style).

For cloud machines that have no desktop keyring and no usable kernel keyring. One agent serves one product
namespace. It never writes a secret to disk, and after it stops (or the machine restarts) the person approves
again. There is no plaintext fallback anywhere in this module.

Run it as ``python -m anthus_cli_login.stores.agent serve|status|stop --namespace <namespace>``; a product
mounts the same functions under its own CLI name (``<product> auth agent``).

Security model:
- the socket lives in a 0700 directory under the product's state directory and is created 0600;
- the server checks the peer's user id on every connection (``SO_PEERCRED`` on Linux, ``getpeereid`` on macOS)
  and the client checks the server's, so a different user can neither read nor impersonate it;
- other processes of the same user can talk to it, exactly as with ssh-agent;
- core dumps are disabled, so a crash does not write the secrets out.

Windows is not supported in this version: the module imports, but ``serve`` and the client say so clearly.
Use the Credential Manager store there.

Protocol: each connection carries one request and one answer, each a 4-byte big-endian length followed by a
JSON object. Operations: ``ping``, ``get``, ``set``, ``delete``, ``stop``.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from ..errors import AuthError, StoreUnavailable
from ..locks import default_state_dir

ENV_SOCKET = "ANTHUS_CLI_LOGIN_AGENT_SOCKET"
MAX_MESSAGE = 1 << 20  # one MiB per message: a session record is a few KiB
_SAFE = re.compile(r"[A-Za-z0-9._-]{1,200}")
_IO_TIMEOUT = 5.0
# sockaddr_un.sun_path is 104 bytes on macOS and 108 on Linux, including the terminating NUL.
_MAX_SOCKET_PATH = 100

UNSUPPORTED_ON_WINDOWS = (
    "The memory agent is not supported on Windows in this version; use Windows Credential Manager "
    "(the default store there)."
)


def _require_unix() -> None:
    if sys.platform == "win32" or not hasattr(socket, "AF_UNIX"):
        raise AuthError(UNSUPPORTED_ON_WINDOWS)


def agent_command(namespace: str, *, state_dir: Path | str | None = None, socket_path: Path | str | None = None) -> str:
    """The command that starts this namespace's agent, for guidance in error messages."""
    command = f"{os.path.basename(sys.executable) or 'python'} -m anthus_cli_login.stores.agent serve --namespace {namespace}"
    if state_dir is not None:
        command += f" --state-dir {state_dir}"
    if socket_path is not None:
        command += f" --socket {socket_path}"
    return command + " --background"


def socket_path_for(namespace: str, state_dir: Path | str | None = None, environ=None) -> Path:
    """Where the namespace's agent listens: the environment override, else the state directory."""
    override = (os.environ if environ is None else environ).get(ENV_SOCKET)
    if override:
        return Path(override)
    base = Path(state_dir) if state_dir is not None else default_state_dir(namespace)
    return base / "agent" / "agent.sock"


# ---------------------------------------------------------------------------------------------------------
# Peer identity


def peer_uid(sock: socket.socket) -> int:
    """The user id of the process on the other end of a Unix socket."""
    if sys.platform.startswith("linux"):
        data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", data)[1]
    libc = ctypes.CDLL(None, use_errno=True)
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    if libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), "getpeereid failed")
    return uid.value


# ---------------------------------------------------------------------------------------------------------
# Wire format


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    while size:
        chunk = sock.recv(min(size, 65536))
        if not chunk:
            raise ConnectionError("connection closed")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def send_message(sock: socket.socket, message: dict) -> None:
    data = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE:
        raise ValueError("message too large")
    sock.sendall(struct.pack(">I", len(data)) + data)


def read_message(sock: socket.socket) -> dict:
    (size,) = struct.unpack(">I", _read_exact(sock, 4))
    if size > MAX_MESSAGE:
        raise ValueError("message too large")
    message = json.loads(_read_exact(sock, size).decode("utf-8"))
    if not isinstance(message, dict):
        raise TypeError("message must be an object")
    return message


# ---------------------------------------------------------------------------------------------------------
# Directory and process hygiene


def _private_directory(path: Path, *, create: bool) -> None:
    """A directory only this user can enter. Refuses a symlink, a foreign owner or loose permissions."""
    if path.is_symlink():
        raise AuthError("The memory agent directory must not be a symlink.")
    if not path.exists():
        if not create:
            raise FileNotFoundError(str(path))
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)
        except OSError:
            raise AuthError("Unable to create the private memory agent directory; check permissions.") from None
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise AuthError(
            "The memory agent directory must be owned by you with mode 0700; "
            f"fix it or set {ENV_SOCKET} to a socket inside a private directory."
        )


def _harden_process() -> None:
    """Best effort: no core dumps and no ptrace-style reads of the agent's memory by other processes."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0
        except (OSError, AttributeError):
            pass


def _check_length(path: Path) -> None:
    if len(os.fsencode(path)) > _MAX_SOCKET_PATH:
        raise AuthError(
            "The memory agent socket path is too long for a Unix socket; "
            f"set {ENV_SOCKET} to a shorter path inside a private directory."
        )


# ---------------------------------------------------------------------------------------------------------
# The client


class AgentClient:
    """Talks to an agent over its socket, checking that the agent runs as the same user."""

    def __init__(self, path: Path | str, namespace: str):
        _require_unix()
        self.path = Path(path)
        self.namespace = namespace

    def _not_running(self) -> StoreUnavailable:
        return StoreUnavailable(
            "The memory agent is not running. Start it with: "
            + agent_command(self.namespace, socket_path=os.environ.get(ENV_SOCKET) and self.path or None)
            + " and then sign in again."
        )

    def request(self, message: dict) -> dict:
        try:
            _private_directory(self.path.parent, create=False)
            info = self.path.lstat()
        except FileNotFoundError:
            raise self._not_running() from None
        except AuthError as error:
            raise StoreUnavailable(str(error)) from None
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
            raise StoreUnavailable("The memory agent socket is not owned by you; refusing to use it.")
        _check_length(self.path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(_IO_TIMEOUT)
            try:
                sock.connect(os.fspath(self.path))
            except (FileNotFoundError, ConnectionRefusedError):
                raise self._not_running() from None
            try:
                if peer_uid(sock) != os.geteuid():
                    raise StoreUnavailable("The memory agent runs as a different user; refusing to use it.")
                send_message(sock, message)
                answer = read_message(sock)
            except StoreUnavailable:
                raise
            except (OSError, ValueError, TypeError):
                raise StoreUnavailable(
                    "The memory agent did not answer; stop it with `... stop` and start it again."
                ) from None
        finally:
            sock.close()
        if not answer.get("ok"):
            raise AuthError("The memory agent refused the request.")
        return answer

    def ping(self) -> dict:
        answer = self.request({"op": "ping"})
        if answer.get("namespace") != self.namespace:
            raise StoreUnavailable("The memory agent at this socket serves a different product; refusing to use it.")
        return answer


class AgentStore:
    """The session store backed by a running memory agent."""

    name = "memory agent"

    def __init__(self, namespace: str, *, state_dir=None, socket_path=None, environ=None):
        if not namespace:
            raise AuthError("A store namespace is required.")
        self.namespace = namespace
        path = Path(socket_path) if socket_path is not None else socket_path_for(namespace, state_dir, environ)
        self.client = AgentClient(path, namespace)

    def probe(self) -> None:
        self.client.ping()

    @staticmethod
    def _key(key: str) -> str:
        if not isinstance(key, str) or not _SAFE.fullmatch(key):
            raise AuthError("Invalid session key.")
        return key

    def get(self, key):
        return self.client.request({"op": "get", "key": self._key(key)}).get("value")

    def set(self, key, value):
        self.client.request({"op": "set", "key": self._key(key), "value": value})

    def delete(self, key):
        self.client.request({"op": "delete", "key": self._key(key)})


# ---------------------------------------------------------------------------------------------------------
# The server


class MemoryAgent:
    """The agent's state: a dictionary and a stop flag. No file is ever opened for it."""

    def __init__(self, namespace: str):
        self.namespace = namespace
        self._secrets: dict[str, str] = {}
        self._lock = threading.Lock()
        self.stopping = threading.Event()

    def handle(self, request: dict) -> dict:
        op = request.get("op")
        if op == "ping":
            with self._lock:
                return {"ok": True, "namespace": self.namespace, "pid": os.getpid(), "count": len(self._secrets)}
        if op == "stop":
            self.stopping.set()
            return {"ok": True}
        key = request.get("key")
        if op in ("get", "set", "delete") and (not isinstance(key, str) or not _SAFE.fullmatch(key)):
            return {"ok": False, "error": "invalid_key"}
        if op == "get":
            with self._lock:
                return {"ok": True, "value": self._secrets.get(key)}
        if op == "set":
            value = request.get("value")
            if not isinstance(value, str):
                return {"ok": False, "error": "invalid_value"}
            with self._lock:
                self._secrets[key] = value
            return {"ok": True}
        if op == "delete":
            with self._lock:
                self._secrets.pop(key, None)
            return {"ok": True}
        return {"ok": False, "error": "unknown_operation"}

    def serve_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(_IO_TIMEOUT)
            if peer_uid(conn) != os.geteuid():
                return  # a different user gets no answer at all
            send_message(conn, self.handle(read_message(conn)))
        except (OSError, ValueError, TypeError):
            pass  # a broken or hostile client only loses its own connection
        finally:
            conn.close()


def _alive(path: Path, namespace: str) -> bool:
    try:
        AgentClient(path, namespace).request({"op": "ping"})
        return True
    except AuthError:
        return False


def serve(
    namespace: str,
    *,
    state_dir=None,
    socket_path=None,
    ready: threading.Event | None = None,
    handle_signals: bool = False,
) -> None:
    """Run the agent in the foreground until it is stopped. ``ready`` is set once the socket listens."""
    _require_unix()
    if not _SAFE.fullmatch(namespace or ""):
        raise AuthError("Invalid namespace.")
    path = Path(socket_path) if socket_path is not None else socket_path_for(namespace, state_dir)
    _check_length(path)
    _private_directory(path.parent, create=True)
    if os.path.lexists(path):
        if _alive(path, namespace):
            raise AuthError("A memory agent is already running for this product.")
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
            raise AuthError("Something that is not a stale agent socket is in the way; remove it and retry.")
        path.unlink()
    _harden_process()
    agent = MemoryAgent(namespace)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous_umask = os.umask(0o177)
    try:
        server.bind(os.fspath(path))
    finally:
        os.umask(previous_umask)
    os.chmod(path, 0o600)
    server.listen(16)
    server.settimeout(0.2)
    if handle_signals and threading.current_thread() is threading.main_thread():
        for name in ("SIGTERM", "SIGINT", "SIGHUP"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), lambda *_: agent.stopping.set())
    if ready is not None:
        ready.set()
    try:
        while not agent.stopping.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=agent.serve_connection, args=(conn,), daemon=True).start()
    finally:
        server.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def start_background(namespace: str, *, state_dir=None, socket_path=None, timeout: float = 10.0) -> None:
    """Start the agent as a detached process and return once it answers."""
    _require_unix()
    path = Path(socket_path) if socket_path is not None else socket_path_for(namespace, state_dir)
    if _alive(path, namespace):
        return
    command = [sys.executable, "-m", "anthus_cli_login.stores.agent", "serve", "--namespace", namespace]
    command += ["--socket", os.fspath(path)]
    subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _alive(path, namespace):
            return
        time.sleep(0.05)
    raise AuthError("The memory agent did not start; run the `serve` command in the foreground to see why.")


def status(namespace: str, *, state_dir=None, socket_path=None) -> dict | None:
    """The running agent's ping answer, or None when no agent is running."""
    path = Path(socket_path) if socket_path is not None else socket_path_for(namespace, state_dir)
    try:
        return AgentClient(path, namespace).ping()
    except StoreUnavailable:
        return None


def stop(namespace: str, *, state_dir=None, socket_path=None, timeout: float = 5.0) -> bool:
    """Stop the agent. Returns False when none was running. Everything it held is gone."""
    path = Path(socket_path) if socket_path is not None else socket_path_for(namespace, state_dir)
    client = AgentClient(path, namespace)
    try:
        client.ping()
        client.request({"op": "stop"})
    except StoreUnavailable:
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and os.path.lexists(path):
        time.sleep(0.02)
    return True


def main(argv=None) -> int:
    """``serve`` / ``status`` / ``stop``; a product mounts this under ``<product> auth agent``."""
    parser = argparse.ArgumentParser(prog="python -m anthus_cli_login.stores.agent")
    parser.add_argument("action", choices=["serve", "status", "stop"])
    parser.add_argument("--namespace", required=True, help="the product namespace this agent serves")
    parser.add_argument("--state-dir", help="the product's state directory (default: under ~/.config)")
    parser.add_argument("--socket", help=f"explicit socket path (also {ENV_SOCKET})")
    parser.add_argument("--background", action="store_true", help="serve: detach and return once it answers")
    args = parser.parse_args(argv)
    options = {"state_dir": args.state_dir, "socket_path": args.socket or os.environ.get(ENV_SOCKET)}
    try:
        if args.action == "serve":
            if args.background:
                start_background(args.namespace, **options)
                print("memory agent running")
                return 0
            print(f"memory agent for {args.namespace} listening; stop it with `stop` or a signal", file=sys.stderr)
            serve(args.namespace, handle_signals=True, **options)
            return 0
        if args.action == "status":
            answer = status(args.namespace, **options)
            if answer is None:
                print("memory agent not running")
                return 1
            print(f"memory agent running (pid {answer['pid']}, {answer['count']} stored)")
            return 0
        print("memory agent stopped" if stop(args.namespace, **options) else "memory agent not running")
        return 0
    except AuthError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
