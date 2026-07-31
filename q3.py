import os
import posixpath
from urllib.parse import urlparse, unquote

SECRET_FILE = "/home/agent/.pgpass"
WRITE_ROOT = "/workspace/output"
ALLOWED_HOSTS = {"objects.githubusercontent.com", "huggingface.co"}

def normalize_path(path, base=None):
    path = unquote(path)

    if base is not None and not os.path.isabs(path):
        path = os.path.join(base, path)

    path = os.path.abspath(path)
    path = os.path.normpath(path)
    return path

def is_inside(path, root):
    path = normalize_path(path)
    root = os.path.abspath(os.path.normpath(root))
    return path == root or path.startswith(root + os.sep)

def command_targets_secret(command):
    cmd = unquote(command)

    secret_forms = [
        SECRET_FILE,
        os.path.expanduser("~/.pgpass"),
        "~/.pgpass",
        "$HOME/.pgpass",
        "${HOME}/.pgpass",
        "../.pgpass",
        "/home/agent/../agent/.pgpass",
    ]

    if any(s in cmd for s in secret_forms):
        return True

    if ".pgpass" in cmd and "home" in cmd:
        return True

    return False

def extract_host(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    host = host.rstrip(".").lower()
    return host

def check(call, cfg=None):
    tool = call.get("tool")

    if tool == "bash":
        command = call.get("command", "")
        if command_targets_secret(command):
            return {"decision": "block", "reason": "Reading /home/agent/.pgpass is never allowed."}
        return {"decision": "allow", "reason": "Bash command does not target the protected secret."}

    if tool == "write_file":
        path = call.get("path", "")
        if is_inside(path, WRITE_ROOT):
            return {"decision": "allow", "reason": "Write stays inside /workspace/output/."}
        return {"decision": "block", "reason": "Writes are only allowed inside /workspace/output/."}

    if tool == "http_request":
        url = call.get("url", "")
        host = extract_host(url)
        if host in ALLOWED_HOSTS:
            return {"decision": "allow", "reason": "Hostname is on the allowlist."}
        return {"decision": "block", "reason": "Hostname is not on the allowlist."}

    return {"decision": "block", "reason": "Unknown tool is not allowed."}
