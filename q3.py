import os
from urllib.parse import urlparse, unquote

SECRET_FILE = "/home/agent/.pgpass"
WRITE_ROOT = "/workspace/output"
ALLOWED_HOSTS = {"objects.githubusercontent.com", "huggingface.co"}

def normalize_path(path):
    path = unquote(path)
    return os.path.abspath(os.path.normpath(path))

def is_inside_root(path, root):
    path = normalize_path(path)
    root = os.path.abspath(os.path.normpath(root))
    return path == root or path.startswith(root + os.sep)

def command_mentions_secret(command):
    cmd = unquote(command)

    secret_forms = [
        SECRET_FILE,
        os.path.expanduser("~/.pgpass"),
        "~/.pgpass",
        "$HOME/.pgpass",
        "${HOME}/.pgpass",
        "../.pgpass",
        "..%2f.pgpass",
    ]

    if any(form in cmd for form in secret_forms):
        return True

    if ".pgpass" in cmd and "home/agent" in cmd:
        return True

    return False

def extract_host(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.rstrip(".").lower()

def check(call, cfg=None):
    tool = call.get("tool", "")

    if tool == "bash":
        command = call.get("command", "")
        if command_mentions_secret(command):
            return {
                "decision": "block",
                "reason": "Reading /home/agent/.pgpass is never permitted by this agent's policy."
            }
        return {
            "decision": "allow",
            "reason": "Bash command does not target the protected secret."
        }

    if tool == "write_file":
        path = call.get("path", "")
        if is_inside_root(path, WRITE_ROOT):
            return {
                "decision": "allow",
                "reason": "Write stays inside /workspace/output/."
            }
        return {
            "decision": "block",
            "reason": "Writes are only allowed inside /workspace/output/."
        }

    if tool == "http_request":
        url = call.get("url", "")
        host = extract_host(url)
        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Hostname is on the allowlist."
            }
        return {
            "decision": "block",
            "reason": "Hostname is not on the allowlist."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool is not allowed."
    }
