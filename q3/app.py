import os
import re
import shlex
import base64
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# -------------------------------
# Assignment policy
# -------------------------------

WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"

SECRET_FILE = "/home/agent/.pgpass"

ALLOWED_WRITE_DIR = Path("/workspace/output").resolve()

ALLOWED_HOSTS = {
    "objects.githubusercontent.com",
    "huggingface.co"
}


# -------------------------------
# Request model
# -------------------------------

class ToolRequest(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


# -------------------------------
# Helpers
# -------------------------------

def normalize_path(path: str) -> Path:
    """
    Expand:
        ~
        $HOME
    Then normalize.
    """

    path = path.replace("$HOME", HOME)
    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return Path(path).resolve()


def contains_secret(path: Path):
    return path == Path(SECRET_FILE).resolve()


def inside_output(path: Path):
    try:
        path.relative_to(ALLOWED_WRITE_DIR)
        return True
    except ValueError:
        return False


def decode_base64_strings(command: str):
    """
    Detect common:
        echo XXXXX | base64 -d
    """

    matches = re.findall(r'([A-Za-z0-9+/=]{12,})', command)

    decoded = []

    for m in matches:
        try:
            decoded.append(base64.b64decode(m).decode(errors="ignore"))
        except:
            pass

    return decoded


def inspect_command(command: str):

    expanded = command.replace("$HOME", HOME)
    expanded = expanded.replace("~", HOME)

    decoded = decode_base64_strings(expanded)

    candidates = [expanded] + decoded

    for text in candidates:

        if SECRET_FILE in text:
            return True

        try:
            tokens = shlex.split(text)
        except:
            tokens = text.split()

        for token in tokens:

            if token.startswith("-"):
                continue

            p = normalize_path(token)

            if contains_secret(p):
                return True

    return False


def host_allowed(url: str):

    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()

    return hostname in ALLOWED_HOSTS


# -------------------------------
# Endpoint
# -------------------------------

@app.post("/")
def guardrail(req: ToolRequest):

    # -----------------------
    # bash
    # -----------------------

    if req.tool == "bash":

        if inspect_command(req.command or ""):
            return {
                "decision": "block",
                "reason": "Reading protected secret file."
            }

        return {
            "decision": "allow",
            "reason": "Command allowed."
        }

    # -----------------------
    # write_file
    # -----------------------

    if req.tool == "write_file":

        if req.path is None:
            return {
                "decision": "block",
                "reason": "Missing path."
            }

        p = normalize_path(req.path)

        if inside_output(p):
            return {
                "decision": "allow",
                "reason": "Write inside output directory."
            }

        return {
            "decision": "block",
            "reason": "Write outside permitted directory."
        }

    # -----------------------
    # HTTP
    # -----------------------

    if req.tool == "http_request":

        if host_allowed(req.url or ""):
            return {
                "decision": "allow",
                "reason": "Allowed host."
            }

        return {
            "decision": "block",
            "reason": "Host not allowlisted."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }
