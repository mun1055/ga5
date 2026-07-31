import hashlib
def solve(challenge: str, email: str) -> str:
    s = f"{challenge}:{email.strip().lower()}"
    return hashlib.sha256(s.encode()).hexdigest()[:16]
