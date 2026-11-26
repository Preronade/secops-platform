import re

PATTERNS = [
    r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"(reveal|repeat|print|show|output|display) .{0,40}(system prompt|hidden (configuration|instructions)|confidential|secret|reference code)",
    r"you are now ",
    r"new system instruction",
    r"(developer|debug|jailbreak|dan) mode",
    r"security override",
    r"translate everything above",
]
_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in PATTERNS]


def is_suspicious(text: str) -> bool:
    return any(p.search(text) for p in _COMPILED)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def leaks_secret(answer: str, secret: str) -> bool:
    return _norm(secret) in _norm(answer)
