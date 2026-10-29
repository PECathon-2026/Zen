"""Local secret store. The model only ever sees `{{SECRET:name}}`; real values are substituted at fill() time.

Values never appear in repr, logs or exception messages (only names and kinds do).
"""
import os
import re

PLACEHOLDER = re.compile(r"\{\{SECRET:([A-Za-z0-9_.-]+)\}\}")
KINDS = ("password", "otp", "card", "email", "secret", "text")
_KIND_HINTS = [("password", r"pass|pwd"), ("otp", r"otp|one_?time|2fa"), ("card", r"card|cvv|cvc|cc_"),
               ("email", r"email|mail"), ("secret", r"api|token|key|secret")]


class VaultError(Exception):
    pass


def infer_kind(name: str) -> str:
    n = name.lower()
    return next((k for k, pat in _KIND_HINTS if re.search(pat, n)), "text")


def placeholder(name: str) -> str:
    return "{{SECRET:%s}}" % name


def secret_name(text: str) -> str | None:
    """Name if `text` is exactly one placeholder, else None."""
    m = PLACEHOLDER.fullmatch(text or "")
    return m.group(1) if m else None


class Vault:
    """name -> (kind, value). Load from env (`ZENLENS_SECRET_<NAME>`) or a gitignored `name[:kind]=value` file."""
    __slots__ = ("_s",)

    def __init__(self, secrets: dict | None = None):
        self._s: dict[str, tuple[str, str]] = {}
        for name, v in (secrets or {}).items():
            kind, val = v if isinstance(v, tuple) else (infer_kind(name), v)
            self.add(name, val, kind)

    def add(self, name: str, value: str, kind: str | None = None):
        if not PLACEHOLDER.fullmatch(placeholder(name)):
            raise VaultError("invalid secret name")
        kind = kind or infer_kind(name)
        if kind not in KINDS:
            raise VaultError(f"invalid kind for {name}: {kind}")
        self._s[name] = (kind, value)

    @classmethod
    def from_env(cls, prefix: str = "ZENLENS_SECRET_", env=None):
        env = os.environ if env is None else env
        return cls({k[len(prefix):].lower(): v for k, v in env.items() if k.startswith(prefix) and v})

    @classmethod
    def from_file(cls, path):
        v = cls()
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    raise VaultError(f"{path}:{n}: expected name[:kind]=value")
                key, val = line.split("=", 1)
                name, _, kind = key.strip().partition(":")
                v.add(name, val.strip(), kind or None)
        return v

    def names(self) -> list[str]:
        return sorted(self._s)

    def kind(self, name: str) -> str:
        if name not in self._s:
            raise VaultError(f"unknown secret: {name}")
        return self._s[name][0]

    def __contains__(self, name):
        return name in self._s

    def resolve(self, text: str) -> str:
        """Substitute every placeholder with its real value. Local use only (executor fill)."""
        def sub(m):
            if m.group(1) not in self._s:
                raise VaultError(f"unknown secret: {m.group(1)}")
            return self._s[m.group(1)][1]
        return PLACEHOLDER.sub(sub, text)

    def canaries(self) -> tuple[str, ...]:
        """Real values, for egress_check(canaries=...) so a value can never leave even if it leaks into a payload."""
        return tuple(v for _, v in self._s.values() if len(v) >= 6)  # shorter values match bbox numbers etc.

    def __repr__(self):
        return f"Vault(names={self.names()})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Vault is not serializable")
