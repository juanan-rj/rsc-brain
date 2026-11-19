"""Minimal OAuth 2.1 for the RSC Brain MCP server (stdlib only).

What it does: lets MCP clients that only speak OAuth (claude.ai web and mobile) connect.
- Descubrimiento: /.well-known/oauth-protected-resource y /.well-known/oauth-authorization-server
- Dynamic client registration (RFC 7591), public, with a closed redirect_uri allowlist
- /authorize: a screen where the person pastes ONE of their existing tokens (from tokens.json)
- /token: authorization_code with mandatory PKCE S256, and refresh_token with rotation
- The OAuth token inherits the identity (name and workspaces) of the token used to sign in.

What it does NOT do: it creates no new users or passwords, and static Bearer tokens
keep working exactly as before (the server checks them first).
Tokens are never stored in clear text: the state only holds SHA-256 hashes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import tempfile
import threading
import time
from urllib.parse import urlencode, urlparse

ACCESS_TTL = 3600            # 1 hora
REFRESH_TTL = 30 * 86400     # 30 dias
CODE_TTL = 60                # the authorization code lives 60 s and is single use
CLIENT_TTL = 90 * 86400
MAX_CLIENTS = 200
MAX_REDIRECTS = 5
FAIL_LIMIT = 5               # intentos fallidos por IP
REG_LIMIT = 20               # registros por IP y hora
REG_WINDOW = 3600
FAIL_WINDOW = 900            # en 15 minutos
SCOPES = ["brain:read", "brain:write"]

DEFAULT_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")

Resp = tuple  # (status:int, headers:dict, body:bytes)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _json(status: int, payload: dict, extra: dict | None = None) -> Resp:
    headers = {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "Pragma": "no-cache"}
    headers.update(extra or {})
    return status, headers, json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _page(status: int, body: str, extra: dict | None = None) -> Resp:
    headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
    }
    headers.update(extra or {})
    return status, headers, body.encode("utf-8")


def _redirect(url: str) -> Resp:
    if any(ord(c) <= 31 or ord(c) == 127 for c in url):
        return 400, {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"}, b"redireccion no valida"
    return 303, {"Location": url, "Cache-Control": "no-store", "Content-Length": "0"}, b""


class OAuth:
    def __init__(self, state_path, tokens_provider, public_url: str | None = None,
                 extra_redirects=(), clock=time.time, audit=None):
        self.state_path = state_path
        self.tokens_provider = tokens_provider      # () -> {token: {"nombre":..., "workspaces":[...]}}
        self.public_url = (public_url or "").rstrip("/") or None
        self.allowed_redirects = set(DEFAULT_REDIRECTS) | {u for u in extra_redirects if u}
        self.clock = clock
        self._audit = audit or (lambda *a, **k: None)
        self._lock = threading.RLock()
        self._codes: dict = {}      # hash(code) -> data, in memory only
        self._access: dict = {}     # hash(access) -> data, in memory only
        self._fails: dict = {}      # ip -> [marcas de tiempo] de logins fallidos
        self._reg_hits: dict = {}   # ip -> [marcas de tiempo] de registros
        self._state = self._load()

    # ------------------------------------------------------------------ estado
    def _load(self) -> dict:
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("clients", {})
                data.setdefault("refresh", {})
                return data
        except (OSError, ValueError):
            pass
        return {"clients": {}, "refresh": {}}

    def _save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.state_path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".oauth-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.state_path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _prune(self) -> None:
        now = self.clock()
        self._state["clients"] = {k: v for k, v in self._state["clients"].items() if v.get("exp", 0) > now}
        self._state["refresh"] = {k: v for k, v in self._state["refresh"].items() if v.get("exp", 0) > now}
        self._codes = {k: v for k, v in self._codes.items() if v["exp"] > now}
        self._access = {k: v for k, v in self._access.items() if v["exp"] > now}
        for table, window in ((self._fails, FAIL_WINDOW), (self._reg_hits, REG_WINDOW)):
            for ip in list(table):
                table[ip] = [t for t in table[ip] if now - t < window]
                if not table[ip]:
                    del table[ip]

    # --------------------------------------------------------------- utilidades
    def base(self, host: str | None) -> str:
        if self.public_url:
            return self.public_url
        safe_host = re.sub(r"[^A-Za-z0-9.\-:\[\]]", "", host or "localhost")
        return f"https://{safe_host}"

    def redirect_allowed(self, uri: str) -> bool:
        if not isinstance(uri, str) or len(uri) > 512 or not uri.isascii():
            return False
        if any(ord(c) <= 32 or ord(c) == 127 for c in uri):   # CR, LF, tabulador, espacios: inyeccion de cabeceras
            return False
        if uri in self.allowed_redirects:
            return True
        try:
            p = urlparse(uri)
        except ValueError:
            return False
        # loopback for desktop/terminal clients (Claude Code opens a local port)
        return (p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost", "::1")
                and not p.fragment and not p.username)

    def _identity_for(self, tid: str):
        """Finds the current token whose hash is `tid`. If it is removed or rotated, the OAuth session stops being valid."""
        for tok, info in self.tokens_provider().items():
            if hmac.compare_digest(_sha256(tok), tid):
                return info
        return None

    def _match_token(self, presented: str):
        """Compares against all tokens in constant time. Returns info or None."""
        found = None
        for tok, info in self.tokens_provider().items():
            if hmac.compare_digest(presented.encode("utf-8"), tok.encode("utf-8")):
                found = (_sha256(tok), info)
        return found

    # ------------------------------------------------------------ descubrimiento
    def protected_resource_metadata(self, host: str | None) -> Resp:
        base = self.base(host)
        return _json(200, {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": SCOPES,
            "bearer_methods_supported": ["header"],
            "resource_name": "rsc-brain",
        })

    def authorization_server_metadata(self, host: str | None) -> Resp:
        base = self.base(host)
        return _json(200, {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "scopes_supported": SCOPES,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        })

    def www_authenticate(self, host: str | None) -> str:
        return f'Bearer resource_metadata="{self.base(host)}/.well-known/oauth-protected-resource"'

    # ---------------------------------------------------------------- registro
    def register(self, body: bytes, ip: str = "-") -> Resp:
        try:
            meta = json.loads(body.decode("utf-8"))
            if not isinstance(meta, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return _json(400, {"error": "invalid_client_metadata", "error_description": "JSON no valido"})
        uris = meta.get("redirect_uris")
        if not isinstance(uris, list) or not (1 <= len(uris) <= MAX_REDIRECTS):
            return _json(400, {"error": "invalid_redirect_uri", "error_description": "redirect_uris obligatorio (1 a 5)"})
        if not all(self.redirect_allowed(u) for u in uris):
            return _json(400, {"error": "invalid_redirect_uri", "error_description": "redirect_uri no permitido"})
        if meta.get("token_endpoint_auth_method", "none") != "none":
            return _json(400, {"error": "invalid_client_metadata", "error_description": "public clients only (none)"})
        name = str(meta.get("client_name") or "cliente MCP")[:80]
        with self._lock:
            self._prune()
            now = self.clock()
            hits = self._reg_hits.setdefault(ip, [])
            if len(hits) >= REG_LIMIT:
                return _json(429, {"error": "temporarily_unavailable", "error_description": "too many registrations from your IP"})
            hits.append(now)
            while len(self._state["clients"]) >= MAX_CLIENTS:
                oldest = min(self._state["clients"], key=lambda k: self._state["clients"][k].get("created", 0))
                del self._state["clients"][oldest]
            client_id = "c_" + secrets.token_urlsafe(16)
            self._state["clients"][client_id] = {"redirect_uris": list(uris), "client_name": name,
                                                 "created": now, "exp": now + CLIENT_TTL}
            self._save()
        self._audit("oauth", "-", "register", client_id, "ok")
        return _json(201, {
            "client_id": client_id, "client_name": name, "redirect_uris": list(uris),
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })

    # --------------------------------------------------------------- authorize
    def _client(self, client_id):
        with self._lock:
            c = self._state["clients"].get(client_id or "")
        if c and c.get("exp", 0) > self.clock():
            return c
        return None

    def _check_authorize(self, p: dict):
        """Returns (client|None, error_response|None). Bad client or redirect: error page, never a redirect."""
        c = self._client(p.get("client_id"))
        if c is None:
            return None, _page(400, _error_html("Cliente no registrado o caducado."))
        if p.get("redirect_uri") not in c["redirect_uris"]:
            return None, _page(400, _error_html("redirect_uri does not match the registered one."))
        return c, None

    def _err_redirect(self, p: dict, code: str, desc: str) -> Resp:
        q = {"error": code, "error_description": desc}
        if p.get("state"):
            q["state"] = p["state"]
        sep = "&" if "?" in p["redirect_uri"] else "?"
        return _redirect(p["redirect_uri"] + sep + urlencode(q))

    def authorize_get(self, p: dict) -> Resp:
        c, err = self._check_authorize(p)
        if err:
            return err
        if p.get("response_type") != "code":
            return self._err_redirect(p, "unsupported_response_type", "only response_type=code")
        if not p.get("code_challenge") or p.get("code_challenge_method") != "S256":
            return self._err_redirect(p, "invalid_request", "PKCE S256 obligatorio")
        return _page(200, _login_html(c, p))

    def _locked(self, ip: str) -> bool:
        now = self.clock()
        mine = [t for t in self._fails.get(ip, []) if now - t < FAIL_WINDOW]
        if mine:
            self._fails[ip] = mine
        else:
            self._fails.pop(ip, None)
        return len(mine) >= FAIL_LIMIT

    def _fail(self, ip: str) -> None:
        self._fails.setdefault(ip, []).append(self.clock())

    def authorize_post(self, form: dict, ip: str) -> Resp:
        c, err = self._check_authorize(form)
        if err:
            return err
        if form.get("response_type", "code") != "code":
            return self._err_redirect(form, "unsupported_response_type", "only response_type=code")
        if not form.get("code_challenge") or form.get("code_challenge_method") != "S256":
            return self._err_redirect(form, "invalid_request", "PKCE S256 obligatorio")
        with self._lock:
            if self._locked(ip):
                self._audit("oauth", "-", "login", "-", "429")
                return _page(429, _login_html(c, form, "Demasiados intentos. Espera 15 minutos."))
            matched = self._match_token(form.get("token", "").strip())
            if matched is None:
                self._fail(ip)
                self._audit("oauth", "-", "login", "-", "fallo")
                return _page(401, _login_html(c, form, "Token no valido."))
            tid, info = matched
            code = secrets.token_urlsafe(32)
            self._prune()
            self._codes[_sha256(code)] = {
                "client_id": form["client_id"], "redirect_uri": form["redirect_uri"],
                "challenge": form["code_challenge"], "tid": tid, "nombre": info["nombre"],
                "exp": self.clock() + CODE_TTL,
            }
        self._audit(info["nombre"], "-", "login", form["client_id"], "ok")
        q = {"code": code}
        if form.get("state"):
            q["state"] = form["state"]
        sep = "&" if "?" in form["redirect_uri"] else "?"
        return _redirect(form["redirect_uri"] + sep + urlencode(q))

    # ------------------------------------------------------------------- token
    def _issue(self, client_id: str, tid: str, nombre: str) -> dict:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = self.clock()
        self._access[_sha256(access)] = {"client_id": client_id, "tid": tid, "nombre": nombre, "exp": now + ACCESS_TTL}
        self._state["refresh"][_sha256(refresh)] = {"client_id": client_id, "tid": tid, "nombre": nombre, "exp": now + REFRESH_TTL}
        self._save()
        return {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL,
                "refresh_token": refresh, "scope": " ".join(SCOPES)}

    def token(self, form: dict) -> Resp:
        grant = form.get("grant_type")
        client_id = form.get("client_id", "")
        if self._client(client_id) is None:
            return _json(401, {"error": "invalid_client"})
        with self._lock:
            self._prune()
            if grant == "authorization_code":
                data = self._codes.pop(_sha256(form.get("code", "")), None)   # single use, whatever happens
                verifier = form.get("code_verifier", "")
                if (not data or data["client_id"] != client_id or data["redirect_uri"] != form.get("redirect_uri")
                        or not _VERIFIER_RE.match(verifier)
                        or not hmac.compare_digest(_pkce_s256(verifier), data["challenge"])):
                    return _json(400, {"error": "invalid_grant"})
                if self._identity_for(data["tid"]) is None:
                    return _json(400, {"error": "invalid_grant"})
                out = self._issue(client_id, data["tid"], data["nombre"])
                self._audit(data["nombre"], "-", "token", client_id, "ok")
                return _json(200, out)
            if grant == "refresh_token":
                key = _sha256(form.get("refresh_token", ""))
                data = self._state["refresh"].pop(key, None)                    # rotation: the old one dies
                if not data or data["client_id"] != client_id or self._identity_for(data.get("tid", "")) is None:
                    if data:                      # only written if a refresh token was actually removed
                        self._save()
                    return _json(400, {"error": "invalid_grant"})
                out = self._issue(client_id, data["tid"], data["nombre"])
                self._audit(data["nombre"], "-", "refresh", client_id, "ok")
                return _json(200, out)
        return _json(400, {"error": "unsupported_grant_type"})

    # --------------------------------------------------------------- identidad
    def identify(self, auth_header: str):
        """For /mcp: returns the identity if it is a valid OAuth access token, otherwise None."""
        if not auth_header.startswith("Bearer "):
            return None
        with self._lock:
            data = self._access.get(_sha256(auth_header[7:].strip()))
            if not data or data["exp"] <= self.clock():
                return None
            info = self._identity_for(data["tid"])
        if info is None:
            return None
        wss = list(info.get("workspaces") or [])
        default_ws = wss[0] if len(wss) == 1 and wss[0] != "*" else "personal"
        return {"nombre": info["nombre"], "workspaces": wss, "oauth": True, "default_ws": default_ws}


# ------------------------------------------------------------------------ HTML
_STYLE = ("body{font:16px system-ui,sans-serif;max-width:30rem;margin:12vh auto;padding:0 1rem;"
          "background:#111;color:#eee}input,button{font:inherit;padding:.6rem;width:100%;box-sizing:border-box;"
          "margin:.4rem 0}button{background:#5e6ad2;color:#fff;border:0;border-radius:6px;cursor:pointer}"
          "input{background:#1b1b1b;color:#eee;border:1px solid #444;border-radius:6px}.e{color:#ff8a8a}"
          "small{color:#999}")


def _error_html(msg: str) -> str:
    return f"<!doctype html><meta charset=utf-8><title>RSC Brain</title><style>{_STYLE}</style><h1>RSC Brain</h1><p class=e>{html.escape(msg)}</p>"


def _login_html(client: dict, p: dict, error: str | None = None) -> str:
    hidden = "".join(
        f'<input type=hidden name="{k}" value="{html.escape(p.get(k, ""), quote=True)}">'
        for k in ("client_id", "redirect_uri", "response_type", "state", "code_challenge",
                  "code_challenge_method", "scope", "resource"))
    host = urlparse(p.get("redirect_uri", "")).hostname or "?"
    err = f'<p class=e>{html.escape(error)}</p>' if error else ""
    return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>RSC Brain</title><style>{_STYLE}</style><h1>RSC Brain</h1>"
            f"<p><b>{html.escape(client.get('client_name', 'Un cliente'))}</b> quiere acceder a tu memoria "
            f"(volvera a <code>{html.escape(host)}</code>).</p>{err}"
            f"<form method=post action=/authorize>{hidden}"
            f"<label>Tu token de acceso<input type=password name=token autocomplete=off required autofocus></label>"
            f"<button type=submit>Permitir acceso</button></form>"
            f"<small>Paste one of your RSC Brain tokens. Access inherits its permissions and you can revoke it by removing the token.</small>")
