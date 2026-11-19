#!/usr/bin/env python3
"""
mcp-brain-http.py - Remote MCP server (Streamable HTTP / JSON-RPC 2.0) for RSC-OS
Designed to be exposed behind cloudflared (HTTPS + Cloudflare Zero Trust Service Token).
- No external dependencies (Python 3 stdlib + SQLite FTS5 only).
- Validacion doble: Authorization: Bearer <RSC_API_TOKEN>
- Aislamiento por coleccion mediante cabecera X-RSC-Workspace (o parametro workspace).
- Herramientas MCP:
    1. brain_query     -> Busca en SQLite FTS5 + invariantes fijados (tope 800 tokens).
    2. brain_save      -> Saves decisions/memories (with a pinned option for a 1h hot cache).
    3. post_task_close -> Updates the docs, indexes into Brain and computes a timesheet excluding break windows.
    4. quota_status    -> Consulta o marca estado de cuotas cloud / fallback local.
"""
import argparse
import hmac
import json
import math
import os
import re
import sqlite3
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rsc_oauth  # Minimal OAuth 2.1 (PKCE) for clients that only speak OAuth

BASE_DIR = Path(os.environ.get("RSC_BASE_DIR", "/srv"))
TOKENS_FILE = BASE_DIR / "rsc-core" / "config" / "tokens.json"
AUDIT_FILE = BASE_DIR / "rsc-core" / "logs" / "mcp-access.jsonl"
MAX_BODY = 256 * 1024
MIN_TOKEN = 24


def load_tokens() -> dict:
    """token -> {"nombre": str, "workspaces": [..] o ["*"]}.  There is never a default token."""
    tokens = {}
    try:
        data = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
        for tok, info in (data.get("tokens") or {}).items():
            if isinstance(tok, str) and len(tok) >= MIN_TOKEN and isinstance(info, dict):
                tokens[tok] = {"nombre": str(info.get("nombre", "?")), "workspaces": list(info.get("workspaces") or [])}
    except (OSError, ValueError):
        pass
    admin = os.environ.get("RSC_API_TOKEN", "")
    if len(admin) >= MIN_TOKEN and "CAMBIA" not in admin.upper():
        tokens[admin] = {"nombre": "admin", "workspaces": ["*"]}
    return tokens


def audit(who: str, ws: str, method: str, tool: str, status: str) -> None:
    """Access log: who, workspace, method and tool. Never content."""
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        rec = {"t": datetime.now().isoformat(timespec="seconds"), "quien": who, "ws": ws,
               "metodo": method, "tool": tool, "estado": status}
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
TOKENS: dict = {}
_TOKENS_MTIME = None
OAUTH = None  # instancia de rsc_oauth.OAuth (se crea en build_server)
OAUTH_FILE = BASE_DIR / "rsc-core" / "config" / "oauth.json"
MAX_OAUTH_BODY = 64 * 1024
MAX_QUERY_CHARS = 3200  # ~800 tokens max por respuesta de brain_query

DEFAULT_SCHEDULE = {
    "timezone": "Europe/Madrid",
    "owner": "Juan Antonio Rojas",
    "template": "General Template",
    "non_billable_windows": [
        {"name": "desayuno", "start": "10:00", "end": "10:30"},
        {"name": "comida", "start": "14:00", "end": "15:00"},
    ],
    "rounding_block_minutes": 15,
    "min_block_minutes": 15,
}


def sanitize_workspace(name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_-]", "_", (name or "personal").strip().lower())
    return clean or "personal"


def get_db_path(workspace: str) -> Path:
    col_dir = BASE_DIR / "rsc-brain" / "collections"
    col_dir.mkdir(parents=True, exist_ok=True)
    return col_dir / f"{sanitize_workspace(workspace)}.db"


def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            tags TEXT DEFAULT '',
            pinned INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
            title, content, tags, content='memories', content_rowid='id'
        )
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
            INSERT INTO memories_fts(rowid, title, content, tags)
            VALUES (new.id, new.title, new.content, new.tags);
        END;
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
            INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
            VALUES ('delete', old.id, old.title, old.content, old.tags);
        END;
    """)
    for col, ddl in (("topic", "TEXT DEFAULT ''"), ("kind", "TEXT DEFAULT 'note'"), ("session", "TEXT DEFAULT ''")):
        try:
            conn.execute(f"ALTER TABLE memories ADD COLUMN {col} {ddl}")
        except sqlite3.OperationalError:
            pass
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
            INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
            VALUES ('delete', old.id, old.title, old.content, old.tags);
            INSERT INTO memories_fts(rowid, title, content, tags)
            VALUES (new.id, new.title, new.content, new.tags);
        END;
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, goal TEXT DEFAULT '', started_at TEXT NOT NULL, ended_at TEXT DEFAULT ''
        )
    """)
    conn.commit()
    return conn


def tool_brain_save(workspace: str, args: dict) -> str:
    title = (args.get("title") or "Nota").strip()
    content = (args.get("content") or "").strip()
    tags = (args.get("tags") or "").strip()
    pinned = 1 if args.get("pinned") else 0
    if not content:
        return "Error: 'content' es obligatorio."

    db_path = get_db_path(workspace)
    conn = init_db(db_path)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute(
        "INSERT INTO memories (title, content, tags, pinned, created_at) VALUES (?, ?, ?, ?, ?)",
        (title, content, tags, pinned, now),
    )
    mem_id = cur.lastrowid
    conn.commit()
    conn.close()
    pin_txt = " [PINNED HOT CACHE]" if pinned else ""
    return f"Guardado en {sanitize_workspace(workspace)}.db (id={mem_id}){pin_txt}: {title}"


def tool_brain_query(workspace: str, args: dict) -> str:
    query = (args.get("query") or "").strip()
    limit = int(args.get("limit") or 5)
    include_pinned = args.get("include_pinned", True)

    db_path = get_db_path(workspace)
    conn = init_db(db_path)
    blocks = []

    if include_pinned:
        pinned_rows = conn.execute(
            "SELECT id, title, content, created_at FROM memories WHERE pinned = 1 ORDER BY id DESC LIMIT 10"
        ).fetchall()
        if pinned_rows:
            blocks.append("=== INVARIANTES FIJADOS (HOT CACHE 1H) ===")
            for r in pinned_rows:
                blocks.append(f"[#{r['id']}] {r['title']}: {r['content']}")

    if query:
        safe_q = " OR ".join(re.findall(r"[a-zA-Z0-9_áéíóúñÁÉÍÓÚÑ]+", query))
        if safe_q:
            rows = conn.execute(
                """
                SELECT m.id, m.title, m.content, m.tags, m.created_at
                FROM memories_fts f
                JOIN memories m ON m.id = f.rowid
                WHERE memories_fts MATCH ?
                ORDER BY bm25(memories_fts)
                LIMIT ?
                """,
                (safe_q, limit),
            ).fetchall()
        else:
            rows = []
    else:
        rows = conn.execute(
            "SELECT id, title, content, tags, created_at FROM memories ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    if rows:
        blocks.append(f"=== RESULTADOS ({sanitize_workspace(workspace)}) ===")
        for r in rows:
            tag_s = f" [{r['tags']}]" if r["tags"] else ""
            blocks.append(f"[#{r['id']} | {r['created_at']}]{tag_s} {r['title']}: {r['content']}")
    elif not blocks:
        blocks.append(f"No results in {sanitize_workspace(workspace)} for '{query}'.")

    conn.close()
    text = "\n".join(blocks)
    if len(text) > MAX_QUERY_CHARS:
        text = text[:MAX_QUERY_CHARS] + "\n...[truncado al presupuesto de 800 tokens]"
    return text


def to_minutes(hhmm: str) -> int:
    h, m = map(int, hhmm.strip().split(":"))
    return h * 60 + m


def from_minutes(total_min: int) -> str:
    return f"{(total_min // 60) % 24:02d}:{total_min % 60:02d}"


def format_ticket_dt(date_obj: datetime, hhmm: str) -> str:
    h, m = map(int, hhmm.split(":"))
    dt = date_obj.replace(hour=h, minute=m, second=0, microsecond=0)
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{days[dt.weekday()]}, {months[dt.month - 1]} {dt.day:02d} {dt.strftime('%H:%M:%S')} {dt.year}"


def tool_post_task_close(workspace: str, args: dict) -> str:
    client = (args.get("client") or workspace).strip()
    start_s = (args.get("start") or "").strip()
    end_s = (args.get("end") or "").strip()
    summary = (args.get("summary") or "").strip()
    ticket = (args.get("ticket") or "").strip()
    pending = (args.get("pending") or "").strip()
    date_str = (args.get("date") or "").strip()

    if not summary:
        return "Error: 'summary' es obligatorio."

    is_personal = client.lower() in ("personal", "casa", "homelab")
    ws_dir = (
        BASE_DIR / "workspaces" / "personal"
        if is_personal
        else BASE_DIR / "workspaces" / "work" / "clients" / sanitize_workspace(client.replace("work-", ""))
    )
    docs_dir = ws_dir / "02-DOCS"
    docs_dir.mkdir(parents=True, exist_ok=True)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    with (docs_dir / "DECISIONS.md").open("a", encoding="utf-8") as f:
        f.write(f"\n## [{now_str}] Cierre de tarea\n- {summary}\n")
        if pending:
            f.write(f"- Pendiente: {pending}\n")

    (docs_dir / "STATE.md").write_text(
        f"# Estado actual ({now_str})\n\n- Ultima tarea: {summary}\n- Pendiente: {pending or 'Ninguno'}\n",
        encoding="utf-8",
    )

    tool_brain_save(workspace, {"title": f"Cierre {client}", "content": summary, "tags": "cierre,post-task"})

    if is_personal:
        return "[OK] Docs and Brain updated. Personal work excluded from the timesheet."

    if not start_s or not end_s:
        return "[OK] Docs and Brain updated. 'start' and 'end' (HH:MM) are missing to generate the timesheet entry."

    sched_path = BASE_DIR / "rsc-core" / "config" / "schedule.json"
    schedule = json.loads(sched_path.read_text(encoding="utf-8")) if sched_path.exists() else DEFAULT_SCHEDULE

    s, e = to_minutes(start_s), to_minutes(end_s)
    if e <= s:
        return "Error: 'end' must be later than 'start'."

    segments = [(s, e)]
    deducted = []
    for w in schedule["non_billable_windows"]:
        ws, we = to_minutes(w["start"]), to_minutes(w["end"])
        new_segs = []
        ov_total = 0
        for a, b in segments:
            ov_s, ov_e = max(a, ws), min(b, we)
            if ov_s < ov_e:
                ov_total += ov_e - ov_s
                if a < ov_s:
                    new_segs.append((a, ov_s))
                if ov_e < b:
                    new_segs.append((ov_e, b))
            else:
                new_segs.append((a, b))
        if ov_total > 0:
            deducted.append(f"{w['name']} ({w['start']}-{w['end']}, -{ov_total} min)")
        segments = new_segs

    eff_min = sum(b - a for a, b in segments)
    block = schedule.get("rounding_block_minutes", 15)
    billed_min = max(schedule.get("min_block_minutes", 15), int(math.ceil(eff_min / block) * block)) if eff_min > 0 else 0
    hours, mins = divmod(billed_min, 60)
    today = datetime.strptime(date_str, "%Y-%m-%d") if date_str else datetime.now()

    if len(segments) > 1:
        start_disp = from_minutes(segments[0][0])
        end_disp = from_minutes(segments[-1][1])
    else:
        end_disp = from_minutes(segments[-1][1]) if segments else end_s
        start_calc = to_minutes(end_disp) - billed_min
        for w in schedule["non_billable_windows"]:
            ws, we = to_minutes(w["start"]), to_minutes(w["end"])
            if ws <= start_calc < we:
                start_calc -= (we - ws)
        start_disp = from_minutes(start_calc)

    logs_dir = BASE_DIR / "rsc-core" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / f"timesheet-{today.strftime('%Y-%m-%d')}.json"
    recs = json.loads(log_file.read_text(encoding="utf-8")) if log_file.exists() else []
    recs.append({
        "client": client, "ticket": ticket, "start": start_s, "end": end_s,
        "effective_minutes": eff_min, "billed_minutes": billed_min, "summary": summary
    })
    log_file.write_text(json.dumps(recs, indent=2, ensure_ascii=False), encoding="utf-8")

    tramos_line = (
        f"Effective segments (no breaks): {' + '.join(f'{from_minutes(a)}-{from_minutes(b)}' for a, b in segments)}\n"
        if len(segments) > 1 else ""
    )
    ticket_suffix = f" (Ticket {ticket})" if ticket else ""
    return (
        f"=== REGISTRO DE TRABAJO - {client}{ticket_suffix} ===\n"
        f"Plantilla:                   {schedule.get('template', 'General Template')}\n"
        f"Propietario:                 {schedule.get('owner', 'Juan Antonio Rojas')}\n"
        f"Tiempo empleado:             {hours} h  {mins:02d} min\n"
        f"{tramos_line}"
        f"Hora de inicio:              {format_ticket_dt(today, start_disp)}\n"
        f"Hora de finalizacion:        {format_ticket_dt(today, end_disp)}\n"
        f"Incluir horas no operativas: No\n\n"
        f"- {summary}\n\n"
        f"Resumen: {eff_min} min efectivos -> {billed_min} min fichados | Pausas descontadas: {', '.join(deducted) if deducted else 'ninguna'}."
    )


def tool_quota_status(args: dict) -> str:
    q_path = BASE_DIR / "rsc-core" / "config" / "quota-state.json"
    if not q_path.exists():
        return "quota-state.json no encontrado."
    data = json.loads(q_path.read_text(encoding="utf-8"))
    provider = args.get("provider")
    new_status = args.get("set_status")
    if provider and new_status and provider in data.get("providers", {}):
        data["providers"][provider]["status"] = new_status
        q_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return json.dumps(data, indent=2, ensure_ascii=False)


TOOLS_SCHEMA = [
    {
        "name": "brain_query",
        "description": "Busca memoria persistente e invariantes fijados (Hot Cache 1h) en RSC Brain (tope 800 tokens).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Texto o palabras clave a buscar"},
                "workspace": {"type": "string", "description": "Opcional: sobreescribe X-RSC-Workspace"},
                "limit": {"type": "integer", "default": 5}
            }
        }
    },
    {
        "name": "brain_save",
        "description": "Guarda una decision arquitectonica o aprendizaje en RSC Brain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "content": {"type": "string"},
                "tags": {"type": "string"},
                "pinned": {"type": "boolean", "description": "Fijar en Hot Cache 1h"},
                "workspace": {"type": "string"}
            },
            "required": ["title", "content"]
        }
    },
    {
        "name": "post_task_close",
        "description": "Automatic close: updates the docs, saves to Brain and computes a timesheet entry excluding break windows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client": {"type": "string"},
                "start": {"type": "string", "description": "HH:MM"},
                "end": {"type": "string", "description": "HH:MM"},
                "summary": {"type": "string"},
                "ticket": {"type": "string"},
                "pending": {"type": "string"}
            },
            "required": ["client", "summary"]
        }
    },
    {
        "name": "quota_status",
        "description": "Reads or updates the quota status of the cloud pools and the local fallback.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string"},
                "set_status": {"type": "string"}
            }
        }
    }
]


# ---------- Compatibility with the mem_* tools of the previous RSC Brain ----------
SECRET_RE = re.compile(r"(?i)(sk-[a-z0-9]{16,}|bearer\s+[a-z0-9._-]{20,}|password\s*[:=]\s*\S+|token\s*[:=]\s*\S{16,})")


def _clean(text: str) -> str:
    """Quita lo marcado como privado y lo que parece un secreto: no se guarda ni se indexa."""
    text = re.sub(r"<private>.*?</private>", "[privado]", text or "", flags=re.S)
    return SECRET_RE.sub("[secreto omitido]", text)


def tool_mem_save(ws: str, a: dict) -> str:
    content = _clean((a.get("content") or "").strip())
    if not content:
        return "Error: 'content' es obligatorio."
    title = _clean((a.get("title") or content[:60]).strip())
    kind = (a.get("type") or a.get("kind") or "note").strip()[:30]
    topic = (a.get("topic") or "").strip()[:80]
    session = str(a.get("session") or "")[:20]
    conn = init_db(get_db_path(ws))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if topic:
        row = conn.execute("SELECT id FROM memories WHERE topic = ? ORDER BY id DESC LIMIT 1", (topic,)).fetchone()
        if row:
            conn.execute("UPDATE memories SET title=?, content=?, kind=?, session=?, created_at=? WHERE id=?",
                         (title, content, kind, session, now, row["id"]))
            conn.commit(); conn.close()
            return f"Updated topic '{topic}' (id={row['id']})."
    cur = conn.execute("INSERT INTO memories (title, content, tags, pinned, created_at, topic, kind, session) VALUES (?,?,?,?,?,?,?,?)",
                       (title, content, kind, 1 if a.get("pinned") else 0, now, topic, kind, session))
    conn.commit(); mid = cur.lastrowid; conn.close()
    return f"Guardado (id={mid}, tipo={kind})."


def tool_mem_context(ws: str, a: dict) -> str:
    conn = init_db(get_db_path(ws))
    rows = conn.execute("SELECT id, title, content, kind, created_at FROM memories ORDER BY pinned DESC, id DESC LIMIT ?",
                        (int(a.get("limit") or 10),)).fetchall()
    out = [f"=== CONTEXTO ({sanitize_workspace(ws)}) ==="] + [
        f"[#{r['id']} | {r['created_at']} | {r['kind']}] {r['title']}: {r['content']}" for r in rows]
    conn.close()
    text = "\n".join(out) if rows else f"No memories in {sanitize_workspace(ws)}."
    return text[:MAX_QUERY_CHARS]


def tool_mem_session_start(ws: str, a: dict) -> str:
    conn = init_db(get_db_path(ws))
    cur = conn.execute("INSERT INTO sessions (goal, started_at) VALUES (?, ?)",
                       (_clean(a.get("goal") or ""), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); sid = cur.lastrowid; conn.close()
    return f"Sesion {sid} iniciada."


def tool_mem_session_summary(ws: str, a: dict) -> str:
    parts = [f"{k.capitalize()}: {_clean(str(a.get(k) or '')).strip()}" for k in ("goal", "done", "discovered", "decided", "pending") if a.get(k)]
    if not parts:
        return "Error: dame al menos goal, done, discovered, decided o pending."
    return tool_mem_save(ws, {"title": "Resumen de sesion", "content": "\n".join(parts), "type": "summary", "session": a.get("session")})


def tool_mem_session_end(ws: str, a: dict) -> str:
    conn = init_db(get_db_path(ws))
    conn.execute("UPDATE sessions SET ended_at=? WHERE id=?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), int(a.get("session") or 0)))
    conn.commit(); conn.close()
    return "Sesion cerrada."


def tool_mem_forget(ws: str, a: dict) -> str:
    conn = init_db(get_db_path(ws))
    cur = conn.execute("DELETE FROM memories WHERE id = ?", (int(a.get("id") or 0),))
    conn.commit(); n = cur.rowcount; conn.close()
    return "Olvidada." if n else "No existe esa memoria."


def _obj(**props):
    return {"type": "object", "properties": {k: {"type": "string", "description": v} for k, v in props.items()}}


COMPAT_TOOLS = [
    {"name": "mem_search", "description": "Searches the workspace memory (alias of brain_query).", "inputSchema": _obj(query="text", limit="max results")},
    {"name": "mem_save", "description": "Saves a decision, finding or lesson. With a topic it updates instead of duplicating. Anything marked <private> is not saved.", "inputSchema": _obj(title="title", content="contenido", type="decision|discovery|learning|note", topic="tema que evoluciona", session="id de sesion")},
    {"name": "mem_context", "description": "Recent and pinned context of the workspace. Call it at the start.", "inputSchema": _obj(limit="max entries")},
    {"name": "mem_session_start", "description": "Abre una sesion de trabajo.", "inputSchema": _obj(goal="goal")},
    {"name": "mem_session_summary", "description": "Saves the session summary.", "inputSchema": _obj(session="id", goal="goal", done="done", discovered="discovered", decided="decided", pending="pendiente")},
    {"name": "mem_session_end", "description": "Closes the session.", "inputSchema": _obj(session="id")},
    {"name": "mem_forget", "description": "Deletes a memory by id (it stays in the access log).", "inputSchema": _obj(id="memory id")},
]


class MCPHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict, extra_headers: dict | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_resp(self, resp):
        """Sends a response (status, headers, body) from the OAuth module."""
        status, headers, body = resp
        self.send_response(status)
        headers = dict(headers)
        headers["Content-Length"] = str(len(body))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _host(self):
        return self.headers.get("Host")

    def _client_ip(self):
        # Behind Cloudflare the connection comes from 127.0.0.1; the real IP is in CF-Connecting-IP
        peer = self.client_address[0]
        if peer in ("127.0.0.1", "::1"):
            return self.headers.get("CF-Connecting-IP") or peer
        return peer

    def _read_body(self, limit: int):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length < 0 or length > limit:
            return None
        return self.rfile.read(length)

    def _identify(self):
        """Returns the token identity or None. Compares all tokens in constant time.
        Static tokens first, then OAuth access tokens."""
        auth = self.headers.get("Authorization", "")
        found = None
        for tok, info in current_tokens().items():
            if hmac.compare_digest(auth, f"Bearer {tok}"):
                found = info
        if found is None and OAUTH is not None:
            found = OAUTH.identify(auth)
        return found

    @staticmethod
    def _allowed(info: dict, ws: str) -> bool:
        wss = info["workspaces"]
        return "*" in wss or sanitize_workspace(ws) in [sanitize_workspace(w) for w in wss]

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._send_json(200, {"status": "ok", "service": "rsc-brain-mcp-http"})
            return
        if OAUTH is not None:
            if path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
                self._send_resp(OAUTH.protected_resource_metadata(self._host()))
                return
            if path == "/.well-known/oauth-authorization-server":
                self._send_resp(OAUTH.authorization_server_metadata(self._host()))
                return
            if path == "/authorize":
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                self._send_resp(OAUTH.authorize_get(params))
                return
        if path == "/mcp":   # Streamable HTTP: this server does not offer an SSE stream
            self._send_json(405, {"error": "Usa POST /mcp"}, {"Allow": "POST"})
            return
        self._send_json(404, {"error": "Usa POST /mcp"})

    def do_DELETE(self):
        if urlparse(self.path).path == "/mcp":   # no hay sesiones que cerrar
            self._send_json(405, {"error": "This server does not use sessions"}, {"Allow": "POST"})
            return
        self._send_json(404, {"error": "Endpoint no encontrado. Usa /mcp"})

    def do_POST(self):
        path = urlparse(self.path).path
        if OAUTH is not None and path in ("/register", "/authorize", "/token"):
            body = self._read_body(MAX_OAUTH_BODY)
            if body is None:
                self._send_json(413, {"error": "Peticion demasiado grande"})
                return
            if path == "/register":
                self._send_resp(OAUTH.register(body, self._client_ip()))
                return
            form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()}
            if path == "/authorize":
                self._send_resp(OAUTH.authorize_post(form, self._client_ip()))
            else:
                self._send_resp(OAUTH.token(form))
            return
        if path != "/mcp":
            self._send_json(404, {"error": "Endpoint no encontrado. Usa /mcp"})
            return
        who = self._identify()
        if who is None:
            audit("?", "-", "-", "-", "401")
            extra = {"WWW-Authenticate": OAUTH.www_authenticate(self._host())} if OAUTH is not None else None
            self._send_json(401, {"error": "Unauthorized: missing or invalid Authorization: Bearer"}, extra)
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length < 0 or length > MAX_BODY:
            self._send_json(413, {"error": "Peticion demasiado grande"})
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as ex:
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(ex)}})
            return

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}
        # No header: static tokens use "personal"; an OAuth session uses its own unique workspace
        header_ws = self.headers.get("X-RSC-Workspace") or who.get("default_ws", "personal")

        if method == "initialize":
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "rsc-brain", "version": "3.1.0"}
                }
            })
            return

        if method == "ping":
            self._send_json(200, {"jsonrpc": "2.0", "id": req_id, "result": {}})
            return

        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return

        if method == "tools/list":
            self._send_json(200, {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SCHEMA + COMPAT_TOOLS}})
            return

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            ws = arguments.get("workspace") or header_ws
            if not self._allowed(who, ws):
                audit(who["nombre"], ws, method, str(name), "403")
                self._send_json(200, {"jsonrpc": "2.0", "id": req_id,
                                      "result": {"isError": True, "content": [{"type": "text", "text":
                                      f"This token has no access to workspace '{sanitize_workspace(ws)}'."}]}})
                return
            if name == "quota_status" and arguments.get("set_status") and "*" not in who["workspaces"]:
                audit(who["nombre"], ws, method, str(name), "403")
                self._send_json(200, {"jsonrpc": "2.0", "id": req_id,
                                      "result": {"isError": True, "content": [{"type": "text", "text":
                                      "Only the admin token can change the quota status."}]}})
                return
            audit(who["nombre"], ws, method, str(name), "ok")
            try:
                if name == "brain_query":
                    out = tool_brain_query(ws, arguments)
                elif name == "brain_save":
                    out = tool_brain_save(ws, arguments)
                elif name == "post_task_close":
                    out = tool_post_task_close(ws, arguments)
                elif name == "mem_search":
                    out = tool_brain_query(ws, arguments)
                elif name == "mem_save":
                    out = tool_mem_save(ws, arguments)
                elif name == "mem_context":
                    out = tool_mem_context(ws, arguments)
                elif name == "mem_session_start":
                    out = tool_mem_session_start(ws, arguments)
                elif name == "mem_session_summary":
                    out = tool_mem_session_summary(ws, arguments)
                elif name == "mem_session_end":
                    out = tool_mem_session_end(ws, arguments)
                elif name == "mem_forget":
                    out = tool_mem_forget(ws, arguments)
                elif name == "quota_status":
                    out = tool_quota_status(arguments)
                else:
                    self._send_json(200, {
                        "jsonrpc": "2.0", "id": req_id,
                        "error": {"code": -32601, "message": f"Tool desconocida: {name}"}
                    })
                    return
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": req_id,
                    "result": {"content": [{"type": "text", "text": out}]}
                })
            except Exception as ex:
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": req_id,
                    "result": {"isError": True, "content": [{"type": "text", "text": f"Error: {ex}"}]}
                })
            return

        self._send_json(200, {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"Metodo no soportado: {method}"}
        })

    def log_message(self, fmt, *args):
        pass


def current_tokens() -> dict:
    """TOKENS, reloaded when tokens.json changes: removing or rotating a token takes effect without a restart.
    A broken or half-written file never leaves the server without tokens: the last good set is kept."""
    global TOKENS, _TOKENS_MTIME
    try:
        mtime = TOKENS_FILE.stat().st_mtime_ns
    except OSError:
        return TOKENS
    if mtime != _TOKENS_MTIME:
        fresh = load_tokens()
        if fresh:
            TOKENS = fresh
        _TOKENS_MTIME = mtime
    return TOKENS


def build_server(host: str, port: int, oauth: bool = True):
    """Loads the tokens, sets up OAuth (if enabled) and returns the server ready for serve_forever()."""
    global TOKENS, OAUTH, _TOKENS_MTIME
    TOKENS = load_tokens()
    try:
        _TOKENS_MTIME = TOKENS_FILE.stat().st_mtime_ns
    except OSError:
        _TOKENS_MTIME = None
    if not TOKENS:
        raise SystemExit("[RSC-OPS] No valid tokens (>=24 characters). Create %s or set RSC_API_TOKEN. Refusing to start without authentication." % TOKENS_FILE)
    OAUTH = None
    if oauth and os.environ.get("RSC_OAUTH", "1") != "0":
        extra = [u.strip() for u in os.environ.get("RSC_OAUTH_REDIRECTS", "").split(",") if u.strip()]
        OAUTH = rsc_oauth.OAuth(
            os.environ.get("RSC_OAUTH_FILE", str(OAUTH_FILE)),
            current_tokens,
            public_url=os.environ.get("RSC_PUBLIC_URL"),
            extra_redirects=extra,
            audit=lambda who, ws, method, tool, status: audit(who, ws, method, tool, status),
        )
    return ThreadingHTTPServer((host, port), MCPHandler)


def main():
    parser = argparse.ArgumentParser(description="HTTP MCP server for RSC Brain")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    srv = build_server(args.host, args.port)
    print(f"[RSC-OPS] {len(TOKENS)} token(s), OAuth {'activo' if OAUTH else 'desactivado'}. "
          f"Escuchando en http://{args.host}:{args.port}/mcp (Base: {BASE_DIR})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
