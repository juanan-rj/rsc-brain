<h1 align="center">🧠 RSC Brain</h1>
<p align="center"><b>An MCP server that gives AI agents persistent memory and pinned invariants.</b></p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLite_FTS5-003B57?style=flat-square&logo=sqlite&logoColor=white"/>
  <img src="https://img.shields.io/badge/OAuth_2.1-PKCE-a371f7?style=flat-square"/>
  <img src="https://img.shields.io/badge/MCP-58a6ff?style=flat-square"/>
</p>

## Features

- 🔎 **Full-text memory search** over SQLite FTS5, with pinned invariants and a short-lived hot cache
- 🔐 **Token auth**: static bearer tokens plus an OAuth 2.1 layer (PKCE S256, refresh-token rotation, hashed state)
- 🧱 **Workspace isolation**: each token only reaches its own workspaces
- 📏 **Token budget**: query answers are capped at about 800 tokens
- 🧹 **Secret redaction**: anything that looks like a secret is dropped before it is stored or indexed
- ☁️ **Built to sit behind a tunnel** (Cloudflare Tunnel or any reverse proxy)

## Files

| File | Purpose |
|---|---|
| `mcp-brain-http.py` | HTTP MCP server |
| `rsc_oauth.py` | Minimal OAuth 2.1 authorization server for MCP clients |
| `DEPLOY.md` | Deployment and rollback notes (real hosts and paths replaced by placeholders) |

## Configuration

| Setting | Meaning |
|---|---|
| `RSC_API_TOKEN` | Admin token, at least 24 characters |
| `tokens.json` | Per-client tokens with their workspaces |
| `RSC_OAUTH=0` | Turn the OAuth layer off |
| `RSC_OAUTH_REDIRECTS` | Extra allowed OAuth redirect URIs, comma separated |

## Credits and status

This is my **modified MCP endpoint** for the RSC ecosystem created by **Eric Risco**
([ericrisco/rsc-brain](https://github.com/ericrisco/rsc-brain), [ericrisco/rsc-harness](https://github.com/ericrisco/rsc-harness)).
Check the upstream projects for the official versions and their licenses.
I use it in my own agent setup, together with my
[RSC Harness fork](https://github.com/juanan-rj/rsc-harness) and my [homelab](https://github.com/juanan-rj/homelab).
