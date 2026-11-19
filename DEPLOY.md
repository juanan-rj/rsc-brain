# Deploying the RSC Brain MCP server (with OAuth)

Service: `rsc-brain-mcp.service` (user `<service-user>`, `Restart=always`, `RestartSec=3`).
Files on the server: `<server-path>/rsc-brain/engine/mcp-brain-http.py` and `rsc_oauth.py`.
OAuth state: `<server-path>/rsc-core/config/oauth.json` (mode 600, hashes only). Tokens: `<server-path>/rsc-core/config/tokens.json`.

## Deploy
1. Run the tests: `python -I -m unittest discover -s tests` (everything must pass).
2. Copy `mcp-brain-http.py` and `rsc_oauth.py` to `/tmp`, strip CR characters (`sed -i 's/\r$//'`) and run `python3 -m py_compile`.
3. Back up: `cp -p mcp-brain-http.py backup-pre-oauth-<date>/` inside `engine/`.
4. `install -m 755` the script and `install -m 644` the module into `engine/`.
5. Restart. Without sudo: `kill -TERM $(systemctl show -p MainPID --value rsc-brain-mcp)` and systemd relaunches it in 3 s.
   With sudo: `sudo systemctl restart rsc-brain-mcp`.
6. Verify: `RSC_E2E_TOKEN=<token> python tests/e2e_remote.py https://<your-domain>` (16 steps).

## Rolling back
Copy the script from the `backup-pre-oauth-*` folder over `mcp-brain-http.py` and restart (as in step 5).
The `rsc_oauth.py` module can stay: the old script does not import it. To switch off OAuth only, without
rolling back, set the variable `RSC_OAUTH=0` in the service.

## Notes
- Cloudflare blocks Python's default User-Agent (error 1010): the tests use their own.
- Allowed redirects: `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`
  and loopback (`http://127.0.0.1|localhost|[::1]:port/...`). For others, set `RSC_OAUTH_REDIRECTS` (comma separated).
- Revoking or rotating a token in `tokens.json` takes effect without a restart and cuts its OAuth sessions.
- Known gap (pre-existing): `post_task_close` does not check that the token may write to the given client.
