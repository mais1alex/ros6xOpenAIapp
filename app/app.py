from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import routeros_api
import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security.utils import get_authorization_scheme_param
from mcp.server.fastmcp import FastMCP

try:
    from mcp.server.transport_security import TransportSecuritySettings
except Exception:
    TransportSecuritySettings = None

try:
    import paramiko
except Exception:
    paramiko = None

try:
    from pyngrok import ngrok
except Exception:
    ngrok = None

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
CONFIG_PATH = DATA_DIR / "config.json"
SESSION_COOKIE = "mikrotik_ai_session"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

DEFAULT_CONFIG: Dict[str, Any] = {
    "mikrotik_host": "192.168.88.1",
    "mikrotik_user": "admin",
    "mikrotik_pass": "",
    "mikrotik_api_port": 8728,
    "mikrotik_api_ssl": False,
    "mikrotik_plaintext_login": True,
    "mikrotik_ssh_port": 22,
    "public_base_url": "",
    "ngrok_auth_token": "",
    "ngrok_domain": "",
    "oauth_user": "admin",
    "oauth_pass": "",
    "oauth_secret": "",
    "require_oauth": True,
}

_clients: Dict[str, Dict[str, Any]] = {}
_auth_codes: Dict[str, Dict[str, Any]] = {}
_tokens: Dict[str, Dict[str, Any]] = {}
_ngrok_tunnel = None


def ensure_data() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        cfg = DEFAULT_CONFIG.copy()
        cfg["oauth_pass"] = secrets.token_urlsafe(18)
        cfg["oauth_secret"] = secrets.token_urlsafe(48)
        save_config(cfg)


def load_config() -> Dict[str, Any]:
    ensure_data()
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    cfg = DEFAULT_CONFIG.copy()
    cfg.update(data)
    if not cfg.get("oauth_secret"):
        cfg["oauth_secret"] = secrets.token_urlsafe(48)
        save_config(cfg)
    if not cfg.get("oauth_pass"):
        cfg["oauth_pass"] = secrets.token_urlsafe(18)
        save_config(cfg)
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def masked(value: str) -> str:
    return "" if not value else "********"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign_with_secret(payload: Dict[str, Any], secret: str) -> str:
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{b64url(sig)}"


def verify_signed_token(token: str, secret: str) -> Dict[str, Any]:
    try:
        body, sig = token.rsplit(".", 1)
        expected = b64url(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise ValueError("assinatura invalida")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Token invalido: {exc}")
    if payload.get("exp", 0) < int(time.time()):
        raise HTTPException(status_code=401, detail="Token expirado")
    return payload


def make_session() -> str:
    secret = get_admin_secret()
    return sign_with_secret({"sub": "admin", "iat": int(time.time()), "exp": int(time.time()) + 86400}, secret)


def get_admin_secret() -> str:
    cfg = load_config()
    return cfg.get("oauth_secret") or "local-secret"


def is_logged(request: Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    try:
        verify_signed_token(token, get_admin_secret())
        return True
    except Exception:
        return False


def require_login(request: Request) -> None:
    if not is_logged(request):
        raise HTTPException(status_code=303, headers={"Location": "/login"})


def public_base_url() -> str:
    cfg = load_config()
    return str(cfg.get("public_base_url") or "").rstrip("/")


def routeros_pool() -> routeros_api.RouterOsApiPool:
    cfg = load_config()
    return routeros_api.RouterOsApiPool(
        cfg["mikrotik_host"],
        username=cfg["mikrotik_user"],
        password=cfg["mikrotik_pass"],
        port=int(cfg.get("mikrotik_api_port") or 8728),
        use_ssl=bool(cfg.get("mikrotik_api_ssl")),
        plaintext_login=bool(cfg.get("mikrotik_plaintext_login", True)),
    )


def routeros_api_client():
    return routeros_pool().get_api()


def ros_get(path: str) -> List[Dict[str, Any]]:
    return routeros_api_client().get_resource(path).get()


def ssh_exec(command: str) -> str:
    if paramiko is None:
        return "paramiko nao esta instalado"
    cfg = load_config()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=cfg["mikrotik_host"],
            port=int(cfg.get("mikrotik_ssh_port") or 22),
            username=cfg["mikrotik_user"],
            password=cfg["mikrotik_pass"],
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
        )
        _, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out or err
    finally:
        client.close()


def create_mcp() -> FastMCP:
    transport_security = None
    if TransportSecuritySettings is not None:
        # Necessario para uso atras de ngrok/proxy publico.
        # O MCP SDK pode bloquear hosts nao-localhost com 421 Invalid Host header.
        transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    try:
        server = FastMCP(
            "mikrotik-ai",
            stateless_http=True,
            json_response=True,
            host="0.0.0.0",
            transport_security=transport_security,
        )
    except TypeError:
        try:
            server = FastMCP(
                "mikrotik-ai",
                stateless_http=True,
                json_response=True,
                host="0.0.0.0",
            )
        except TypeError:
            server = FastMCP("mikrotik-ai")

    @server.tool()
    def health() -> Dict[str, Any]:
        """Verifica se o MCP esta operacional e mostra o MikroTik configurado."""
        cfg = load_config()
        return {
            "status": "OK",
            "mikrotik_host": cfg.get("mikrotik_host"),
            "api_port": cfg.get("mikrotik_api_port"),
            "ssh_port": cfg.get("mikrotik_ssh_port"),
        }

    @server.tool()
    def test_mikrotik_connection() -> Dict[str, Any]:
        """Testa conexao com o MikroTik via RouterOS API."""
        api = routeros_api_client()
        resource = api.get_resource("/system/resource").get()
        return {"ok": True, "resource": resource}

    @server.tool()
    def system_resource() -> List[Dict[str, Any]]:
        """Retorna recursos do sistema: CPU, memoria, uptime e versao."""
        return ros_get("/system/resource")

    @server.tool()
    def interfaces() -> List[Dict[str, Any]]:
        """Lista interfaces do MikroTik."""
        return ros_get("/interface")

    @server.tool()
    def ip_addresses() -> List[Dict[str, Any]]:
        """Lista enderecos IP configurados."""
        return ros_get("/ip/address")

    @server.tool()
    def routes() -> List[Dict[str, Any]]:
        """Lista rotas IP."""
        return ros_get("/ip/route")

    @server.tool()
    def firewall_filters() -> List[Dict[str, Any]]:
        """Lista regras de firewall filter."""
        return ros_get("/ip/firewall/filter")

    @server.tool()
    def firewall_nat() -> List[Dict[str, Any]]:
        """Lista regras NAT."""
        return ros_get("/ip/firewall/nat")

    @server.tool()
    def logs(top: int = 50) -> List[Dict[str, Any]]:
        """Lista os ultimos logs do RouterOS."""
        rows = ros_get("/log")
        return rows[-max(1, min(top, 300)):]

    @server.tool()
    def routeros_command(command: str) -> str:
        """Executa comando RouterOS via SSH. Use com cuidado."""
        return ssh_exec(command)

    return server


mcp = create_mcp()


class BearerAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        cfg = load_config()
        if not cfg.get("require_oauth", True) or scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        scheme, token = get_authorization_scheme_param(headers.get("authorization"))
        if scheme.lower() != "bearer" or not token:
            res = JSONResponse({"error": "missing_bearer_token"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await res(scope, receive, send)
            return
        verify_signed_token(token, cfg["oauth_secret"])
        await self.app(scope, receive, send)


def check_pkce(verifier: str, challenge: Optional[str], method: Optional[str]) -> bool:
    if not challenge:
        return True
    if method in (None, "plain"):
        return hmac.compare_digest(verifier, challenge)
    if method == "S256":
        return hmac.compare_digest(b64url(hashlib.sha256(verifier.encode()).digest()), challenge)
    return False


def create_mcp_oauth_app() -> FastAPI:
    try:
        mcp.settings.streamable_http_path = "/mcp"
        mcp_app = mcp.streamable_http_app()
    except Exception:
        mcp_app = mcp.sse_app()

    app = FastAPI(
        title="MikroTik AI MCP OAuth",
        lifespan=mcp_app.router.lifespan_context,
    )

    @app.get("/")
    def root():
        base = public_base_url()
        return {"status": "OK", "mcp_url": f"{base}/mcp" if base else "configure public URL in web panel"}

    @app.get("/.well-known/oauth-authorization-server")
    @app.get("/.well-known/oauth-authorization-server/mcp")
    @app.get("/.well-known/openid-configuration")
    def oauth_metadata():
        base = public_base_url()
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "scopes_supported": ["mcp", "mikrotik:read", "mikrotik:write"],
        }

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/mcp")
    def protected_resource_metadata():
        base = public_base_url()
        return {"resource": f"{base}/mcp", "authorization_servers": [base], "scopes_supported": ["mcp", "mikrotik:read", "mikrotik:write"]}

    @app.post("/register")
    async def register(request: Request):
        data = await request.json()
        client_id = secrets.token_urlsafe(24)
        client_secret = secrets.token_urlsafe(32)
        _clients[client_id] = {"client_secret": client_secret, "redirect_uris": data.get("redirect_uris", []), "client_name": data.get("client_name", "MCP Client")}
        return {"client_id": client_id, "client_secret": client_secret, "client_id_issued_at": int(time.time()), "token_endpoint_auth_method": "client_secret_post"}

    @app.get("/authorize", response_class=HTMLResponse)
    def authorize_form(client_id: str, redirect_uri: str, response_type: str = "code", scope: str = "mcp", state: Optional[str] = None, code_challenge: Optional[str] = None, code_challenge_method: Optional[str] = "S256", resource: Optional[str] = None):
        if response_type != "code":
            raise HTTPException(400, "response_type deve ser code")
        if client_id not in _clients:
            _clients.setdefault(client_id, {"client_secret": None, "redirect_uris": [redirect_uri], "client_name": "MCP Client"})
        hidden = {"client_id": client_id, "redirect_uri": redirect_uri, "scope": scope, "state": state or "", "code_challenge": code_challenge or "", "code_challenge_method": code_challenge_method or "plain"}
        inputs = "".join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in hidden.items())
        return f"""
        <html><body style="font-family:Arial;max-width:420px;margin:40px auto">
        <h2>Autorizar MikroTik AI MCP</h2>
        <p>Use o usuario e senha OAuth definidos no painel.</p>
        <form method="post" action="/authorize">
          {inputs}
          <label>Usuario</label><br><input name="username" style="width:100%;padding:10px"><br><br>
          <label>Senha</label><br><input name="password" type="password" style="width:100%;padding:10px"><br><br>
          <button type="submit" style="padding:10px 16px">Autorizar</button>
        </form></body></html>"""

    @app.post("/authorize")
    def authorize_submit(username: str = Form(...), password: str = Form(...), client_id: str = Form(...), redirect_uri: str = Form(...), scope: str = Form("mcp"), state: str = Form(""), code_challenge: str = Form(""), code_challenge_method: str = Form("plain")):
        cfg = load_config()
        if username != cfg.get("oauth_user") or password != cfg.get("oauth_pass"):
            raise HTTPException(status_code=401, detail="Usuario ou senha invalidos")
        code = secrets.token_urlsafe(32)
        _auth_codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "scope": scope, "sub": username, "code_challenge": code_challenge, "code_challenge_method": code_challenge_method, "exp": time.time() + 300}
        params = {"code": code}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)

    @app.post("/token")
    def token(grant_type: str = Form(...), code: Optional[str] = Form(None), redirect_uri: Optional[str] = Form(None), client_id: Optional[str] = Form(None), client_secret: Optional[str] = Form(None), code_verifier: Optional[str] = Form(None), refresh_token: Optional[str] = Form(None)):
        cfg = load_config()
        if grant_type == "authorization_code":
            if not code or code not in _auth_codes:
                raise HTTPException(400, "authorization code invalido")
            item = _auth_codes.pop(code)
            if item["exp"] < time.time() or item["redirect_uri"] != redirect_uri or item["client_id"] != client_id:
                raise HTTPException(400, "authorization code expirado ou inconsistente")
            expected_secret = _clients.get(client_id or "", {}).get("client_secret")
            if expected_secret and client_secret and not hmac.compare_digest(client_secret, expected_secret):
                raise HTTPException(401, "client_secret invalido")
            if not check_pkce(code_verifier or "", item.get("code_challenge"), item.get("code_challenge_method")):
                raise HTTPException(400, "PKCE invalido")
            now = int(time.time())
            payload = {"iss": public_base_url(), "sub": item["sub"], "aud": "mikrotik-ai-mcp", "scope": item["scope"], "iat": now, "exp": now + 3600}
            access_token = sign_with_secret(payload, cfg["oauth_secret"])
            new_refresh = secrets.token_urlsafe(48)
            _tokens[new_refresh] = {**payload, "exp": now + 60 * 60 * 24 * 30}
            return {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600, "refresh_token": new_refresh, "scope": item["scope"]}
        if grant_type == "refresh_token" and refresh_token in _tokens:
            item = _tokens[refresh_token]
            now = int(time.time())
            payload = {k: item[k] for k in ("iss", "sub", "aud", "scope") if k in item}
            payload.update({"iat": now, "exp": now + 3600})
            return {"access_token": sign_with_secret(payload, cfg["oauth_secret"]), "token_type": "Bearer", "expires_in": 3600, "scope": payload.get("scope", "mcp")}
        raise HTTPException(400, "grant_type nao suportado")

    app.mount("/", BearerAuthMiddleware(mcp_app))
    return app


def html_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"""
    <!doctype html><html lang="pt-br"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{title}</title>
    <style>
    body{{font-family:Arial,sans-serif;background:#0f172a;color:#e5e7eb;margin:0}}.wrap{{max-width:920px;margin:32px auto;padding:0 18px}}
    .card{{background:#111827;border:1px solid #334155;border-radius:14px;padding:22px;margin:16px 0;box-shadow:0 8px 24px #0004}}
    input,select{{width:100%;box-sizing:border-box;padding:11px;border-radius:9px;border:1px solid #475569;background:#020617;color:#e5e7eb;margin-top:5px}}
    label{{display:block;margin:12px 0 4px;color:#cbd5e1}}button,.btn{{background:#2563eb;color:white;border:0;border-radius:9px;padding:11px 15px;text-decoration:none;display:inline-block;cursor:pointer}}
    .muted{{color:#94a3b8}}.ok{{color:#22c55e}}.bad{{color:#ef4444}}code{{background:#020617;border:1px solid #334155;border-radius:8px;padding:3px 6px}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}@media(max-width:700px){{.grid{{grid-template-columns:1fr}}}}
    </style></head><body><div class="wrap"><h1>{title}</h1>{body}</div></body></html>
    """)


def start_ngrok_if_configured() -> Optional[str]:
    global _ngrok_tunnel
    cfg = load_config()
    token = cfg.get("ngrok_auth_token")
    if not token or ngrok is None:
        return None
    try:
        ngrok.set_auth_token(token)
        if _ngrok_tunnel is not None:
            return str(_ngrok_tunnel.public_url)
        kwargs = {"addr": 8000, "bind_tls": True}
        if cfg.get("ngrok_domain"):
            kwargs["domain"] = cfg.get("ngrok_domain")
        _ngrok_tunnel = ngrok.connect(**kwargs)
        cfg["public_base_url"] = str(_ngrok_tunnel.public_url).rstrip("/")
        save_config(cfg)
        return cfg["public_base_url"]
    except Exception as exc:
        return f"ERRO: {exc}"


def create_web_app() -> FastAPI:
    app = FastAPI(title="MikroTik AI MCP Panel")

    @app.get("/login", response_class=HTMLResponse)
    def login_page():
        warning = "" if ADMIN_PASSWORD else "<p class='bad'>ADMIN_PASSWORD nao definido. Defina essa variavel no Docker.</p>"
        return html_page("MikroTik AI MCP", f"""
        <div class="card"><h2>Login</h2>{warning}<form method="post" action="/login"><label>Senha administrativa</label><input type="password" name="password" autofocus><br><br><button>Entrar</button></form></div>
        """)

    @app.post("/login")
    def login(password: str = Form(...)):
        if not ADMIN_PASSWORD or not hmac.compare_digest(password, ADMIN_PASSWORD):
            raise HTTPException(status_code=401, detail="Senha invalida")
        res = RedirectResponse("/", status_code=302)
        res.set_cookie(SESSION_COOKIE, make_session(), httponly=True, samesite="lax")
        return res

    @app.get("/logout")
    def logout():
        res = RedirectResponse("/login", status_code=302)
        res.delete_cookie(SESSION_COOKIE)
        return res

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        require_login(request)
        cfg = load_config()
        mcp_url = f"{cfg.get('public_base_url','').rstrip('/')}/mcp" if cfg.get("public_base_url") else "Configure a URL publica ou inicie o ngrok"
        return html_page("MikroTik AI MCP — Painel", f"""
        <p class="muted">Painel local. Nao exponha esta porta publicamente.</p>
        <div class="card"><h2>Status</h2><p>MCP local: <code>http://localhost:8000/mcp</code></p><p>URL para ChatGPT: <code>{mcp_url}</code></p><p>Usuario OAuth: <code>{cfg.get('oauth_user')}</code></p><p>Senha OAuth: <code>{cfg.get('oauth_pass')}</code></p></div>
        <div class="card"><h2>Configurar</h2><form method="post" action="/save">
        <div class="grid"><div><label>Host MikroTik</label><input name="mikrotik_host" value="{cfg.get('mikrotik_host','')}"></div><div><label>Usuario RouterOS</label><input name="mikrotik_user" value="{cfg.get('mikrotik_user','')}"></div></div>
        <label>Senha RouterOS</label><input type="password" name="mikrotik_pass" placeholder="{masked(cfg.get('mikrotik_pass',''))}">
        <div class="grid"><div><label>Porta API</label><input name="mikrotik_api_port" value="{cfg.get('mikrotik_api_port',8728)}"></div><div><label>Porta SSH</label><input name="mikrotik_ssh_port" value="{cfg.get('mikrotik_ssh_port',22)}"></div></div>
        <label>API SSL</label><select name="mikrotik_api_ssl"><option value="false" {'selected' if not cfg.get('mikrotik_api_ssl') else ''}>Nao</option><option value="true" {'selected' if cfg.get('mikrotik_api_ssl') else ''}>Sim</option></select>
        <label>URL publica MCP/ngrok</label><input name="public_base_url" value="{cfg.get('public_base_url','')}" placeholder="https://xxxxx.ngrok-free.dev">
        <label>Ngrok Auth Token opcional</label><input type="password" name="ngrok_auth_token" placeholder="{masked(cfg.get('ngrok_auth_token',''))}">
        <label>Dominio ngrok reservado opcional</label><input name="ngrok_domain" value="{cfg.get('ngrok_domain','')}" placeholder="meu-dominio.ngrok-free.app">
        <div class="grid"><div><label>Usuario OAuth</label><input name="oauth_user" value="{cfg.get('oauth_user','admin')}"></div><div><label>Senha OAuth</label><input name="oauth_pass" value="{cfg.get('oauth_pass','')}"></div></div>
        <br><button>Salvar</button> <a class="btn" href="/test">Testar MikroTik</a> <a class="btn" href="/ngrok/start">Iniciar ngrok</a> <a class="btn" href="/logout">Sair</a>
        </form></div>
        """)

    @app.post("/save")
    def save(request: Request, mikrotik_host: str = Form(...), mikrotik_user: str = Form(...), mikrotik_pass: str = Form(""), mikrotik_api_port: int = Form(8728), mikrotik_ssh_port: int = Form(22), mikrotik_api_ssl: str = Form("false"), public_base_url: str = Form(""), ngrok_auth_token: str = Form(""), ngrok_domain: str = Form(""), oauth_user: str = Form("admin"), oauth_pass: str = Form("")):
        require_login(request)
        cfg = load_config()
        cfg.update({
            "mikrotik_host": mikrotik_host.strip(),
            "mikrotik_user": mikrotik_user.strip(),
            "mikrotik_api_port": int(mikrotik_api_port),
            "mikrotik_ssh_port": int(mikrotik_ssh_port),
            "mikrotik_api_ssl": mikrotik_api_ssl == "true",
            "public_base_url": public_base_url.strip().rstrip("/"),
            "ngrok_domain": ngrok_domain.strip(),
            "oauth_user": oauth_user.strip() or "admin",
            "oauth_pass": oauth_pass.strip() or cfg.get("oauth_pass") or secrets.token_urlsafe(18),
        })
        if mikrotik_pass:
            cfg["mikrotik_pass"] = mikrotik_pass
        if ngrok_auth_token:
            cfg["ngrok_auth_token"] = ngrok_auth_token
        save_config(cfg)
        return RedirectResponse("/", status_code=302)

    @app.get("/test", response_class=HTMLResponse)
    def test(request: Request):
        require_login(request)
        try:
            result = ros_get("/system/resource")
            body = f"<div class='card'><h2 class='ok'>Conexao OK</h2><pre>{json.dumps(result, indent=2, ensure_ascii=False)}</pre><a class='btn' href='/'>Voltar</a></div>"
        except Exception as exc:
            body = f"<div class='card'><h2 class='bad'>Falha na conexao</h2><p>{exc}</p><a class='btn' href='/'>Voltar</a></div>"
        return html_page("Teste MikroTik", body)

    @app.get("/ngrok/start", response_class=HTMLResponse)
    def start_ngrok(request: Request):
        require_login(request)
        result = start_ngrok_if_configured()
        if result and not result.startswith("ERRO"):
            body = f"<div class='card'><h2 class='ok'>Ngrok iniciado</h2><p>URL publica: <code>{result}</code></p><p>URL ChatGPT: <code>{result}/mcp</code></p><a class='btn' href='/'>Voltar</a></div>"
        else:
            body = f"<div class='card'><h2 class='bad'>Ngrok nao iniciado</h2><p>{result or 'Informe o ngrok auth token ou configure a URL publica manualmente.'}</p><a class='btn' href='/'>Voltar</a></div>"
        return html_page("Ngrok", body)

    return app


def run_web():
    uvicorn.run(create_web_app(), host="0.0.0.0", port=int(os.getenv("WEB_PORT", "8080")))


def run_mcp():
    uvicorn.run(create_mcp_oauth_app(), host="0.0.0.0", port=int(os.getenv("MCP_PORT", "8000")))


if __name__ == "__main__":
    ensure_data()
    cfg = load_config()
    if cfg.get("ngrok_auth_token") and not cfg.get("public_base_url"):
        start_ngrok_if_configured()
    t = threading.Thread(target=run_mcp, daemon=True)
    t.start()
    run_web()
