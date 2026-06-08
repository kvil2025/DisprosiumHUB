"""
HP Command Center — FastAPI Backend
====================================
Production-ready backend providing system monitoring, process management,
Docker control, Ollama AI proxy, authenticated terminal access, and more.
"""

import asyncio
import json
import logging
import os
import platform
import pty
import secrets
import select
import signal
import struct
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import psutil
from dotenv import load_dotenv
from pathlib import Path

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from jose import JWTError, jwt
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_dotenv()

JWT_SECRET: str = os.getenv("JWT_SECRET", secrets.token_urlsafe(64))
JWT_ALGORITHM: str = "HS256"
JWT_EXPIRATION_HOURS: int = 24
GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
ALLOWED_EMAIL: str = os.getenv("ALLOWED_EMAIL", "")
HOME_DIR: str = os.getenv("HOME_DIR", "/home/user")
DATA_DIR: str = os.getenv("DATA_DIR", f"{HOME_DIR}/data")
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_URL", os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
N8N_BASE_URL: str = os.getenv("N8N_URL", os.getenv("N8N_BASE_URL", "http://localhost:5678"))
N8N_API_KEY: str = os.getenv("N8N_API_KEY", "")
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
FRONTEND_DIR: str = os.getenv("FRONTEND_DIR", "/app/frontend")

# Initialize Gemini
if GEMINI_AVAILABLE and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    logger_init_msg = "Gemini API configured"
else:
    logger_init_msg = "Gemini NOT available (missing library or API key)"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hp-command")

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class GoogleAuthRequest(BaseModel):
    id_token: str


class OllamaChatRequest(BaseModel):
    model: str
    messages: list[dict]
    stream: bool = True
    options: Optional[dict] = None


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="HP Command Center",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS — allow all origins (behind Cloudflare Tunnel)
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Auth Helpers
# ---------------------------------------------------------------------------

def create_jwt_token(email: str, name: str, picture: str) -> str:
    """Create a signed JWT for an authenticated user."""
    payload = {
        "sub": email,
        "name": name,
        "picture": picture,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> dict:
    """Verify and decode a JWT token. Raises on failure."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
        )


async def get_current_user(request: Request) -> dict:
    """Dependency that extracts and validates the JWT from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
        )
    token = auth_header.removeprefix("Bearer ").strip()
    return verify_jwt_token(token)


# ---------------------------------------------------------------------------
# Auth Middleware — protect /api/* except public routes
# ---------------------------------------------------------------------------
PUBLIC_PATHS = {"/api/health", "/api/config", "/api/auth/google", "/api/auth/me", "/api/docs", "/api/redoc", "/api/openapi.json"}


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip non-API routes (except n8n-proxy), public routes, and websocket upgrades
        is_api = path.startswith("/api/")
        is_n8n_proxy = path.startswith("/n8n-proxy/") or path == "/n8n-proxy" or path.startswith("/rest/")

        if not is_api and not is_n8n_proxy:
            return await call_next(request)

        if path in PUBLIC_PATHS or request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        # For n8n-proxy: accept JWT from cookie or query param (browser new tab)
        token = None
        if is_n8n_proxy:
            token = request.cookies.get("hp_jwt")
            if not token:
                token = request.query_params.get("token")
            if not token:
                return HTMLResponse(
                    content="<html><body style='background:#0a0a0f;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;'>"
                    "<div style='text-align:center;'><h2>&#128274; Sesion requerida</h2>"
                    "<p>Inicia sesion en DisprosiumHUB y luego haz click en 'Abrir n8n'.</p>"
                    "<a href='/' style='color:#00f2ff;'>&larr; Ir a DisprosiumHUB</a></div></body></html>",
                    status_code=401,
                )
        else:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.removeprefix("Bearer ").strip()
            else:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing or malformed Authorization header"},
                )

        try:
            verify_jwt_token(token)
        except HTTPException:
            if is_n8n_proxy:
                return HTMLResponse(
                    content="<html><body style='background:#0a0a0f;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;'>"
                    "<div style='text-align:center;'><h2>&#9200; Sesion expirada</h2>"
                    "<p>Tu sesion ha expirado. Vuelve a iniciar sesion.</p>"
                    "<a href='/' style='color:#00f2ff;'>&larr; Ir a DisprosiumHUB</a></div></body></html>",
                    status_code=401,
                )
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"},
            )

        return await call_next(request)


app.add_middleware(AuthMiddleware)


# ============================================================================
# ROUTES
# ============================================================================

# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/config")
async def get_config():
    """Return public config (Google Client ID) for the frontend."""
    return {"google_client_id": GOOGLE_CLIENT_ID}



# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/auth/google")
async def auth_google(body: GoogleAuthRequest):
    """Verify a Google ID token and issue a JWT session token."""
    try:
        idinfo = google_id_token.verify_oauth2_token(
            body.id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google token: {exc}",
        )

    email = idinfo.get("email", "")
    if email.lower() != ALLOWED_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized email address",
        )

    token = create_jwt_token(
        email=email,
        name=idinfo.get("name", ""),
        picture=idinfo.get("picture", ""),
    )

    return {
        "token": token,
        "user": {
            "email": email,
            "name": idinfo.get("name", ""),
            "picture": idinfo.get("picture", ""),
        },
    }


@app.get("/api/auth/me")
async def auth_me(request: Request):
    """Validate JWT and return user info."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.removeprefix("Bearer ").strip()
    payload = verify_jwt_token(token)

    return {
        "email": payload.get("sub"),
        "name": payload.get("name"),
        "picture": payload.get("picture"),
    }


# ---------------------------------------------------------------------------
# System Metrics
# ---------------------------------------------------------------------------
@app.get("/api/system")
async def system_metrics():
    """Return comprehensive system metrics."""
    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    load_avg = os.getloadavg()

    # Temperatures (may not be available on all systems)
    temperatures = {}
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name, entries in temps.items():
                temperatures[name] = [
                    {"label": e.label or "N/A", "current": e.current, "high": e.high, "critical": e.critical}
                    for e in entries
                ]
    except (AttributeError, RuntimeError):
        pass  # Not available on macOS / some Linux

    # Network I/O
    net = psutil.net_io_counters()

    return {
        "cpu": {
            "percent": cpu_percent,
            "cores_physical": psutil.cpu_count(logical=False),
            "cores_logical": psutil.cpu_count(logical=True),
            "frequency_mhz": round(cpu_freq.current, 0) if cpu_freq else None,
        },
        "memory": {
            "total_gb": round(mem.total / (1024**3), 2),
            "used_gb": round(mem.used / (1024**3), 2),
            "available_gb": round(mem.available / (1024**3), 2),
            "percent": mem.percent,
        },
        "disk": {
            "total_gb": round(disk.total / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "percent": disk.percent,
        },
        "network": {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
        },
        "uptime_seconds": int(uptime_seconds),
        "uptime_human": str(timedelta(seconds=int(uptime_seconds))),
        "load_avg": {
            "1min": round(load_avg[0], 2),
            "5min": round(load_avg[1], 2),
            "15min": round(load_avg[2], 2),
        },
        "temperatures": temperatures,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "hostname": platform.node(),
        },
    }


# ---------------------------------------------------------------------------
# Process Management
# ---------------------------------------------------------------------------
@app.get("/api/processes")
async def list_processes():
    """Return the top 50 processes sorted by CPU usage."""
    procs = []
    for proc in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_percent", "status", "username"]
    ):
        try:
            info = proc.info
            procs.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu_percent": info["cpu_percent"] or 0.0,
                    "memory_percent": round(info["memory_percent"] or 0.0, 2),
                    "status": info["status"],
                    "username": info["username"] or "N/A",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort by CPU descending, take top 50
    procs.sort(key=lambda p: p["cpu_percent"], reverse=True)
    return {"processes": procs[:50], "total": len(procs)}


@app.delete("/api/processes/{pid}")
async def kill_process(pid: int, user: dict = Depends(get_current_user)):
    """Kill a process by PID."""
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.terminate()

        # Wait up to 3 seconds for graceful termination
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()  # Force kill if still alive

        logger.info("User %s killed process %d (%s)", user.get("sub"), pid, proc_name)
        return {"status": "killed", "pid": pid, "name": proc_name}

    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"Process {pid} not found")
    except psutil.AccessDenied:
        raise HTTPException(
            status_code=403, detail=f"Access denied to kill process {pid}"
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Docker Management
# ---------------------------------------------------------------------------
@app.get("/api/docker")
async def list_docker_containers():
    """List all Docker containers."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return {
                "containers": [],
                "error": result.stderr.strip() or "Docker command failed",
                "docker_available": False,
            }

        containers = []
        for line in result.stdout.strip().splitlines():
            if line.strip():
                try:
                    container = json.loads(line)
                    containers.append(
                        {
                            "id": container.get("ID", ""),
                            "name": container.get("Names", ""),
                            "image": container.get("Image", ""),
                            "status": container.get("Status", ""),
                            "state": container.get("State", ""),
                            "ports": container.get("Ports", ""),
                            "created": container.get("CreatedAt", ""),
                        }
                    )
                except json.JSONDecodeError:
                    continue

        return {"containers": containers, "docker_available": True}

    except FileNotFoundError:
        return {
            "containers": [],
            "error": "Docker is not installed",
            "docker_available": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "containers": [],
            "error": "Docker command timed out",
            "docker_available": False,
        }


@app.post("/api/docker/{name}/{action}")
async def docker_action(
    name: str,
    action: str,
    user: dict = Depends(get_current_user),
):
    """Start, stop, or restart a Docker container."""
    if action not in ("start", "stop", "restart"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {action}. Must be start, stop, or restart.",
        )

    try:
        result = subprocess.run(
            ["docker", action, name],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=result.stderr.strip() or f"Failed to {action} container {name}",
            )

        logger.info(
            "User %s performed %s on container %s", user.get("sub"), action, name
        )
        return {"status": "success", "action": action, "container": name}

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Docker is not installed")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Docker command timed out")


# ---------------------------------------------------------------------------
# n8n Integration API
# ---------------------------------------------------------------------------

@app.get("/api/n8n/status")
async def n8n_status(user: dict = Depends(get_current_user)):
    """Check n8n connectivity and return basic info."""
    if not N8N_BASE_URL:
        return {"available": False, "error": "N8N_BASE_URL not configured"}
    try:
        headers = {}
        if N8N_API_KEY:
            headers["X-N8N-API-KEY"] = N8N_API_KEY
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{N8N_BASE_URL}/api/v1/workflows?limit=1", headers=headers)
            if resp.status_code == 200:
                return {"available": True, "url": N8N_BASE_URL, "api_key_set": bool(N8N_API_KEY)}
            elif resp.status_code == 401:
                return {"available": True, "url": N8N_BASE_URL, "api_key_set": False, "error": "API key required. Go to n8n Settings > API > Create API Key."}
            else:
                return {"available": False, "error": f"n8n responded {resp.status_code}"}
    except Exception as e:
        return {"available": False, "error": f"Cannot connect to n8n: {e}"}


@app.get("/api/n8n/workflows")
async def n8n_list_workflows(user: dict = Depends(get_current_user)):
    """List all n8n workflows with status."""
    if not N8N_API_KEY:
        raise HTTPException(status_code=400, detail="N8N_API_KEY not configured. Go to n8n Settings > API > Create API Key, then add it to your .env file.")
    try:
        headers = {"X-N8N-API-KEY": N8N_API_KEY}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{N8N_BASE_URL}/api/v1/workflows", headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=f"n8n API error: {resp.text[:200]}")
            data = resp.json()
            workflows = []
            for w in data.get("data", []):
                workflows.append({
                    "id": w.get("id"),
                    "name": w.get("name", "Unnamed"),
                    "active": w.get("active", False),
                    "createdAt": w.get("createdAt", ""),
                    "updatedAt": w.get("updatedAt", ""),
                    "tags": [t.get("name", "") for t in w.get("tags", [])],
                    "nodes": len(w.get("nodes", [])),
                })
            return {"workflows": workflows, "total": len(workflows)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/n8n/workflows/{workflow_id}/activate")
async def n8n_toggle_workflow(workflow_id: str, user: dict = Depends(get_current_user)):
    """Toggle a workflow active/inactive."""
    if not N8N_API_KEY:
        raise HTTPException(status_code=400, detail="N8N_API_KEY not configured")
    try:
        headers = {"X-N8N-API-KEY": N8N_API_KEY, "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=10) as client:
            # Get current state
            resp = await client.get(f"{N8N_BASE_URL}/api/v1/workflows/{workflow_id}", headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=404, detail="Workflow not found")
            wf = resp.json()
            new_active = not wf.get("active", False)
            endpoint = "activate" if new_active else "deactivate"
            resp2 = await client.post(f"{N8N_BASE_URL}/api/v1/workflows/{workflow_id}/{endpoint}", headers=headers)
            if resp2.status_code in (200, 201):
                return {"id": workflow_id, "active": new_active, "action": endpoint}
            else:
                raise HTTPException(status_code=resp2.status_code, detail=resp2.text[:200])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/n8n/executions")
async def n8n_recent_executions(limit: int = 10, user: dict = Depends(get_current_user)):
    """Get recent workflow executions."""
    if not N8N_API_KEY:
        raise HTTPException(status_code=400, detail="N8N_API_KEY not configured")
    try:
        headers = {"X-N8N-API-KEY": N8N_API_KEY}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{N8N_BASE_URL}/api/v1/executions?limit={limit}", headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=f"n8n error: {resp.text[:200]}")
            data = resp.json()
            executions = []
            for ex in data.get("data", []):
                executions.append({
                    "id": ex.get("id"),
                    "workflowName": ex.get("workflowData", {}).get("name", "?"),
                    "status": ex.get("status", ex.get("finished", False) and "success" or "running"),
                    "startedAt": ex.get("startedAt", ""),
                    "stoppedAt": ex.get("stoppedAt", ""),
                    "mode": ex.get("mode", ""),
                })
            return {"executions": executions}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------------
# OpenClaw Bot Management
# ---------------------------------------------------------------------------
OPENCLAW_DIR = os.getenv("OPENCLAW_DIR", f"{HOME_DIR}/openclaw")
OPENCLAW_LOG = f"{OPENCLAW_DIR}/bot.log"
OPENCLAW_VENV = f"{OPENCLAW_DIR}/venv/bin/python3"


@app.get("/api/openclaw/status")
async def openclaw_status():
    """Check if OpenClaw bot is running and get basic info."""
    try:
        result = subprocess.run(
            ["pgrep", "-af", "bot_hp.py"],
            capture_output=True, text=True, timeout=5
        )
        is_running = result.returncode == 0
        pid = None
        if is_running and result.stdout.strip():
            pid = result.stdout.strip().split()[0]

        # Get last log lines
        log_lines = []
        try:
            result_log = subprocess.run(
                ["tail", "-20", OPENCLAW_LOG],
                capture_output=True, text=True, timeout=5
            )
            log_lines = result_log.stdout.strip().split("\n") if result_log.stdout else []
        except Exception:
            pass

        # Get uptime if running
        uptime = None
        if pid:
            try:
                result_up = subprocess.run(
                    ["ps", "-p", pid, "-o", "etime="],
                    capture_output=True, text=True, timeout=5
                )
                uptime = result_up.stdout.strip()
            except Exception:
                pass

        return {
            "running": is_running,
            "pid": pid,
            "uptime": uptime,
            "log_lines": log_lines,
            "log_path": OPENCLAW_LOG,
        }
    except Exception as exc:
        return {"running": False, "error": str(exc)}


@app.post("/api/openclaw/start")
async def openclaw_start():
    """Start the OpenClaw bot."""
    # Check if already running
    check = subprocess.run(["pgrep", "-f", "bot_hp.py"], capture_output=True, timeout=5)
    if check.returncode == 0:
        return {"status": "already_running", "message": "Bot ya está corriendo"}

    try:
        subprocess.Popen(
            f"cd {OPENCLAW_DIR} && source venv/bin/activate && nohup python3 bot_hp.py > bot.log 2>&1 &",
            shell=True, executable="/bin/bash",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(2)

        check2 = subprocess.run(["pgrep", "-f", "bot_hp.py"], capture_output=True, timeout=5)
        if check2.returncode == 0:
            return {"status": "started", "message": "Bot iniciado correctamente"}
        else:
            return {"status": "error", "message": "Bot no pudo iniciar. Revisa los logs."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error starting bot: {exc}")


@app.post("/api/openclaw/stop")
async def openclaw_stop():
    """Stop the OpenClaw bot."""
    try:
        result = subprocess.run(
            ["pkill", "-f", "bot_hp.py"],
            capture_output=True, text=True, timeout=5
        )
        return {"status": "stopped", "message": "Bot detenido"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error stopping bot: {exc}")


@app.post("/api/openclaw/restart")
async def openclaw_restart():
    """Restart the OpenClaw bot."""
    subprocess.run(["pkill", "-f", "bot_hp.py"], capture_output=True, timeout=5)
    await asyncio.sleep(2)
    subprocess.Popen(
        f"cd {OPENCLAW_DIR} && source venv/bin/activate && nohup python3 bot_hp.py > bot.log 2>&1 &",
        shell=True, executable="/bin/bash",
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    await asyncio.sleep(2)
    check = subprocess.run(["pgrep", "-f", "bot_hp.py"], capture_output=True, timeout=5)
    return {
        "status": "restarted" if check.returncode == 0 else "error",
        "message": "Bot reiniciado" if check.returncode == 0 else "Error al reiniciar"
    }


@app.get("/api/openclaw/logs")
async def openclaw_logs(lines: int = 50):
    """Get the last N lines of the bot log."""
    try:
        result = subprocess.run(
            ["tail", f"-{min(lines, 200)}", OPENCLAW_LOG],
            capture_output=True, text=True, timeout=5
        )
        return {"lines": result.stdout.strip().split("\n") if result.stdout else [], "path": OPENCLAW_LOG}
    except Exception as exc:
        return {"lines": [], "error": str(exc)}


class OpenClawCommand(BaseModel):
    command: str


@app.post("/api/openclaw/execute")
async def openclaw_execute(body: OpenClawCommand):
    """Execute an OpenClaw skill command from the web interface."""
    cmd = body.command.strip().lower()
    original = body.command.strip()

    # ── Clima ──
    if cmd.startswith("clima en ") or cmd.startswith("clima "):
        city = original.split(" ", 2)[-1] if "en" not in cmd.split()[1:2] else original.split("en ", 1)[-1]
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://wttr.in/{city}?format=4&lang=es")
                return {"skill": "clima", "result": resp.text.strip(), "city": city}
        except Exception as e:
            return {"skill": "clima", "error": str(e)}

    # ── Estado del disco ──
    if cmd in ("estado del disco", "disco", "df", "espacio"):
        result = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        return {"skill": "disco", "result": result.stdout.strip()}

    # ── Buscar archivo ──
    if cmd.startswith("busca ") or cmd.startswith("buscar "):
        query = original.split(" ", 2)[-1] if len(original.split()) > 2 else original.split(" ", 1)[-1]
        result = subprocess.run(
            ["find", DATA_DIR, "-iname", f"*{query}*", "-maxdepth", "4"],
            capture_output=True, text=True, timeout=15
        )
        files = [f for f in result.stdout.strip().split("\n") if f]
        return {"skill": "buscar", "query": query, "files": files[:20], "total": len(files)}

    # ── Noticias ──
    if cmd.startswith("noticias"):
        topics = []
        if ":" in original:
            topics = [t.strip() for t in original.split(":", 1)[1].split(",")]
        else:
            # Load saved topics
            topics_file = f"{OPENCLAW_DIR}/temas_noticias.txt"
            try:
                result = subprocess.run(["cat", topics_file], capture_output=True, text=True, timeout=5)
                if result.stdout.strip():
                    topics = [t.strip() for t in result.stdout.strip().split(",")]
            except Exception:
                pass
        if not topics:
            topics = ["minería chile", "geología", "tecnología"]

        import urllib.parse
        news_results = []
        async with httpx.AsyncClient(timeout=10) as client:
            for topic in topics[:5]:
                try:
                    url = f"https://news.google.com/rss/search?q={urllib.parse.quote(topic)}&hl=es-419&gl=CL&ceid=CL:es-419"
                    resp = await client.get(url)
                    # Simple XML parsing for titles
                    import re
                    titles = re.findall(r"<title>(.+?)</title>", resp.text)[1:4]  # Skip feed title
                    news_results.append({"topic": topic, "headlines": titles})
                except Exception:
                    news_results.append({"topic": topic, "headlines": []})
        return {"skill": "noticias", "results": news_results}

    # ── Ejecutar comando seguro ──
    safe_commands = ["uptime", "free -h", "whoami", "hostname", "uname -a", "date", "w", "last -5"]
    if cmd.startswith("ejecuta "):
        command = original.split(" ", 1)[1]
        if command not in safe_commands:
            return {"skill": "ejecutar", "error": f"Comando no permitido. Seguros: {', '.join(safe_commands)}"}
        result = subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
        return {"skill": "ejecutar", "command": command, "result": result.stdout.strip() or result.stderr.strip()}

    # ── Default: enviar a Ollama como pregunta IA ──
    try:
        ollama_payload = {
            "model": "llama3.2:1b",
            "messages": [
                {"role": "system", "content": "Eres OpenClaw, el asistente IA personal de Cristian Ávila, ingeniero geólogo chileno. Respondes en español, conciso y útil. Si te preguntan sobre geología, minería o temas técnicos, da respuestas detalladas."},
                {"role": "user", "content": original}
            ],
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=ollama_payload)
            data = resp.json()
            answer = data.get("message", {}).get("content", "Sin respuesta")
            return {"skill": "ai", "result": answer, "model": "llama3.2:1b"}
    except httpx.ConnectError:
        return {"skill": "ai", "error": "Ollama no está corriendo"}
    except Exception as e:
        return {"skill": "ai", "error": str(e)}


# ---------------------------------------------------------------------------
# OpenClaw Unified — Memory + Skills + AI + Auto-learning
# ---------------------------------------------------------------------------
import uuid as _uuid
import re as _re
import urllib.parse as _urlparse
from pathlib import Path

CONVERSATIONS_DIR = Path(os.getenv("CONVERSATIONS_DIR", "/app/data/conversations"))
CONVERSATIONS_DIR.mkdir(parents=True, exist_ok=True)
LEARNED_SKILLS_PATH = Path(os.getenv("LEARNED_SKILLS_PATH", "/app/data/learned_skills.json"))

# ── Conversation helpers ──
def _conv_path(conv_id: str) -> Path:
    return CONVERSATIONS_DIR / f"{conv_id}.json"

def _load_conversation(conv_id: str) -> dict:
    path = _conv_path(conv_id)
    if path.exists():
        return json.loads(path.read_text())
    return {"id": conv_id, "title": "", "messages": [], "created_at": datetime.now(timezone.utc).isoformat(), "model": ""}

def _save_conversation(conv: dict):
    path = _conv_path(conv["id"])
    path.write_text(json.dumps(conv, ensure_ascii=False, indent=2))

# ── Learned Skills helpers ──
def _load_learned_skills() -> list:
    if LEARNED_SKILLS_PATH.exists():
        try:
            data = json.loads(LEARNED_SKILLS_PATH.read_text())
            return data.get("skills", [])
        except Exception:
            pass
    return []

def _save_learned_skills(skills: list):
    LEARNED_SKILLS_PATH.write_text(json.dumps({"skills": skills}, ensure_ascii=False, indent=2))

def _format_learned_skills(skills: list) -> str:
    if not skills:
        return "Ninguno aún. Sugiere guardar skills cuando resuelvas algo útil."
    lines = []
    for s in skills:
        lines.append(f'- "{s["trigger"]}" → {s["action"]} (usado {s.get("success_count", 0)}x)')
    return "\n".join(lines)

def _build_system_prompt() -> str:
    learned = _load_learned_skills()
    owner_name = os.getenv("OWNER_NAME", "the user")
    owner_bio = os.getenv("OWNER_BIO", "")
    return f"""Eres OpenClaw 🐾, el asistente IA personal de {owner_name}.
{owner_bio}

REGLAS:
- Respondes en español a menos que te hablen en otro idioma
- Eres conciso, técnico cuando necesario, y amigable
- Tienes memoria de conversaciones anteriores — si te preguntan algo que ya discutieron, refiérelo
- Si detectas que puedes crear un skill automatizable, sugiérelo al final con: "💡 ¿Guardar como skill? Escribe: guardar skill"

SKILLS NATIVOS (se ejecutan automáticamente sin IA):
- "clima en [ciudad]" → consulta clima
- "noticias" o "noticias: tema1, tema2" → titulares de Google News
- "busca [nombre]" → buscar archivos en HP_Disco
- "estado del disco" / "disco" → espacio en disco
- "ejecuta [comando]" → comandos seguros (uptime, free -h, date, etc.)
- "ls [ruta]" / "listar [ruta]" → explorar directorios
- "leer [ruta]" / "cat [ruta]" → ver contenido de archivos
- "analizar [ruta]" / "resumir [ruta]" → leer archivo + analizarlo con IA
- "n8n list" → listar workflows de n8n
- "n8n [webhook-id]" → ejecutar un webhook de n8n
- "modelos" / "llm" → ver modelos de IA instalados y recomendaciones
- "descargar [modelo]" / "pull [modelo]" → descargar nuevo modelo de Ollama

CAPACIDADES ESPECIALES:
- Controlas el HP server (CPU, RAM, disco, procesos, Docker)
- Puedes interactuar con n8n para automatizar tareas
- Puedes recomendar qué modelo de IA usar según la tarea:
  * Tareas generales → llama3.2:1b (rápido, liviano)
  * Coding/técnico → qwen2.5-coder (si está instalado)
  * Tareas complejas → sugiere descargar un modelo más grande si hay RAM

SKILLS APRENDIDOS:
{_format_learned_skills(learned)}
"""

# ── Skill Detection ──
async def _detect_and_run_skill(message: str) -> Optional[dict]:
    """Try to match message to a native skill. Returns result dict or None."""
    cmd = message.strip().lower()
    original = message.strip()

    # Clima
    if cmd.startswith("clima en ") or cmd.startswith("clima "):
        city = original.split("en ", 1)[-1] if " en " in original.lower() else original.split(" ", 1)[-1]
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://wttr.in/{city}?format=4&lang=es")
                return {"skill": "clima", "result": resp.text.strip(), "city": city}
        except Exception as e:
            return {"skill": "clima", "error": str(e)}

    # Disco
    if cmd in ("estado del disco", "disco", "df", "espacio"):
        result = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        return {"skill": "disco", "result": result.stdout.strip()}

    # Buscar archivo
    if cmd.startswith("busca ") or cmd.startswith("buscar "):
        query = original.split(" ", 2)[-1] if len(original.split()) > 2 else original.split(" ", 1)[-1]
        result = subprocess.run(
            ["find", DATA_DIR, "-iname", f"*{query}*", "-maxdepth", "4"],
            capture_output=True, text=True, timeout=15
        )
        files = [f for f in result.stdout.strip().split("\n") if f]
        return {"skill": "buscar", "query": query, "files": files[:20], "total": len(files)}

    # Noticias
    if cmd.startswith("noticias"):
        topics = []
        if ":" in original:
            topics = [t.strip() for t in original.split(":", 1)[1].split(",")]
        else:
            topics_file = f"{OPENCLAW_DIR}/temas_noticias.txt"
            try:
                result = subprocess.run(["cat", topics_file], capture_output=True, text=True, timeout=5)
                if result.stdout.strip():
                    topics = [t.strip() for t in result.stdout.strip().split(",")]
            except Exception:
                pass
        if not topics:
            topics = ["minería chile", "geología", "tecnología"]

        news_results = []
        async with httpx.AsyncClient(timeout=10) as client:
            for topic in topics[:5]:
                try:
                    url = f"https://news.google.com/rss/search?q={_urlparse.quote(topic)}&hl=es-419&gl=CL&ceid=CL:es-419"
                    resp = await client.get(url)
                    titles = _re.findall(r"<title>(.+?)</title>", resp.text)[1:4]
                    news_results.append({"topic": topic, "headlines": titles})
                except Exception:
                    news_results.append({"topic": topic, "headlines": []})
        return {"skill": "noticias", "results": news_results}

    # Leer / Analizar archivos
    SAFE_DIRS = [HOME_DIR, "/host", "/tmp", "/var/log", "/etc", "/opt"]
    SAFE_EXTENSIONS = {".txt", ".csv", ".json", ".py", ".md", ".log", ".yaml", ".yml", ".sh", ".sql", ".xml", ".html", ".env", ".conf", ".cfg", ".ini", ".toml", ".pdf", ".docx"}
    MAX_FILE_SIZE = 50 * 1024  # 50KB text limit

    if cmd.startswith("leer ") or cmd.startswith("cat ") or cmd.startswith("ver "):
        filepath = original.split(" ", 1)[1].strip()
        # Security: only allow safe directories
        if not any(filepath.startswith(d) for d in SAFE_DIRS):
            return {"skill": "leer", "error": f"Ruta no permitida. Directorios seguros: {', '.join(SAFE_DIRS)}"}
        import pathlib
        ext = pathlib.Path(filepath).suffix.lower()
        if ext not in SAFE_EXTENSIONS:
            return {"skill": "leer", "error": f"Extensión '{ext}' no permitida. Permitidas: {', '.join(SAFE_EXTENSIONS)}"}
        try:
            import pathlib as _pl
            ext = _pl.Path(filepath).suffix.lower()
            fsize = os.path.getsize(filepath)

            # PDF extraction
            if ext == ".pdf":
                try:
                    from pypdf import PdfReader
                    reader = PdfReader(filepath)
                    pages = len(reader.pages)
                    text_parts = []
                    for i, page in enumerate(reader.pages[:20]):  # max 20 pages
                        t = page.extract_text() or ''
                        text_parts.append(f"--- Página {i+1} ---\n{t}")
                    content = "\n".join(text_parts)[:MAX_FILE_SIZE]
                    truncated = len(content) >= MAX_FILE_SIZE or pages > 20
                    return {"skill": "leer", "path": filepath, "content": content, "size": fsize, "pages": pages, "truncated": truncated, "format": "pdf"}
                except ImportError:
                    return {"skill": "leer", "error": "pypdf no instalado. Usa 'analizar' para enviar el PDF directo a Gemini."}
                except Exception as e:
                    return {"skill": "leer", "error": f"Error leyendo PDF: {e}"}

            # Regular text files
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(MAX_FILE_SIZE)
            truncated = fsize > MAX_FILE_SIZE
            return {"skill": "leer", "path": filepath, "content": content, "size": fsize, "truncated": truncated}
        except FileNotFoundError:
            return {"skill": "leer", "error": f"Archivo no encontrado: {filepath}"}
        except Exception as e:
            return {"skill": "leer", "error": str(e)}

    if cmd.startswith("analizar ") or cmd.startswith("analiza ") or cmd.startswith("resumir ") or cmd.startswith("resume "):
        filepath = original.split(" ", 1)[1].strip()
        if not any(filepath.startswith(d) for d in SAFE_DIRS):
            return {"skill": "analizar", "error": f"Ruta no permitida. Directorios seguros: {', '.join(SAFE_DIRS)}"}
        import pathlib
        ext = pathlib.Path(filepath).suffix.lower()
        if ext not in SAFE_EXTENSIONS:
            return {"skill": "analizar", "error": f"Extensión '{ext}' no permitida."}
        try:
            file_size = os.path.getsize(filepath)
            provider = "llama"
            is_pdf = ext == ".pdf"

            # PDF: use Gemini multimodal (can read PDFs natively)
            if is_pdf and GEMINI_AVAILABLE and GEMINI_API_KEY:
                try:
                    with open(filepath, "rb") as f:
                        pdf_bytes = f.read(5 * 1024 * 1024)  # max 5MB
                    model = genai.GenerativeModel(
                        model_name="gemini-2.0-flash",
                        system_instruction="Eres un analista técnico experto. Analiza documentos y da resúmenes concisos en español.",
                    )
                    gemini_resp = model.generate_content([
                        "Analiza este documento PDF. Da un resumen del contenido, propósito, estructura, y observaciones importantes.",
                        {"mime_type": "application/pdf", "data": pdf_bytes}
                    ])
                    return {"skill": "analizar", "path": filepath, "size": file_size, "analysis": gemini_resp.text, "provider": "gemini", "format": "pdf"}
                except Exception as e:
                    logger.warning(f"Gemini PDF analysis failed: {e}")
                    # Try pypdf fallback
                    try:
                        from pypdf import PdfReader
                        reader = PdfReader(filepath)
                        text_parts = []
                        for i, page in enumerate(reader.pages[:20]):
                            text_parts.append(page.extract_text() or '')
                        content = "\n".join(text_parts)[:MAX_FILE_SIZE]
                    except Exception:
                        return {"skill": "analizar", "error": f"No pude leer el PDF: {e}"}

            # Text files: read content
            elif not is_pdf:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(MAX_FILE_SIZE)
            else:
                # PDF without Gemini: try pypdf
                try:
                    from pypdf import PdfReader
                    reader = PdfReader(filepath)
                    text_parts = [page.extract_text() or '' for page in reader.pages[:20]]
                    content = "\n".join(text_parts)[:MAX_FILE_SIZE]
                except ImportError:
                    return {"skill": "analizar", "error": "Necesito pypdf o Gemini para analizar PDFs."}

            analysis_prompt = f"Analiza el siguiente archivo ({filepath}, {file_size} bytes):\n\n```\n{content}\n```\n\nDa un resumen de su contenido, propósito, y observaciones importantes. Si es código, describe qué hace. Si es datos, describe la estructura."

            # Try Gemini first (much better analysis)
            if GEMINI_AVAILABLE and GEMINI_API_KEY:
                try:
                    model = genai.GenerativeModel(
                        model_name="gemini-2.0-flash",
                        system_instruction="Eres un analista técnico experto. Analiza archivos y da resúmenes concisos en español.",
                    )
                    gemini_resp = model.generate_content(analysis_prompt)
                    analysis = gemini_resp.text
                    provider = "gemini"
                    return {"skill": "analizar", "path": filepath, "size": file_size, "analysis": analysis, "provider": provider}
                except Exception as e:
                    logger.warning(f"Gemini analysis failed, trying Llama: {e}")

            # Fallback to Llama
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json={
                    "model": "llama3.2:1b",
                    "messages": [
                        {"role": "system", "content": "Eres un analista técnico experto. Analiza archivos y da resúmenes concisos en español."},
                        {"role": "user", "content": analysis_prompt}
                    ],
                    "stream": False,
                })
                data = resp.json()
                analysis = data.get("message", {}).get("content", "Sin análisis")
                return {"skill": "analizar", "path": filepath, "size": file_size, "analysis": analysis, "provider": provider}
        except FileNotFoundError:
            return {"skill": "analizar", "error": f"Archivo no encontrado: {filepath}"}
        except httpx.ConnectError:
            return {"skill": "analizar", "error": "Ni Gemini ni Ollama disponibles"}
        except Exception as e:
            return {"skill": "analizar", "error": str(e)}

    # Listar directorio (local o dentro de un container)
    if cmd.startswith("ls ") or cmd.startswith("listar ") or cmd.startswith("directorio "):
        dirpath = original.split(" ", 1)[1].strip()

        # Docker container: "ls docker:<container>:/path"
        if dirpath.startswith("docker:"):
            parts = dirpath.replace("docker:", "").split(":", 1)
            cname = parts[0]
            cpath = parts[1] if len(parts) > 1 else "/"
            try:
                result = subprocess.run(
                    ["docker", "exec", cname, "ls", "-la", "--color=never", cpath],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    return {"skill": "ls", "error": result.stderr.strip()}
                lines = result.stdout.strip().split("\n")
                entries = []
                for line in lines[1:]:  # skip 'total' line
                    parts_l = line.split()
                    if len(parts_l) >= 9:
                        name = " ".join(parts_l[8:])
                        is_dir = parts_l[0].startswith("d")
                        try:
                            size = int(parts_l[4])
                        except ValueError:
                            size = None
                        entries.append({"name": name, "is_dir": is_dir, "size": size if not is_dir else None})
                return {"skill": "ls", "path": f"docker:{cname}:{cpath}", "entries": entries[:50], "total": len(entries), "container": cname}
            except Exception as e:
                return {"skill": "ls", "error": str(e)}

        if not any(dirpath.startswith(d) for d in SAFE_DIRS):
            return {"skill": "ls", "error": f"Ruta no permitida. Seguros: {', '.join(SAFE_DIRS)}. Para containers: ls docker:<nombre>:<ruta>"}
        try:
            import pathlib
            p = pathlib.Path(dirpath)
            if not p.is_dir():
                return {"skill": "ls", "error": f"No es un directorio: {dirpath}"}
            entries = []
            for item in sorted(p.iterdir())[:50]:
                try:
                    stat = item.stat()
                    entries.append({"name": item.name, "is_dir": item.is_dir(), "size": stat.st_size if item.is_file() else None})
                except PermissionError:
                    entries.append({"name": item.name, "is_dir": False, "size": None})
            return {"skill": "ls", "path": dirpath, "entries": entries, "total": len(list(p.iterdir()))}
        except Exception as e:
            return {"skill": "ls", "error": str(e)}

    # Ejecutar comando seguro
    safe_commands = ["uptime", "free -h", "whoami", "hostname", "uname -a", "date", "w", "last -5"]
    if cmd.startswith("ejecuta "):
        command = original.split(" ", 1)[1]
        if command not in safe_commands:
            return {"skill": "ejecutar", "error": f"Comando no permitido. Seguros: {', '.join(safe_commands)}"}
        result = subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
        return {"skill": "ejecutar", "command": command, "result": result.stdout.strip() or result.stderr.strip()}

    # n8n: trigger webhook
    if cmd.startswith("n8n ") or cmd.startswith("webhook "):
        parts = original.split(" ", 1)
        if len(parts) < 2:
            return {"skill": "n8n", "error": "Uso: n8n <webhook-id> o n8n list"}
        subcmd = parts[1].strip()

        if subcmd in ("list", "listar", "workflows"):
            # List n8n webhooks/workflows via production webhooks test
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    # Try the public API with key
                    headers = {}
                    if N8N_API_KEY:
                        headers["X-N8N-API-KEY"] = N8N_API_KEY
                    resp = await client.get(f"{N8N_BASE_URL}/api/v1/workflows", headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        workflows = data.get("data", [])
                        wf_list = [{"name": w.get("name", "?"), "id": w.get("id"), "active": w.get("active", False)} for w in workflows]
                        return {"skill": "n8n", "action": "list", "workflows": wf_list}
                    else:
                        return {"skill": "n8n", "action": "list", "error": f"API respondió {resp.status_code}. Configura N8N_API_KEY o crea una desde n8n Settings > API."}
            except Exception as e:
                return {"skill": "n8n", "error": str(e)}
        else:
            # Trigger a webhook by ID or path
            webhook_path = subcmd
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    # Try production webhook first, then test
                    for prefix in ["/webhook/", "/webhook-test/"]:
                        try:
                            resp = await client.post(f"{N8N_BASE_URL}{prefix}{webhook_path}", json={"source": "openclaw", "timestamp": datetime.now(timezone.utc).isoformat()})
                            if resp.status_code < 400:
                                return {"skill": "n8n", "action": "trigger", "webhook": webhook_path, "status": resp.status_code, "response": resp.text[:500]}
                        except Exception:
                            continue
                    return {"skill": "n8n", "action": "trigger", "webhook": webhook_path, "error": "Webhook no encontrado. Verifica el ID/path en n8n."}
            except Exception as e:
                return {"skill": "n8n", "error": str(e)}

    # Modelos: listar, recomendar, descargar
    if cmd in ("modelos", "models", "llm", "listar modelos"):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
                data = resp.json()
                models = []
                for m in data.get("models", []):
                    size_gb = m.get("size", 0) / 1e9
                    details = m.get("details", {})
                    models.append({
                        "name": m["name"],
                        "size_gb": round(size_gb, 1),
                        "params": details.get("parameter_size", "?"),
                        "family": details.get("family", "?"),
                        "quant": details.get("quantization_level", "?"),
                    })
                # Get RAM info
                import shutil
                mem = psutil.virtual_memory()
                ram_free_gb = round(mem.available / 1e9, 1)
                ram_total_gb = round(mem.total / 1e9, 1)
                # Recommend models
                recs = []
                if ram_free_gb < 1:
                    recs.append("⚠️ Poca RAM libre. Solo modelos <1B parámetros.")
                elif ram_free_gb < 2:
                    recs.append("💡 Puedes usar modelos de 1-1.5B (llama3.2:1b, qwen2.5:0.5b)")
                elif ram_free_gb < 4:
                    recs.append("💡 Puedes usar modelos de hasta 3B (llama3.2:3b, qwen2.5-coder:1.5b)")
                else:
                    recs.append("✅ Suficiente RAM para modelos de 7B")

                return {"skill": "modelos", "models": models, "ram_free_gb": ram_free_gb, "ram_total_gb": ram_total_gb, "recommendations": recs}
        except httpx.ConnectError:
            return {"skill": "modelos", "error": "Ollama no está corriendo"}

    if cmd.startswith("descargar ") or cmd.startswith("pull "):
        model_name = original.split(" ", 1)[1].strip()
        allowed_models = ["llama3.2:1b", "llama3.2:3b", "qwen2.5:0.5b", "qwen2.5:1.5b", "qwen2.5-coder:1.5b", "qwen2.5-coder:0.5b", "gemma2:2b", "phi3:mini", "tinyllama:latest"]
        if model_name not in allowed_models:
            return {"skill": "pull", "error": f"Modelo no permitido. Disponibles: {', '.join(allowed_models)}"}
        try:
            async with httpx.AsyncClient(timeout=600) as client:
                resp = await client.post(f"{OLLAMA_BASE_URL}/api/pull", json={"name": model_name, "stream": False})
                return {"skill": "pull", "model": model_name, "result": "Descarga iniciada" if resp.status_code == 200 else f"Error: {resp.text[:200]}"}
        except Exception as e:
            return {"skill": "pull", "error": str(e)}

    # Guardar skill
    if cmd == "guardar skill" or cmd.startswith("guardar skill"):
        return {"skill": "learn_trigger"}

    return None  # Not a skill → send to AI


def _format_skill_as_message(result: dict) -> str:
    """Format skill result as a readable message for conversation history."""
    skill = result.get("skill", "")
    if skill == "clima":
        return f"🌤️ Clima: {result.get('result', result.get('error', ''))}"
    elif skill == "disco":
        return f"💾 Estado del disco:\n```\n{result.get('result', '')}\n```"
    elif skill == "buscar":
        files = result.get("files", [])
        if files:
            return f"🔍 {result.get('total', 0)} archivos encontrados para '{result.get('query', '')}':\n" + "\n".join(f"  📄 {f}" for f in files)
        return f"🔍 No se encontraron archivos para '{result.get('query', '')}'"
    elif skill == "noticias":
        parts = []
        for r in result.get("results", []):
            parts.append(f"📰 **{r['topic']}**")
            for h in r.get("headlines", []):
                parts.append(f"  • {h}")
        return "\n".join(parts) or "Sin noticias"
    elif skill == "ejecutar":
        if result.get("error"):
            return f"❌ {result['error']}"
        return f"🔧 `{result.get('command', '')}`:\n```\n{result.get('result', '')}\n```"
    elif skill == "leer":
        if result.get("error"):
            return f"📄 Error: {result['error']}"
        trunc = " (truncado, >10KB)" if result.get("truncated") else ""
        return f"📄 **{result.get('path', '')}** ({result.get('size', 0)} bytes{trunc}):\n```\n{result.get('content', '')}\n```"
    elif skill == "analizar":
        if result.get("error"):
            return f"🔬 Error: {result['error']}"
        return f"🔬 **Análisis de {result.get('path', '')}** ({result.get('size', 0)} bytes):\n\n{result.get('analysis', '')}"
    elif skill == "ls":
        if result.get("error"):
            return f"📁 Error: {result['error']}"
        entries = result.get("entries", [])
        lines = []
        for e in entries:
            icon = "📁" if e["is_dir"] else "📄"
            size_str = f" ({e['size']} bytes)" if e.get("size") is not None else ""
            lines.append(f"  {icon} {e['name']}{size_str}")
        return f"📁 **{result.get('path', '')}** ({result.get('total', 0)} items):\n" + "\n".join(lines)
    elif skill == "n8n":
        if result.get("error"):
            return f"🔗 n8n error: {result['error']}"
        action = result.get("action", "")
        if action == "list":
            wfs = result.get("workflows", [])
            if wfs:
                lines = [f"  {'🟢' if w['active'] else '🔴'} {w['name']} (ID: {w['id']})" for w in wfs]
                return "🔗 Workflows n8n:\n" + "\n".join(lines)
            return "🔗 No hay workflows en n8n"
        elif action == "trigger":
            return f"🔗 Webhook '{result.get('webhook', '')}' ejecutado → Status {result.get('status', '?')}"
        return json.dumps(result)
    elif skill == "modelos":
        if result.get("error"):
            return f"🧠 {result['error']}"
        models = result.get("models", [])
        lines = [f"  🤖 {m['name']} — {m['params']} ({m['size_gb']}GB, {m['family']}, {m['quant']})" for m in models]
        recs = "\n".join(result.get("recommendations", []))
        return f"🧠 Modelos instalados:\n" + "\n".join(lines) + f"\n\n💾 RAM: {result.get('ram_free_gb')}GB libre / {result.get('ram_total_gb')}GB total\n{recs}"
    elif skill == "pull":
        if result.get("error"):
            return f"📥 Error: {result['error']}"
        return f"📥 Descargando modelo: {result.get('model', '')} — {result.get('result', '')}"
    return json.dumps(result)


# ── Conversation Endpoints ──
@app.get("/api/conversations")
async def list_conversations(user: dict = Depends(get_current_user)):
    convs = []
    for f in CONVERSATIONS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            convs.append({
                "id": data["id"],
                "title": data.get("title", "Sin título"),
                "model": data.get("model", ""),
                "message_count": len(data.get("messages", [])),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
            })
        except Exception:
            continue
    convs.sort(key=lambda c: c.get("updated_at", c.get("created_at", "")), reverse=True)
    return {"conversations": convs}

@app.post("/api/conversations")
async def create_conversation(user: dict = Depends(get_current_user)):
    conv_id = str(_uuid.uuid4())[:8]
    conv = {"id": conv_id, "title": "", "messages": [], "model": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()}
    _save_conversation(conv)
    return conv

@app.get("/api/conversations/{conv_id}")
async def get_conversation(conv_id: str, user: dict = Depends(get_current_user)):
    return _load_conversation(conv_id)

@app.delete("/api/conversations/{conv_id}")
async def delete_conversation(conv_id: str, user: dict = Depends(get_current_user)):
    path = _conv_path(conv_id)
    if path.exists():
        path.unlink()
    return {"status": "deleted", "id": conv_id}


# ── File Upload ──
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", f"{DATA_DIR}/uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_MAX_SIZE = 5 * 1024 * 1024  # 5MB
UPLOAD_ALLOWED_EXT = {".txt", ".csv", ".json", ".py", ".md", ".log", ".yaml", ".yml", ".sh", ".sql", ".xml", ".html", ".pdf", ".docx", ".xlsx", ".conf", ".cfg", ".ini", ".toml", ".png", ".jpg", ".jpeg", ".gif", ".svg"}


@app.post("/api/openclaw/upload")
async def upload_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """Upload a file to HP_Disco/uploads/ for OpenClaw to analyze."""
    import re as _re_upload
    # Sanitize filename
    safe_name = _re_upload.sub(r'[^\w\-.]', '_', file.filename or "upload")
    ext = Path(safe_name).suffix.lower()
    if ext not in UPLOAD_ALLOWED_EXT:
        raise HTTPException(400, f"Extensión '{ext}' no permitida.")

    # Read with size limit
    content = await file.read()
    if len(content) > UPLOAD_MAX_SIZE:
        raise HTTPException(400, f"Archivo muy grande ({len(content)/1e6:.1f}MB). Máximo: 5MB.")

    # Add timestamp to avoid collisions
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_name = f"{ts}_{safe_name}"
    dest = UPLOAD_DIR / final_name
    dest.write_bytes(content)

    return {
        "status": "uploaded",
        "path": str(dest),
        "filename": final_name,
        "size": len(content),
        "analyze_cmd": f"analizar {dest}",
        "read_cmd": f"leer {dest}",
    }


# ── Learned Skills Endpoints ──
@app.get("/api/openclaw/skills")
async def list_skills(user: dict = Depends(get_current_user)):
    """List native + learned skills."""
    native = [
        {"id": "native_clima", "trigger": "clima en [ciudad]", "action": "Consulta wttr.in", "type": "native"},
        {"id": "native_noticias", "trigger": "noticias / noticias: temas", "action": "Google News RSS", "type": "native"},
        {"id": "native_buscar", "trigger": "busca [archivo]", "action": "find en HP_Disco", "type": "native"},
        {"id": "native_disco", "trigger": "disco / espacio", "action": "df -h", "type": "native"},
        {"id": "native_ejecutar", "trigger": "ejecuta [cmd]", "action": "Comandos seguros", "type": "native"},
    ]
    learned = _load_learned_skills()
    for s in learned:
        s["type"] = "learned"
    return {"native": native, "learned": learned}


class LearnSkillRequest(BaseModel):
    trigger: str
    action: str
    conversation_id: Optional[str] = None


@app.post("/api/openclaw/learn")
async def learn_skill(body: LearnSkillRequest, user: dict = Depends(get_current_user)):
    """Save a new learned skill."""
    skills = _load_learned_skills()
    new_skill = {
        "id": f"sk_{str(_uuid.uuid4())[:6]}",
        "trigger": body.trigger,
        "action": body.action,
        "learned_from": body.conversation_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "success_count": 1,
    }
    skills.append(new_skill)
    _save_learned_skills(skills)
    return {"status": "learned", "skill": new_skill}


@app.delete("/api/openclaw/skills/{skill_id}")
async def delete_skill(skill_id: str, user: dict = Depends(get_current_user)):
    """Delete a learned skill."""
    skills = _load_learned_skills()
    skills = [s for s in skills if s.get("id") != skill_id]
    _save_learned_skills(skills)
    return {"status": "deleted", "id": skill_id}


# ============================================================================
# Orchestrator — Multi-Agent Pipeline Engine
# ============================================================================

# ── Orchestrator Pydantic Models ──

class OrchestratorStep(BaseModel):
    id: str = ""
    type: str  # ollama_chat, gemini_chat, create_file, execute_cmd, n8n_webhook, condition
    label: str = ""
    config: dict = {}  # model, prompt, path, content, command, webhook_url, condition


class OrchestratorPipeline(BaseModel):
    id: str = ""
    name: str
    description: str = ""
    steps: list[OrchestratorStep] = []
    created_at: str = ""
    updated_at: str = ""


class RunStepRequest(BaseModel):
    type: str
    config: dict = {}


# ── Orchestrator Storage ──

PIPELINES_DIR = Path(os.getenv("PIPELINES_DIR", "/app/data/pipelines"))
PIPELINES_DIR.mkdir(parents=True, exist_ok=True)


def _pipeline_path(pid: str) -> Path:
    """Return the JSON file path for a pipeline by ID."""
    return PIPELINES_DIR / f"{pid}.json"


def _load_pipeline(pid: str) -> dict:
    """Load a pipeline from disk. Returns dict or raises HTTPException(404)."""
    path = _pipeline_path(pid)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Pipeline {pid} not found")
    return json.loads(path.read_text())


def _save_pipeline(pipeline_dict: dict):
    """Persist a pipeline dict to disk as JSON."""
    path = _pipeline_path(pipeline_dict["id"])
    path.write_text(json.dumps(pipeline_dict, ensure_ascii=False, indent=2))


def _list_pipelines() -> list[dict]:
    """List all saved pipelines with summary info."""
    pipelines = []
    for f in PIPELINES_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            pipelines.append({
                "id": data.get("id", f.stem),
                "name": data.get("name", "Untitled"),
                "description": data.get("description", ""),
                "step_count": len(data.get("steps", [])),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
            })
        except Exception:
            continue
    pipelines.sort(key=lambda p: p.get("updated_at", p.get("created_at", "")), reverse=True)
    return pipelines


# ── Orchestrator Step Executor ──

async def execute_step(step_type: str, config: dict, step_outputs: dict) -> str:
    """Execute a single pipeline step and return its output string."""

    # ── Variable interpolation ──
    def _interpolate(cfg: dict) -> dict:
        interpolated = {}
        for k, v in cfg.items():
            if isinstance(v, str):
                # Replace {{step_N.output}} with actual outputs
                def _replace_match(m):
                    idx = int(m.group(1))
                    return step_outputs.get(idx, f"[step_{idx}_no_output]")
                interpolated[k] = _re.sub(r"\{\{step_(\d+)\.output\}\}", _replace_match, v)
            else:
                interpolated[k] = v
        return interpolated

    config = _interpolate(config)

    # ── ollama_chat ──
    if step_type == "ollama_chat":
        model = config.get("model", "llama3.2:1b")
        prompt = config.get("prompt", "")
        if not prompt:
            return "Error: No prompt provided for ollama_chat"
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "No response from Ollama")

    # ── gemini_chat ──
    elif step_type == "gemini_chat":
        if not GEMINI_AVAILABLE or not GEMINI_API_KEY:
            return "Error: Gemini is not available (missing library or API key)"
        model_name = config.get("model", "gemini-2.5-flash")
        prompt = config.get("prompt", "")
        if not prompt:
            return "Error: No prompt provided for gemini_chat"
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        return response.text

    # ── create_file ──
    elif step_type == "create_file":
        filepath = config.get("path", "")
        content = config.get("content", "")
        if not filepath:
            return "Error: No path provided for create_file"
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"File created: {filepath}"

    # ── execute_cmd ──
    elif step_type == "execute_cmd":
        command = config.get("command", "")
        if not command:
            return "Error: No command provided for execute_cmd"
        safe_commands = [
            "ls", "cat", "head", "tail", "wc", "grep", "find", "echo",
            "date", "uptime", "free", "df", "whoami", "hostname", "uname",
            "pwd", "mkdir", "touch",
        ]
        first_word = command.strip().split()[0]
        if first_word not in safe_commands:
            return f"Error: Command '{first_word}' not in whitelist. Allowed: {', '.join(safe_commands)}"
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30,
        )
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr.strip():
            output += f"\nSTDERR: {result.stderr.strip()}"
        return output or "(no output)"

    # ── n8n_webhook ──
    elif step_type == "n8n_webhook":
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            return "Error: No webhook_url provided for n8n_webhook"
        payload = config.get("payload", {})
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(webhook_url, json=payload)
            return resp.text[:2000]

    # ── condition ──
    elif step_type == "condition":
        check_val = str(config.get("check", ""))
        equals_val = str(config.get("equals", ""))
        return "true" if check_val == equals_val else "false"

    else:
        return f"Error: Unknown step type '{step_type}'"


# ── Orchestrator Endpoints ──

@app.get("/api/orchestrator/pipelines")
async def list_orchestrator_pipelines(user: dict = Depends(get_current_user)):
    """List all saved pipelines."""
    return {"pipelines": _list_pipelines()}


@app.post("/api/orchestrator/pipelines")
async def create_orchestrator_pipeline(pipeline: OrchestratorPipeline, user: dict = Depends(get_current_user)):
    """Create a new pipeline."""
    now = datetime.now(timezone.utc).isoformat()
    pipeline_dict = pipeline.model_dump()
    pipeline_dict["id"] = str(_uuid.uuid4())
    pipeline_dict["created_at"] = now
    pipeline_dict["updated_at"] = now
    # Auto-generate step IDs if empty
    for step in pipeline_dict.get("steps", []):
        if not step.get("id"):
            step["id"] = f"step_{str(_uuid.uuid4())[:8]}"
    _save_pipeline(pipeline_dict)
    logger.info("User %s created pipeline %s (%s)", user.get("sub"), pipeline_dict["id"], pipeline_dict["name"])
    return pipeline_dict


@app.get("/api/orchestrator/pipelines/{pipeline_id}")
async def get_orchestrator_pipeline(pipeline_id: str, user: dict = Depends(get_current_user)):
    """Get a pipeline by ID."""
    return _load_pipeline(pipeline_id)


@app.put("/api/orchestrator/pipelines/{pipeline_id}")
async def update_orchestrator_pipeline(pipeline_id: str, pipeline: OrchestratorPipeline, user: dict = Depends(get_current_user)):
    """Update an existing pipeline."""
    # Ensure it exists
    _load_pipeline(pipeline_id)
    pipeline_dict = pipeline.model_dump()
    pipeline_dict["id"] = pipeline_id
    pipeline_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
    # Preserve created_at from existing
    try:
        existing = json.loads(_pipeline_path(pipeline_id).read_text())
        pipeline_dict["created_at"] = existing.get("created_at", pipeline_dict["updated_at"])
    except Exception:
        pipeline_dict["created_at"] = pipeline_dict["updated_at"]
    # Auto-generate step IDs if empty
    for step in pipeline_dict.get("steps", []):
        if not step.get("id"):
            step["id"] = f"step_{str(_uuid.uuid4())[:8]}"
    _save_pipeline(pipeline_dict)
    logger.info("User %s updated pipeline %s", user.get("sub"), pipeline_id)
    return pipeline_dict


@app.delete("/api/orchestrator/pipelines/{pipeline_id}")
async def delete_orchestrator_pipeline(pipeline_id: str, user: dict = Depends(get_current_user)):
    """Delete a pipeline."""
    path = _pipeline_path(pipeline_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Pipeline {pipeline_id} not found")
    path.unlink()
    logger.info("User %s deleted pipeline %s", user.get("sub"), pipeline_id)
    return {"status": "deleted"}


@app.post("/api/orchestrator/run/{pipeline_id}")
async def run_orchestrator_pipeline(pipeline_id: str, user: dict = Depends(get_current_user)):
    """Execute a pipeline with SSE streaming of step results."""
    pipeline_data = _load_pipeline(pipeline_id)
    steps = pipeline_data.get("steps", [])

    async def event_generator():
        step_outputs: dict[int, str] = {}
        successful = 0
        failed = 0
        pipeline_start = time.time()

        for idx, step in enumerate(steps):
            step_id = step.get("id", f"step_{idx}")
            step_type = step.get("type", "unknown")
            step_label = step.get("label", step_type)
            step_config = step.get("config", {})

            # Emit running event
            yield f"data: {json.dumps({'step_id': step_id, 'step_index': idx, 'status': 'running', 'type': step_type, 'label': step_label})}\n\n"

            step_start = time.time()
            try:
                output = await execute_step(step_type, step_config, step_outputs)
                duration = round(time.time() - step_start, 3)
                step_outputs[idx] = output
                successful += 1
                yield f"data: {json.dumps({'step_id': step_id, 'step_index': idx, 'status': 'success', 'output': output[:5000], 'duration': duration})}\n\n"
            except Exception as exc:
                duration = round(time.time() - step_start, 3)
                error_msg = str(exc)
                step_outputs[idx] = f"ERROR: {error_msg}"
                failed += 1
                yield f"data: {json.dumps({'step_id': step_id, 'step_index': idx, 'status': 'error', 'error': error_msg[:2000], 'duration': duration})}\n\n"
                # Continue to next step — don't abort

        total_duration = round(time.time() - pipeline_start, 3)
        yield f"data: {json.dumps({'status': 'pipeline_complete', 'total_steps': len(steps), 'successful': successful, 'failed': failed, 'total_duration': total_duration})}\n\n"

    logger.info("User %s running pipeline %s (%s)", user.get("sub"), pipeline_id, pipeline_data.get("name", ""))
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/orchestrator/step")
async def run_single_step(body: RunStepRequest, user: dict = Depends(get_current_user)):
    """Execute a single step for testing purposes."""
    step_start = time.time()
    try:
        output = await execute_step(body.type, body.config, {})
        duration = round(time.time() - step_start, 3)
        return {"status": "success", "output": output, "duration": duration}
    except Exception as exc:
        duration = round(time.time() - step_start, 3)
        return {"status": "error", "error": str(exc), "duration": duration}


# ── Ollama Models ──
@app.get("/api/ollama/models")
async def ollama_models():
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            return resp.json()
        except httpx.ConnectError:
            return {"models": [], "error": "Ollama is not running", "ollama_available": False}
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Ollama error: {exc}")


# ── Ollama Running Models (ps) ──
@app.get("/api/ollama/ps")
async def ollama_running_models():
    """List models currently loaded in Ollama memory (VRAM/RAM)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/ps")
            data = resp.json()
            models = data.get("models", [])
            result = []
            for m in models:
                size_bytes = m.get("size", 0)
                size_gb = round(size_bytes / (1024**3), 2)
                result.append({
                    "name": m.get("name", "?"),
                    "model": m.get("model", "?"),
                    "size_bytes": size_bytes,
                    "size_gb": size_gb,
                    "digest": m.get("digest", "")[:12],
                    "expires_at": m.get("expires_at", ""),
                    "details": m.get("details", {}),
                    "size_vram": m.get("size_vram", 0),
                })
            return {"models": result, "count": len(result)}
        except httpx.ConnectError:
            return {"models": [], "count": 0, "error": "Ollama is not running"}
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Ollama error: {exc}")


class OllamaUnloadRequest(BaseModel):
    model: str


@app.post("/api/ollama/unload")
async def ollama_unload_model(body: OllamaUnloadRequest, user: dict = Depends(get_current_user)):
    """Unload a model from Ollama memory by sending keep_alive=0."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Send a generate request with keep_alive=0 to unload the model
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={"model": body.model, "keep_alive": 0},
            )
            if resp.status_code == 200:
                logger.info("User %s unloaded model %s", user.get("sub"), body.model)
                return {"status": "unloaded", "model": body.model, "message": f"Modelo {body.model} liberado de memoria"}
            else:
                return {"status": "error", "model": body.model, "message": f"Error: {resp.text[:200]}"}
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="Ollama is not running")
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Ollama error: {exc}")


@app.post("/api/ollama/unload-all")
async def ollama_unload_all(user: dict = Depends(get_current_user)):
    """Unload ALL models from Ollama memory."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # First get the list of running models
            ps_resp = await client.get(f"{OLLAMA_BASE_URL}/api/ps")
            ps_data = ps_resp.json()
            models = ps_data.get("models", [])

            if not models:
                return {"status": "ok", "message": "No hay modelos cargados en memoria", "unloaded": []}

            unloaded = []
            errors = []
            for m in models:
                model_name = m.get("name", m.get("model", ""))
                if not model_name:
                    continue
                try:
                    resp = await client.post(
                        f"{OLLAMA_BASE_URL}/api/generate",
                        json={"model": model_name, "keep_alive": 0},
                    )
                    if resp.status_code == 200:
                        unloaded.append(model_name)
                    else:
                        errors.append(f"{model_name}: {resp.text[:100]}")
                except Exception as e:
                    errors.append(f"{model_name}: {str(e)}")

            logger.info("User %s unloaded all models: %s", user.get("sub"), unloaded)
            return {
                "status": "ok",
                "message": f"{len(unloaded)} modelo(s) liberado(s) de memoria",
                "unloaded": unloaded,
                "errors": errors,
            }
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="Ollama is not running")
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Ollama error: {exc}")


class OllamaPullRequest(BaseModel):
    model: str


@app.post("/api/ollama/pull")
async def ollama_pull_model(body: OllamaPullRequest, user: dict = Depends(get_current_user)):
    """Pull (download) a model with streaming progress."""
    allowed_models = [
        "llama3.2:1b", "llama3.2:3b", "qwen2.5:0.5b", "qwen2.5:1.5b",
        "qwen2.5-coder:1.5b", "qwen2.5-coder:0.5b", "gemma2:2b",
        "phi3:mini", "tinyllama:latest"
    ]
    if body.model not in allowed_models:
        raise HTTPException(
            status_code=400,
            detail=f"Modelo no permitido. Disponibles: {', '.join(allowed_models)}"
        )

    logger.info("User %s pulling model %s", user.get("sub"), body.model)

    async def pull_generator():
        async with httpx.AsyncClient(timeout=600.0) as client:
            try:
                async with client.stream(
                    "POST",
                    f"{OLLAMA_BASE_URL}/api/pull",
                    json={"name": body.model, "stream": True},
                ) as resp:
                    async for line in resp.aiter_lines():
                        if line.strip():
                            try:
                                chunk = json.loads(line)
                                # Ollama sends: status, digest, total, completed
                                progress_data = {
                                    "status": chunk.get("status", ""),
                                    "digest": chunk.get("digest", ""),
                                    "total": chunk.get("total", 0),
                                    "completed": chunk.get("completed", 0),
                                }
                                if progress_data["total"] > 0:
                                    progress_data["percent"] = round(
                                        (progress_data["completed"] / progress_data["total"]) * 100, 1
                                    )
                                else:
                                    progress_data["percent"] = 0
                                yield f"data: {json.dumps(progress_data)}\n\n"
                            except json.JSONDecodeError:
                                pass
            except httpx.ConnectError:
                yield f'data: {{"status": "error", "error": "Ollama is not running"}}\n\n'
            except Exception as exc:
                yield f'data: {{"status": "error", "error": "{exc}"}}\n\n'

        yield f'data: {{"status": "done", "model": "{body.model}", "done": true}}\n\n'

    return StreamingResponse(
        pull_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


# ── Unified Chat Endpoint ──
class OpenClawChatRequest(BaseModel):
    model: str = "llama3.2:1b"
    messages: list[dict]
    stream: bool = True
    options: Optional[dict] = None
    conversation_id: Optional[str] = None


@app.post("/api/openclaw/chat")
async def openclaw_unified_chat(body: OpenClawChatRequest):
    """Unified OpenClaw chat — detects skills first, then falls back to Llama with full memory."""

    conv_id = body.conversation_id or str(_uuid.uuid4())[:8]
    conv = _load_conversation(conv_id)
    user_msg = body.messages[-1]["content"] if body.messages else ""

    # Save user message
    conv["messages"].append({"role": "user", "content": user_msg})
    conv["model"] = body.model
    conv["updated_at"] = datetime.now(timezone.utc).isoformat()
    if not conv.get("title") and user_msg:
        conv["title"] = user_msg[:50] + ("..." if len(user_msg) > 50 else "")

    # 1. Try native skills first
    skill_result = await _detect_and_run_skill(user_msg)
    if skill_result:
        if skill_result.get("skill") == "learn_trigger":
            # Extract last assistant message to learn from
            last_msgs = [m for m in conv.get("messages", []) if m["role"] == "assistant"]
            if last_msgs:
                skill_result = {"skill": "learn_prompt", "last_response": last_msgs[-1]["content"][:200]}
            else:
                skill_result = {"skill": "learn_prompt", "error": "No hay respuesta anterior para aprender"}

        # Format skill result as assistant message
        formatted = _format_skill_as_message(skill_result)
        conv["messages"].append({"role": "assistant", "content": formatted})
        _save_conversation(conv)
        return {"type": "skill", "conversation_id": conv_id, **skill_result}

    # 2. Not a skill → route to best AI
    system_prompt = _build_system_prompt()

    # Determine which AI to use
    use_gemini = False
    gemini_model = "gemini-2.0-flash"

    # Force Gemini with @gemini prefix
    if user_msg.lower().startswith("@gemini"):
        user_msg_clean = user_msg[7:].strip()
        conv["messages"][-1]["content"] = user_msg_clean  # update saved msg
        body.messages[-1]["content"] = user_msg_clean
        use_gemini = True
        # Pick model from prefix
        if user_msg.lower().startswith("@gemini-pro"):
            gemini_model = "gemini-2.5-pro"
            user_msg_clean = user_msg[11:].strip()
            conv["messages"][-1]["content"] = user_msg_clean
            body.messages[-1]["content"] = user_msg_clean
        elif user_msg.lower().startswith("@gemini-nano") or user_msg.lower().startswith("@gemini-lite"):
            gemini_model = "gemini-2.0-flash-lite"
            user_msg_clean = user_msg[12:].strip()
            conv["messages"][-1]["content"] = user_msg_clean
            body.messages[-1]["content"] = user_msg_clean
    # Force Llama with @llama prefix
    elif user_msg.lower().startswith("@llama"):
        user_msg_clean = user_msg[6:].strip()
        conv["messages"][-1]["content"] = user_msg_clean
        body.messages[-1]["content"] = user_msg_clean
        use_gemini = False
    # Auto-detect: use Gemini for complex queries
    elif GEMINI_AVAILABLE and GEMINI_API_KEY:
        msg_len = len(user_msg)
        complex_keywords = ["explica", "analiza", "compara", "resume", "genera", "escribe", "código", "codigo", "programa", "script", "plan", "estrategia", "informe", "reporte", "investiga", "traduce", "corrige"]
        is_complex = msg_len > 100 or any(kw in user_msg.lower() for kw in complex_keywords)
        if is_complex:
            use_gemini = True

    # Route to Gemini
    if use_gemini and GEMINI_AVAILABLE and GEMINI_API_KEY:
        try:
            model = genai.GenerativeModel(
                model_name=gemini_model,
                system_instruction=system_prompt,
            )
            # Build history for Gemini
            history = conv.get("messages", [])[:-1]
            if len(history) > 20:
                history = history[-20:]
            gemini_history = []
            for m in history:
                role = "model" if m["role"] == "assistant" else "user"
                gemini_history.append({"role": role, "parts": [m["content"]]})

            chat = model.start_chat(history=gemini_history)
            gemini_resp = chat.send_message(body.messages[-1]["content"])
            response_text = gemini_resp.text

            conv["messages"].append({"role": "assistant", "content": response_text})
            _save_conversation(conv)

            return JSONResponse(content={
                "type": "ai",
                "provider": "gemini",
                "model": gemini_model,
                "conversation_id": conv_id,
                "message": {"role": "assistant", "content": response_text},
                "done": True,
            })
        except Exception as e:
            logger.warning(f"Gemini failed, falling back to Llama: {e}")
            # Fall through to Llama

    # 3. Llama (local) — default or fallback
    full_messages = [{"role": "system", "content": system_prompt}]
    # Include conversation history (limit to last 40 messages for context window)
    history = conv.get("messages", [])[:-1]  # exclude the just-added user msg
    if len(history) > 40:
        history = history[-40:]
    full_messages.extend(history)
    full_messages.extend(body.messages)

    payload = {
        "model": body.model,
        "messages": full_messages,
        "stream": body.stream,
    }
    if body.options:
        payload["options"] = body.options

    if not body.stream:
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
                data = resp.json()
                if "message" in data:
                    conv["messages"].append(data["message"])
                _save_conversation(conv)
                return {"type": "ai", "provider": "llama", "conversation_id": conv_id, **data}
            except httpx.ConnectError:
                raise HTTPException(status_code=502, detail="Ollama is not running")
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"Ollama error: {exc}")

    # Streaming (Llama only — Gemini responses are non-streaming above)
    collected_response = []

    async def event_generator():
        async with httpx.AsyncClient(timeout=300.0) as client:
            try:
                async with client.stream("POST", f"{OLLAMA_BASE_URL}/api/chat", json=payload) as resp:
                    async for line in resp.aiter_lines():
                        if line.strip():
                            try:
                                chunk = json.loads(line)
                                token = chunk.get("message", {}).get("content", "")
                                if token:
                                    collected_response.append(token)
                            except Exception:
                                pass
                            yield f"data: {line}\n\n"
            except httpx.ConnectError:
                yield f'data: {{"error": "Ollama is not running"}}\n\n'
            except Exception as exc:
                yield f'data: {{"error": "{exc}"}}\n\n'

        if collected_response:
            conv["messages"].append({"role": "assistant", "content": "".join(collected_response)})
        _save_conversation(conv)
        yield f'data: {{"conversation_id": "{conv_id}", "type": "ai", "provider": "llama", "done": true, "saved": true}}\n\n'

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


# Keep old endpoint for backwards compatibility
@app.post("/api/ollama/chat")
async def ollama_chat_compat(body: OpenClawChatRequest):
    """Backwards-compatible endpoint — redirects to unified chat."""
    return await openclaw_unified_chat(body)



# ---------------------------------------------------------------------------
# WebSocket Terminal (PTY)
# ---------------------------------------------------------------------------
@app.websocket("/api/terminal")
async def websocket_terminal(websocket: WebSocket):
    """
    Spawn a real bash shell via pty and relay I/O over WebSocket.
    
    Protocol:
    - Text messages → stdin to the shell
    - JSON messages with type "resize" → resize the pty
    - Binary messages → raw stdin bytes
    - Server sends text output from the shell back to the client
    """
    # Authenticate via query param or first message
    token = websocket.query_params.get("token", "")
    if token:
        try:
            verify_jwt_token(token)
        except HTTPException:
            await websocket.close(code=4001, reason="Invalid token")
            return
    else:
        await websocket.close(code=4001, reason="Token required")
        return

    await websocket.accept()
    logger.info("Terminal WebSocket connected")

    # Spawn PTY
    master_fd, slave_fd = pty.openpty()

    shell = os.environ.get("SHELL", "/bin/bash")
    pid = os.fork()

    if pid == 0:
        # Child process — become the shell
        os.close(master_fd)
        os.setsid()

        # Set the slave as controlling terminal
        import fcntl
        fcntl.ioctl(slave_fd, termios_TIOCSCTTY(), 0)

        # Redirect stdio
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        if slave_fd > 2:
            os.close(slave_fd)

        # Set reasonable environment
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["COLUMNS"] = "120"
        env["LINES"] = "40"

        os.execvpe(shell, [shell, "--login"], env)

    # Parent process
    os.close(slave_fd)
    logger.info("Spawned shell PID %d", pid)

    # Make master_fd non-blocking
    import fcntl
    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    async def read_pty_output():
        """Read from PTY master and send to WebSocket."""
        loop = asyncio.get_event_loop()
        try:
            while True:
                await asyncio.sleep(0.01)  # Small yield
                try:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if r:
                        data = os.read(master_fd, 4096)
                        if not data:
                            break
                        await websocket.send_text(data.decode("utf-8", errors="replace"))
                except OSError:
                    break
        except (WebSocketDisconnect, Exception):
            pass

    async def write_pty_input():
        """Read from WebSocket and write to PTY master."""
        try:
            while True:
                message = await websocket.receive()

                if message.get("type") == "websocket.disconnect":
                    break

                if "text" in message:
                    text = message["text"]

                    # Check for resize command
                    try:
                        cmd = json.loads(text)
                        if isinstance(cmd, dict) and cmd.get("type") == "resize":
                            cols = cmd.get("cols", 120)
                            rows = cmd.get("rows", 40)
                            winsize = struct.pack("HHHH", rows, cols, 0, 0)
                            import fcntl
                            import termios
                            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                            continue
                    except (json.JSONDecodeError, ValueError):
                        pass

                    os.write(master_fd, text.encode("utf-8"))

                elif "bytes" in message:
                    os.write(master_fd, message["bytes"])

        except (WebSocketDisconnect, Exception):
            pass

    # Run both tasks concurrently
    try:
        reader_task = asyncio.create_task(read_pty_output())
        writer_task = asyncio.create_task(write_pty_input())

        # Wait for either to complete (means connection dropped or shell exited)
        done, pending = await asyncio.wait(
            [reader_task, writer_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    finally:
        # Clean up
        try:
            os.close(master_fd)
        except OSError:
            pass

        try:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, os.WNOHANG)
        except (OSError, ChildProcessError):
            pass

        try:
            await websocket.close()
        except Exception:
            pass

        logger.info("Terminal WebSocket disconnected, shell PID %d cleaned up", pid)


def termios_TIOCSCTTY():
    """Get TIOCSCTTY constant cross-platform."""
    import termios
    # On Linux it's 0x540E, on macOS/BSD it's a different value
    # Using termios module which handles this portably
    try:
        return termios.TIOCSCTTY
    except AttributeError:
        # Fallback for Linux
        return 0x540E


# ---------------------------------------------------------------------------
# n8n Reverse Proxy — allows accessing n8n UI through Cloudflare Tunnel
# ---------------------------------------------------------------------------
N8N_PROXY_CLIENT = httpx.AsyncClient(
    base_url=N8N_BASE_URL.rstrip("/"),
    timeout=30,
    follow_redirects=True,
    limits=httpx.Limits(max_connections=20),
)


@app.api_route("/rest/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def n8n_rest_proxy(path: str, request: Request):
    """Proxy n8n REST API calls. n8n frontend calls /rest/* directly."""
    return await _proxy_to_n8n(f"rest/{path}", request)


@app.api_route("/n8n-proxy/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def n8n_proxy(path: str, request: Request):
    """Reverse proxy to n8n UI. Auth is handled by AuthMiddleware via cookie."""
    return await _proxy_to_n8n(path, request)


async def _proxy_to_n8n(path: str, request: Request):
    """Shared proxy logic for both /n8n-proxy/* and /rest/* routes."""
    target_url = f"/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    fwd_headers = {}
    for k, v in request.headers.items():
        if k.lower() not in ("host", "cookie", "authorization", "connection", "accept-encoding"):
            fwd_headers[k] = v
    fwd_headers["host"] = N8N_BASE_URL.split("://", 1)[-1].split("/")[0]
    fwd_headers["accept-encoding"] = "identity"

    body = await request.body()

    try:
        resp = await N8N_PROXY_CLIENT.request(
            method=request.method,
            url=target_url,
            headers=fwd_headers,
            content=body if body else None,
        )
    except Exception as e:
        return HTMLResponse(
            content=f"<html><body style='background:#0a0a0f;color:#fff;font-family:sans-serif;padding:40px;'>"
            f"<h2>Error: n8n no disponible</h2><p>{e}</p>"
            f"<a href='/' style='color:#00f2ff;'>&larr; Volver</a></body></html>",
            status_code=502,
        )

    # Build response headers
    resp_headers = {}
    for k, v in resp.headers.items():
        if k.lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection"):
            resp_headers[k] = v
    # Remove X-Frame-Options so n8n can render
    resp_headers.pop("x-frame-options", None)
    resp_headers.pop("X-Frame-Options", None)

    content = resp.content
    content_type = resp.headers.get("content-type", "")

    # Rewrite paths in HTML responses
    if "text/html" in content_type:
        text = content.decode("utf-8", errors="replace")
        text = text.replace('href="/', 'href="/n8n-proxy/')
        text = text.replace("href='/", "href='/n8n-proxy/")
        text = text.replace('src="/', 'src="/n8n-proxy/')
        text = text.replace("src='/", "src='/n8n-proxy/")
        text = text.replace('action="/', 'action="/n8n-proxy/')
        text = text.replace("action='/", "action='/n8n-proxy/")
        content = text.encode("utf-8")

    # Rewrite BASE_PATH in JavaScript responses (base-path.js)
    elif "javascript" in content_type or "application/js" in content_type or path.endswith(".js"):
        text = content.decode("utf-8", errors="replace")
        text = text.replace("window.BASE_PATH = '/';", "window.BASE_PATH = '/n8n-proxy/';")
        text = text.replace("window.BASE_PATH = '/'", "window.BASE_PATH = '/n8n-proxy/'")
        content = text.encode("utf-8")

    # Rewrite redirect Location headers
    location = resp_headers.get("location") or resp_headers.get("Location")
    if location and location.startswith("/"):
        resp_headers["location"] = f"/n8n-proxy{location}"

    return Response(
        content=content,
        status_code=resp.status_code,
        headers=resp_headers,
        media_type=content_type.split(";")[0] if content_type else None,
    )


# ---------------------------------------------------------------------------
# Static Files (Frontend) — must be last
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    """Mount frontend static files if the directory exists."""
    if os.path.isdir(FRONTEND_DIR):
        app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
        logger.info("Serving frontend from %s", FRONTEND_DIR)
    else:
        logger.warning(
            "Frontend directory %s not found — skipping static file serving",
            FRONTEND_DIR,
        )

    logger.info("HP Command Center started")
    logger.info("JWT Secret: %s...", JWT_SECRET[:8])
    logger.info("Google Client ID: %s", GOOGLE_CLIENT_ID[:20] + "..." if GOOGLE_CLIENT_ID else "NOT SET")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("ENV", "production") == "development",
        log_level="info",
    )
