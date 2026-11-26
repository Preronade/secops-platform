import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

HARDEN = os.getenv("HARDEN", "0") == "1"
SENSITIVE = {"configprops", "httptrace", "threaddump", "mappings", "beans", "loggers", "metrics"}

app = FastAPI(title="Demo actuator target (stand-in, NOT real Spring Boot)")


@app.middleware("http")
async def add_headers(request: Request, call_next):
    resp = await call_next(request)
    if HARDEN:
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
    else:
        resp.headers["X-Powered-By"] = "Spring Boot 2.5.0 (demo)"
    return resp


def unauthorized():
    return JSONResponse({"error": "unauthorized"}, status_code=401)


@app.get("/")
def root():
    return {"app": "demo"}


@app.get("/actuator/health")
def health():
    return {"status": "UP"}


@app.get("/actuator")
def index():
    links = ["health"] if HARDEN else ["health", "env", "heapdump", *sorted(SENSITIVE)]
    return {"_links": {name: {"href": f"/actuator/{name}"} for name in links}}


@app.get("/actuator/env")
def env():
    if HARDEN:
        return unauthorized()
    return {"propertySources": [{"name": "demo", "properties": {
        "spring.datasource.password": {"value": "demo-not-a-real-secret"}}}]}


@app.get("/actuator/heapdump")
def heapdump():
    if HARDEN:
        return unauthorized()
    return Response(content=b"DEMO-HEAPDUMP", media_type="application/octet-stream")


@app.get("/actuator/{name}")
def other(name: str):
    if name not in SENSITIVE:
        return JSONResponse({"error": "not found"}, status_code=404)
    if HARDEN:
        return unauthorized()
    return {"demo": name}
