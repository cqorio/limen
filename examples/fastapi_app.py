"""FastAPI wiring. Needs the extra: pip install 'limen[fastapi]'. Run: uvicorn examples.fastapi_app:app

The middleware enforces pre-request and observes post-response. Pass your own `client_ip` / `identity`
ports (see limen.core.ports) to key rules on the real client IP and the authenticated account.
"""
from fastapi import FastAPI

from limen import Limen, Mode
from limen.adapters import LimenMiddleware, MemoryStore

app = FastAPI()

limen = Limen(MemoryStore(), config={"enumeration": Mode.ENFORCE, "sequence_anomaly": Mode.SHADOW})
app.add_middleware(LimenMiddleware, limen=limen)  # + client_ip=..., identity=... in a real app


@app.get("/api/me")
def me():
    return {"ok": True}
