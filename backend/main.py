import asyncio
import uuid
from datetime import datetime
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.models import ScanConfig, ScanResult, ScanProgress, ScanStatus
from app.scanner.engine import scan_engine

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Professional Web Vulnerability Scanner",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store WebSocket connections
ws_connections: dict[str, WebSocket] = {}

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": settings.APP_NAME, "version": settings.VERSION}

@app.post("/api/scan", response_model=ScanResult)
async def start_scan(config: ScanConfig):
    scan_id = str(uuid.uuid4())

    async def ws_progress(progress: ScanProgress):
        if scan_id in ws_connections:
            await ws_connections[scan_id].send_json(progress.model_dump())

    # Start scan in background
    asyncio.create_task(scan_engine.run_scan(config, scan_id, ws_progress))

    # Return initial result
    return ScanResult(
        scan_id=scan_id,
        target=str(config.target),
        status=ScanStatus.PENDING,
        started_at=datetime.utcnow(),
        config=config,
        vulnerabilities=[],
        stats={}
    )

@app.get("/api/scan/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    result = scan_engine.get_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@app.get("/api/scans", response_model=List[ScanResult])
async def get_scan_history():
    return scan_engine.get_history()

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id in scan_engine.active_scans:
        del scan_engine.active_scans[scan_id]
        if scan_id in ws_connections:
            del ws_connections[scan_id]
    return {"message": "Scan deleted"}

@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    ws_connections[scan_id] = websocket

    try:
        # Send current status if scan exists
        result = scan_engine.get_result(scan_id)
        if result:
            await websocket.send_json(ScanProgress(
                scan_id=scan_id,
                status=result.status,
                progress_percent=100 if result.status in (ScanStatus.COMPLETED, ScanStatus.FAILED) else 0,
                message="Connected to scan stream",
                vulnerabilities_found=len(result.vulnerabilities)
            ).model_dump())

        while True:
            # Keep connection alive, wait for client messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        if scan_id in ws_connections:
            del ws_connections[scan_id]
    except Exception:
        if scan_id in ws_connections:
            del ws_connections[scan_id]

@app.get("/api/scan/{scan_id}/export/json")
async def export_json(scan_id: str):
    result = scan_engine.get_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=result.model_dump())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
