from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List
import json
from models import SafetySentinelModel, SafetySentinelSession, TelemetryPacket, TelemetryResult


app = FastAPI(title="ResqBand Safety Sentinel API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory sessions
sessions: Dict[str, SafetySentinelSession] = {}
clients: Dict[str, List[WebSocket]] = {}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ResqBand API"}


@app.post("/api/telemetry", response_model=TelemetryResult)
async def process_telemetry(packet: TelemetryPacket):
    session_id = packet.session_id
    if session_id not in sessions:
        sessions[session_id] = SafetySentinelSession(model=SafetySentinelModel())

    session = sessions[session_id]
    result = session.model.process_telemetry(packet)
    session.history.append(result)

    # Broadcast to WS clients
    if session_id in clients:
        message = json.dumps({
            "type": "telemetry",
            "data": result.dict(),
            "session_id": session_id
        })
        for client in clients[session_id][:]:
            try:
                await client.send_text(message)
            except:
                clients[session_id].remove(client)

    return result


@app.get("/api/sessions/{session_id}/history")
async def get_history(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return {"error": "Session not found"}
    return {"history": [r.dict() for r in session.history[-50:]]}  # Last 50


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()
    if session_id not in clients:
        clients[session_id] = []
    clients[session_id].append(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            # Echo or handle client messages if needed
            await websocket.send_text(f"Connected to {session_id}")
    except WebSocketDisconnect:
        clients[session_id].remove(websocket)
        if not clients[session_id]:
            del clients[session_id]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
