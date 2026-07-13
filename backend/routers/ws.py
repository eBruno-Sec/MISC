from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from core.security import check_ws_key

router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self.connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, mission_id: str):
        await websocket.accept()
        if mission_id not in self.connections:
            self.connections[mission_id] = []
        self.connections[mission_id].append(websocket)

    def disconnect(self, websocket: WebSocket, mission_id: str):
        if mission_id in self.connections:
            try:
                self.connections[mission_id].remove(websocket)
            except ValueError:
                pass

    async def broadcast(self, mission_id: str, data: dict):
        if mission_id not in self.connections:
            return
        dead = []
        for ws in self.connections[mission_id]:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, mission_id)


manager = ConnectionManager()


@router.websocket("/{mission_id}")
async def websocket_endpoint(websocket: WebSocket, mission_id: str):
    if not await check_ws_key(websocket):
        await websocket.close(code=4401)
        return
    await manager.connect(websocket, mission_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, mission_id)
