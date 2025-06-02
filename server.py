import asyncio
from websockets.asyncio.server import broadcast, ServerConnection, serve
from users import USER_CREDENTIALS
from cryptography.fernet import Fernet
import uvicorn
KEY = b"6ruz07L563euMQnRSpdptyfz3KqHM3vlyDCXqExHPsA="


class ChatServer:
    def __init__(self, host="localhost", port=8765, debug=True):
        self.host = host
        self.port = port
        self.debug = debug
        self.connections = dict()  # websocket: username
        self.cipher = Fernet(KEY)

    async def authenticate(self, websocket: ServerConnection):
        try:
            encrypted_message = await websocket.recv()
            message = self.cipher.decrypt(encrypted_message).decode()
            if self.debug:
                print(f"Received authentication message: {message}")
            try:
                username, password = str(message).split(":")
            except Exception:
                print("Unable to parse username and password from the message")
                return False, None
            print(f"Authenticating user: {username}")
            if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
                print(f"Authenticated user: {username}")
                return True, username
            return False, None
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False, None

    async def e_send(self, message: str, websocket: ServerConnection | None = None):
        if websocket is None:
            return
        bytes_message = message.encode("utf-8")
        encrypted_message = self.cipher.encrypt(bytes_message)
        await websocket.send(encrypted_message)

    async def e_broadcast(self, message):
        if not self.connections:
            return
        bytes_message = message.encode("utf-8")
        encrypted_message = self.cipher.encrypt(bytes_message)
        _ = broadcast(self.connections.keys(), encrypted_message)

    async def echo(self, websocket: ServerConnection, username: str = ""):
        try:
            self.connections[websocket] = username
            print(
                f"New connection established from {websocket.remote_address[0]}. Connected users: {len(self.connections)}"
            )
            echo_message = f"[SERVER] - {username} joined. Connected users: {len(self.connections)}"
            await self.e_broadcast(echo_message)
            async for message in websocket:
                _ = broadcast(self.connections.keys(), message)
        finally:
            echo_message = f"[SERVER] - {username} left. Connected users: {len(self.connections) - 1}"
            print(
                f"Connection closed from {websocket.remote_address[0]}. Connected users: {len(self.connections) - 1}"
            )
            del self.connections[websocket]
            await self.e_broadcast(echo_message)

    async def handle_connection(self, websocket: ServerConnection):
        authenticated, username = await self.authenticate(websocket)
        if not authenticated:
            await websocket.close(code=1008, reason="Authentication failed")
            return
        await self.e_send("", websocket)
        await self.e_send(f"[SERVER] - Welcome to the chat server!", websocket)
        if type(username) is not str:
            username = "unknown"
        await self.echo(websocket, username)

    async def start(self):
        try:
            print(f"Starting server on ws://{self.host}:{self.port}...")
            async with serve(self.handle_connection, self.host, self.port) as server:
                await server.serve_forever()
        except KeyboardInterrupt:
            print("Server stopped by user.")
            _ = server.close()
            print("Server closed successfully.")


if __name__ == "__main__":
    # server = ChatServer()
    # try:
    #     asyncio.run(server.start())
    # except KeyboardInterrupt:
    #     print("Server stopped by user.")
    #     quit(0)

    uvicorn.run(
        "server:ChatServer",
        host="0.0.0.0",
        port=8765,
        log_level="debug",
        reload=False,
        factory=True,
    )