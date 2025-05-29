import tkinter as tk
from tkinter import scrolledtext, messagebox, font
from tkinter import Tk

from async_tkinter_loop import async_handler, async_mainloop

from websockets import ConnectionClosedOK, ConnectionClosedError
from websockets.asyncio.client import ClientConnection, connect
from datetime import datetime
from cryptography.fernet import Fernet

KEY = b"6ruz07L563euMQnRSpdptyfz3KqHM3vlyDCXqExHPsA="

cipher = Fernet(KEY)  # Initialize Fernet with the key


class wsIRC:

    def __init__(self, root: Tk):
        self.root: Tk = root
        self.root.title("pisscord")
        self.root.geometry("600x400")

        # Configure grid
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.create_widgets()

        self.websocket: ClientConnection
        self.connected: bool = False

    def construct_message(self, msg: str, msg_owner: str = "") -> str:
        now = datetime.now().strftime("%H:%M")

        if msg_owner == "":
            message = f"{now}[CLIENT] - {msg}"
        else:
            message = f"{now}[{msg_owner}] - {msg}"

        return message

    async def e_send(self, message: str):
        """Encrypts and sends a message."""
        bytes_message = message.encode("utf-8")
        encrypted_message = cipher.encrypt(bytes_message)
        await self.websocket.send(encrypted_message)
        return encrypted_message

    def create_widgets(self):
        # Top frame for connection controls
        top_frame = tk.Frame(self.root)
        top_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        # Connection controls
        tk.Label(top_frame, text="Host:").pack(side=tk.LEFT, padx=(0, 1))
        self.host_entry = tk.Entry(top_frame, width=15)
        self.host_entry.insert(0, "localhost:8765")  # Default host
        self.host_entry.pack(side=tk.LEFT, padx=2)

        tk.Label(top_frame, text="User:").pack(side=tk.LEFT, padx=(10, 1))
        self.username_entry = tk.Entry(top_frame, width=10)
        self.username_entry.pack(side=tk.LEFT, padx=2)

        tk.Label(top_frame, text="Pass:").pack(side=tk.LEFT, padx=(10, 1))
        self.password_entry = tk.Entry(top_frame, show="*", width=10)
        self.password_entry.pack(side=tk.LEFT, padx=2)
        self.password_entry.bind("<Return>", self.on_enter_pressed)

        self.status_light = tk.Canvas(
            top_frame, width=10, height=10, highlightthickness=0
        )
        self.status_oval = self.status_light.create_oval(
            0, 0, 10, 10, fill="gray", outline=""
        )
        self.status_light.pack(side=tk.RIGHT, padx=2)

        self.connect_btn = tk.Button(
            top_frame, text="Connect", command=self.on_connect_click
        )
        self.connect_btn.pack(side=tk.RIGHT, padx=5)

        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.chat_display.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.chat_display.config(state=tk.DISABLED)

        # Bottom frame for message entry
        bottom_frame = tk.Frame(self.root)
        bottom_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        self.message_entry = tk.Entry(bottom_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        self.message_entry.config(state=tk.DISABLED)
        self.message_entry.bind("<Return>", self.on_enter_pressed)

        self.send_btn = tk.Button(bottom_frame, text="Send", command=self.on_send_click)
        self.send_btn.pack(side=tk.LEFT, padx=2)

    def on_enter_pressed(self, event):
        if self.connected:
            self.on_send_click()
        else:
            self.on_connect_click()

    async def handshake(self, websocket: ClientConnection, credentials: tuple):
        username, password = credentials

        await self.e_send(f"{username}:{password}")  # sends credentials to server

    async def check_auth_success(self, websocket: ClientConnection):
        _ = await websocket.recv()  # tries to receive a signal from the server

    @async_handler
    async def start_listener(self):
        while True:
            try:
                encrypted_message = await self.websocket.recv(decode=False)
                message = cipher.decrypt(encrypted_message).decode()  # decrypts message
                if str(message).startswith("[SERVER] - "):
                    self.add_message(message, "blue")
                else:
                    self.add_message(message, "black")
            except ConnectionClosedOK:
                break
            except ConnectionClosedError:
                self.add_message("Connection closed by server", "red")
                self.status_light.itemconfig(self.status_oval, fill="gray")
                self.connect_btn.config(state=tk.NORMAL)
                self.connect_btn.config(text="Connect")
                self.connected = False
                self.send_btn.config(state=tk.DISABLED)
                self.message_entry.config(state=tk.DISABLED)
                self.username_entry.config(state=tk.NORMAL)
                self.password_entry.config(state=tk.NORMAL)
                self.host_entry.config(state=tk.NORMAL)
                break
            except Exception as e:
                self.add_message(f"Error receiving message: {str(e)}")
                break

    @async_handler
    async def on_connect_click(self):

        if self.connected:
            self.connect_btn.config(state=tk.DISABLED)
            self.add_message("Disconnected", "red")
            await self.websocket.close()
            self.status_light.itemconfig(self.status_oval, fill="gray")
            self.connect_btn.config(state=tk.NORMAL)
            self.message_entry.config(state=tk.DISABLED)
            self.connect_btn.config(text="Connect")

            self.connected = False
            self.send_btn.config(state=tk.DISABLED)
            self.username_entry.config(state=tk.NORMAL)
            self.password_entry.config(state=tk.NORMAL)
            self.host_entry.config(state=tk.NORMAL)
            self.chat_display.config(state=tk.DISABLED)
            return

        host = self.host_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        credentials = (username, password)

        if not host or not username or not password:
            messagebox.showerror("Input Error", "Please fill in all fields.")
            return
        if not host.replace(".", "").replace(":", "").isalnum():
            messagebox.showerror("Input Error", "Invalid host address.")
            return
        if not username.isalnum():
            messagebox.showerror("Input Error", "Username must be alphanumeric.")
            return
        if not password:
            messagebox.showerror("Input Error", "Password cannot be empty.")
            return

        self.add_message(f"Connecting to {host}...", "gray")
        # status light to yellow
        self.status_light.itemconfig(self.status_oval, fill="yellow")
        self.connect_btn.config(state=tk.DISABLED)

        try:
            self.websocket = await connect(f"ws://{host}")
            await self.handshake(self.websocket, credentials)
            await self.check_auth_success(self.websocket)
            self.start_listener()
        except ConnectionClosedError as e:  # might go both ways
            if str(e).find("1008") != -1:  # 1008 means wrong credentials
                self.add_message(
                    "Authentication failed. Please check your credentials.", "red"
                )
            else:  # dunno what goes here
                messagebox.showerror(
                    "Unhandled Connection Error",
                    f"Failed to connect to {host}\n{str(e)}",
                )
            self.status_light.itemconfig(self.status_oval, fill="red")
            self.connect_btn.config(state=tk.NORMAL)
            return
        except ConnectionRefusedError:
            self.add_message(
                f"Connection refused. Is the server running on {host}?", "red"
            )
            self.status_light.itemconfig(self.status_oval, fill="red")
            self.connect_btn.config(state=tk.NORMAL)
            return
        except TimeoutError:
            self.add_message(
                f"Connection timed out. Is the server running on {host}?", "red"
            )
            self.status_light.itemconfig(self.status_oval, fill="red")
            self.connect_btn.config(state=tk.NORMAL)
            return
        except Exception as e:  # catch as they appear
            messagebox.showerror(
                "Unhandled Connection Error",
                f"Failed to connect to {host}\n{str(e)}",
            )
            self.status_light.itemconfig(self.status_oval, fill="red")
            self.connect_btn.config(state=tk.NORMAL)
            self.connected = False
            return

        self.add_message(f"Connected to {host}", "green")
        self.status_light.itemconfig(self.status_oval, fill="green")

        self.connect_btn.config(text="Disconnect")
        self.connect_btn.config(state=tk.NORMAL)
        self.connected = True
        self.send_btn.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.NORMAL)
        self.username_entry.config(state=tk.DISABLED)
        self.password_entry.config(state=tk.DISABLED)
        self.host_entry.config(state=tk.DISABLED)

    @async_handler
    async def on_disconnect_click(self):
        # Here you would disconnect from your backend
        self.add_message("Disconnecting...", "yellow")
        await self.websocket.close()
        self.add_message("Disconnected", "gray")
        self.status_light.itemconfig(self.status_oval, fill="gray")

        self.connect_btn.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.DISABLED)
        self.username_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)
        self.host_entry.config(state=tk.NORMAL)
        self.chat_display.config(state=tk.DISABLED)

    @async_handler
    async def on_send_click(self):
        message = self.message_entry.get().strip()
        if not message:
            return

        message_to_send = self.construct_message(message, self.username_entry.get())

        try:
            _ = await self.e_send(message_to_send)  # sends message to server

        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {str(e)}")
            return

        self.message_entry.delete(0, tk.END)

    def add_message(self, message, color="black"):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        if color:
            start_index = f"end-{len(message)+2}c"
            end_index = "end-1c"
            self.chat_display.tag_add(color, start_index, end_index)
            self.chat_display.tag_config(color, foreground=color)
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)


if __name__ == "__main__":
    root: Tk = tk.Tk()
    app = wsIRC(root)
    try:
        async_mainloop(root)
    except KeyboardInterrupt:
        _ = app.websocket.close()
