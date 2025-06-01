from src.wsIRC import wsIRC
from tkinter import Tk
import tkinter as tk
from async_tkinter_loop import async_mainloop
from cryptography.fernet import Fernet


if __name__ == "__main__":
    KEY = b"6ruz07L563euMQnRSpdptyfz3KqHM3vlyDCXqExHPsA="

    cipher = Fernet(KEY)  # Initialize Fernet with the key
    root: Tk = tk.Tk()
    app = wsIRC(root, cipher)
    try:
        async_mainloop(root)
    except KeyboardInterrupt:
        _ = app.websocket.close()
