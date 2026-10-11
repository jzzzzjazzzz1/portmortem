"""Minimal fake FTP server that allows anonymous login - to test the
anonymous-FTP risk check against a real, controlled TCP service."""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2121


def handle(conn):
    conn.sendall(b"220 Welcome to FakeFTPd\r\n")
    while True:
        try:
            data = conn.recv(1024)
        except OSError:
            break
        if not data:
            break
        line = data.decode(errors="replace").strip()
        if line.upper().startswith("USER"):
            conn.sendall(b"331 Please specify the password.\r\n")
        elif line.upper().startswith("PASS"):
            conn.sendall(b"230 Login successful.\r\n")
        elif line.upper().startswith("QUIT"):
            conn.sendall(b"221 Goodbye.\r\n")
            break
        else:
            conn.sendall(b"502 Command not implemented.\r\n")
    conn.close()


def serve():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(5)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    serve()
