"""Minimal fake Redis server that responds +PONG to PING with no auth
required - to test the unauthenticated-Redis risk check."""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 6400


def handle(conn):
    while True:
        try:
            data = conn.recv(1024)
        except OSError:
            break
        if not data:
            break
        if b"PING" in data.upper():
            conn.sendall(b"+PONG\r\n")
        else:
            conn.sendall(b"-ERR unknown command\r\n")
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
