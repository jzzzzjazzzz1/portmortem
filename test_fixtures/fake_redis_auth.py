"""Fake Redis server that REQUIRES auth - replies -NOAUTH to PING without
credentials. Used to prove the unauth-Redis check does NOT false-positive
on a properly secured instance."""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 6401


def handle(conn):
    while True:
        try:
            data = conn.recv(1024)
        except OSError:
            break
        if not data:
            break
        conn.sendall(b"-NOAUTH Authentication required.\r\n")
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
