#!/usr/bin/python3

import sys
import getpass
import socketserver
import socket
import threading
import base64
import time
import binascii

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

USAGE = "Usage: croxy <irc.example.net> [port]\nDefault port is 6667"
LISTEN_PORT = 6667
HARD_CODED_STR_SALT = b"CROXYSALT"

# The two connection endpoints are shared between threads,
# as file-like objects
remote_f = None  # Connection to IRC server.
local_f = None  # Connection from user

# Will hold the password for symmetric encryption
password = None


def main():

    if len(sys.argv) < 2:
        print(USAGE)
        return 1

    host = sys.argv[1]

    port = 6667
    if len(sys.argv) == 3:
        port = sys.argv[2]

    global password
    password = getpass.getpass("Today's password: ")

    print("Now point your IRC client at: localhost:{}".format(LISTEN_PORT))

    local = ClientServer(('localhost', LISTEN_PORT),
                         ClientHandler,
                         host=host,
                         port=port)

    try:
        local.serve_forever()
    except KeyboardInterrupt:
        print("Bye")

    return 0


def remote_side(host="", port=6667):
    """Connect to the real IRC server. Runs in a thread.
    """
    print("Connecting to: {}:{}".format(host, port))

    global local_f
    global remote_f
    remote_conn = socket.create_connection((host, port))
    remote_f = remote_conn.makefile(mode='rw', encoding='utf8')

    while 1:
        line = remote_f.readline()
        if not line:
            print("SERVER EOF")
            break

        print("< ", line.strip())

        prefix, command, args = parse_in(line)

        if command == "PRIVMSG":
            start = ":" + prefix +" "+ command +" "+ args[0] + " :"
            body = args[1]      # This is the message

            try:
                global password
                body = decrypt(password, body)
            except NotEncrypted:
                body = "(I) " + body

            line = start + body + "\r\n"

        try:
            local_f.write(bytes(line, 'utf8'))
            local_f.flush()
        except ValueError:
            print("CLIENT EOF")
            break

    remote_conn.close()


class ClientServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler_class, host=None, port=None):
        super().__init__(addr, handler_class)
        self.host = host
        self.port = port


class ClientHandler(socketserver.StreamRequestHandler):
    """Handles connection from user's IRC client"""

    def __init__(self, request, addr, server):
        """server: Instance of ClientServer."""
        self.host = server.host
        self.port = server.port
        super().__init__(request, addr, server)

    def handle(self):
        """Called by socketserver.TCPServer once for each request,
        We only expect a single request (IRC client) at a time.
        """
        global remote_f
        global local_f
        local_f = self.wfile

        self.connect_remote()

        while 1:
            line = str(self.rfile.readline(), 'utf8')
            if not line:
                print("EOF")
                break

            if line.startswith("PRIVMSG"):
                prefix, body = parse_out(line)
                global password
                line = prefix + ":" + encrypt(password, body) +"\r\n"

            print("> ", line.strip())

            if remote_f:
                remote_f.write(line)
                remote_f.flush()

    def connect_remote(self):
        """Connect to IRC server"""
        remote_args = {"host": self.host, "port": self.port}
        remote = threading.Thread(target=remote_side, kwargs=remote_args)
        remote.start()
        self.wait_for_remote_f()
        return remote

    def wait_for_remote_f(self):
        """Wait for the remote connection to be established"""
        global remote_f
        while not remote_f:
            time.sleep(0.1)


def parse_out(line):
    """Parses an outoing IRC message into prefix and body.
    e.g: "PRIVMSG #test :testing" -> prefix="PRIVMSG #test ", body="testing"
    Outgoing messages are simpler in format than incoming messages.
    """

    parts = line.strip().split(":")
    prefix = parts[0]
    body = ':'.join(parts[1:])
    return prefix, body


def parse_in(line):
    """Parse an incoming IRC message."""
    prefix = ''
    trailing = []
    if not line:
        print("Bad IRC message: ", line)
        return None
    if line[0] == ':':
        prefix, line = line[1:].split(' ', 1)
    if line.find(' :') != -1:
        line, trailing = line.split(' :', 1)
        args = line.split()
        args.append(trailing)
    else:
        args = line.split()
    command = args.pop(0)

    return prefix, command, args


def _derived_key(key):
    return PBKDF2(bytes(key, "utf8"), HARD_CODED_STR_SALT, dkLen=32)


def _cipher(key):
    return AES.new(_derived_key(key), AES.MODE_CBC, b'This is an IV456')


def encrypt(user_key, msg):
    """AES-256 encrypt a message, returning it as ascii (base64)."""

    cipher = _cipher(user_key)
    sec = cipher.encrypt(mpad(msg, 32))
    return str(base64.b64encode(sec), "ascii")


def decrypt(user_key, msg):
    """AES-256 decrypt a message"""
    if isinstance(msg, str):
        msg = bytes(msg, 'ascii')

    try:
        sec = base64.b64decode(msg)
    except binascii.Error:
        raise NotEncrypted()

    cipher = _cipher(user_key)

    try:
        clear = str(cipher.decrypt(sec), "utf8")
    except ValueError:
        raise NotEncrypted()

    return clear.strip('\0')


def mpad(msg, size):
    """Pad a str to multiple of size bytes.
    """
    amount = size - len(msg) % size
    return msg + '\0' * amount


class NotEncrypted(Exception):
    """Is not an encrypted message"""

if __name__ == "__main__":
    sys.exit(main())
