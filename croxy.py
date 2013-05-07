#!/usr/bin/python3
"""Croxy: IRC encrypting proxy.

See README.md at: https://github.com/grahamking/croxy

---
Copyright 2013 Graham King

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

For full license details see <http://www.gnu.org/licenses/>.
"""

import sys
import getpass
import socketserver
import socket
import threading
import base64
import binascii

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

USAGE = "Usage: croxy <irc.example.net> [port]\nDefault port is 6667"
LISTEN_PORT = 6667
HARD_CODED_STR_SALT = b"CROXYSALT"


def main():

    if len(sys.argv) < 2:
        print(USAGE)
        return 1

    host = sys.argv[1]

    port = 6667
    if len(sys.argv) == 3:
        port = sys.argv[2]

    password = getpass.getpass("Today's password: ")

    print("Now point your IRC client at: localhost:{}".format(LISTEN_PORT))

    local = ClientServer(('localhost', LISTEN_PORT),
                         ClientHandler,
                         host,
                         port,
                         password)

    try:
        local.serve_forever()
    except KeyboardInterrupt:
        print("Bye")

    return 0


class ClientServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler_class, host, port, password):
        super().__init__(addr, handler_class)
        self.host = host
        self.port = port
        self.password = password


class ClientHandler(socketserver.StreamRequestHandler):
    """Handles connection from user's IRC client"""

    def __init__(self, request, addr, server):
        """server: Instance of ClientServer."""
        self.host = server.host
        self.port = server.port
        self.password = server.password
        self.local_f = None
        super().__init__(request, addr, server)

    def handle(self):
        """Called by socketserver.TCPServer once for each request,
        We only expect a single request (IRC client) at a time.
        """
        self.local_f = self.wfile

        remote_f = self.connect_remote()

        while 1:
            line = str(self.rfile.readline(), 'utf8')
            if not line:
                print("EOF")
                break

            if line.startswith("PRIVMSG"):
                prefix, body = self.parse_out(line)
                line = prefix + ":" + self.encrypt(body) + "\r\n"

            print("> ", line.strip())

            if remote_f:
                remote_f.write(line)
                remote_f.flush()

    def connect_remote(self):
        """Connect to IRC server"""
        remote = ServerWorker(
            self.host,
            self.port,
            self.password,
            self.local_f)
        remote.start()
        return remote.remote_f

    def parse_out(self, line):
        """Parses an outoing IRC message into prefix and body.
        e.g: "PRIVMSG #test :testing" ->
                prefix="PRIVMSG #test ", body="testing"
        Outgoing messages are simpler in format than incoming messages.
        """

        parts = line.strip().split(":")
        prefix = parts[0]
        body = ':'.join(parts[1:])
        return prefix, body

    def encrypt(self, msg):
        """AES-256 encrypt a message, returning it as ascii (base64)."""

        cipher = _cipher(self.password)
        sec = cipher.encrypt(mpad(msg, 32))
        return str(base64.b64encode(sec), "ascii")


class ServerWorker(threading.Thread):
    """Connect to the real IRC server."""

    def __init__(self, host, port, password, local_f):
        """
        host: IRC server to connect to.
        port: Port IRC server is listening on.
        password: Password for symmetric encryption.
        local_f: File-like object connected to IRC _client_.
        """
        super().__init__()
        print("Connecting to: {}:{}".format(host, port))

        self.host = host
        self.port = port
        self.password = password
        self.local_f = local_f

        self.remote_conn = socket.create_connection((host, port))
        self.remote_f = self.remote_conn.makefile(mode='rw', encoding='utf8')

    def run(self):
        """Thread main method."""

        while 1:
            line = self.remote_f.readline()
            if not line:
                print("SERVER EOF")
                break

            print("< ", line.strip())

            prefix, command, args = self.parse_in(line)

            if command == "PRIVMSG":
                start = ":" + prefix + " " + command + " " + args[0] + " :"
                body = args[1]      # This is the message

                try:
                    body = self.decrypt(body)
                except NotEncrypted:
                    body = "(I) " + body

                line = start + body + "\r\n"

            try:
                self.local_f.write(bytes(line, 'utf8'))
                self.local_f.flush()
            except ValueError:
                print("CLIENT EOF")
                break

        self.remote_conn.close()

    def parse_in(self, line):
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

    def decrypt(self, msg):
        """AES-256 decrypt a message"""
        if isinstance(msg, str):
            msg = bytes(msg, 'ascii')

        try:
            sec = base64.b64decode(msg)
        except binascii.Error:
            raise NotEncrypted()

        cipher = _cipher(self.password)

        try:
            clear = str(cipher.decrypt(sec), "utf8")
        except ValueError:
            raise NotEncrypted()

        return clear.strip('\0')


#
# Utils
#

def _cipher(key):
    """AES-256 cipher"""
    return AES.new(_derived_key(key), AES.MODE_CBC, b'This is an IV456')


def _derived_key(key):
    """32-bit PBKDF2 derived from 'key'"""
    return PBKDF2(bytes(key, "utf8"), HARD_CODED_STR_SALT, dkLen=32)


def mpad(msg, size):
    """Pad a str to multiple of size bytes. """
    amount = size - len(msg) % size
    return msg + '\0' * amount


class NotEncrypted(Exception):
    """Is not an encrypted message"""


if __name__ == "__main__":
    sys.exit(main())
