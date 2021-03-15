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
import ssl
import os
import secrets

USAGE = "Usage: croxy <irc.example.net> [port]\nDefault port is 6697"
LISTEN_PORT = 6667
REMOTE_PORT = 6697  # Default IRC over TLS port

salt = secrets.token_hex(50)
DEFAULT_SALT = salt.encode("utf-8")    # For pbkdf2 only
PBKDF2_ITERATIONS = 5000

def main(args):

    if len(args) < 1:
        print(USAGE)
        return 1

    host, port = parse_args(args)
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

def parse_args(args):
    """Takes sys.argv returns tuple (host, port)"""
    host = args[0]

    port = REMOTE_PORT
    if len(args) == 2:
        port = args[1]

    return host, port


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
        self.server = server

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
        if not remote_f:
            # Error connecting to IRC. Abort.
            self.server.server_close()
            return

        while 1:
            line_bytes = self.rfile.readline()
            line = decode(line_bytes)
            if not line:
                print("EOF")
                break

            handle_client_line(line, self.password, remote_f)

    def connect_remote(self):
        """Connect to IRC server"""
        remote = ServerWorker(
            self.host,
            self.port,
            self.password,
            self.local_f)

        if not remote.remote_conn:
            # Connect failed
            return None

        remote.start()
        return remote.remote_f


def handle_client_line(line, password, remote_f):
    """Handle a single line from the client.
    line: str
    remote_f: file
    """

    if line.startswith("PRIVMSG"):
        prefix, body = parse_out(line)
        ciphertext = croxy_encrypt(body, password)
        line = (prefix + ":" + ciphertext + "\r\n")

    print("> ", line.strip())

    if remote_f:
        as_bytes = line.encode('utf8')
        remote_f.write(as_bytes)
        remote_f.flush()


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

        sock = socket.create_connection((host, port))
        try:
            ssock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)
            msg = ("TLS socket connection established. {openssl}\n"
                  "Cipher: {cipher}\n"
                  "Server certificate (not checked):\n{cert}\n")
            print(msg.format(
                openssl=ssl.OPENSSL_VERSION,
                cipher=ssock.cipher(),
                cert=ssock.getpeercert()
            ))

            self.remote_conn = ssock

        except ssl.SSLError as exc:
            print("SSLError: {}".format(exc))
            print("Could not establish TLS/SSL connection. Are you sure "
                  "port {} supports TLSv1?".format(port))
            self.remote_conn = None     # Stops the program
            return

        # Set socket file to binary, handle encoding ourselves
        self.remote_f = self.remote_conn.makefile(mode='rwb')

    def run(self):
        """Thread main method."""

        while 1:
            line = decode(self.remote_f.readline())
            if not line:
                print("SERVER EOF")
                break

            try:
                handle_server_line(line, self.password, self.local_f)
            except CloseException:
                print("CLIENT EOF")
                break

        self.remote_conn.close()


def handle_server_line(line, password, local_f):
    """Handle a single IRC line from the server.
    """

    print("< ", line.strip())

    prefix, command, args = parse_in(line)

    if command == "PRIVMSG":
        start = ":" + prefix + " " + command + " " + args[0] + " :"
        body = args[1]      # This is the message

        try:
            body = croxy_decrypt(body, password)
        except NotEncrypted:
            body = "(I) " + body

        line = start + body + "\r\n"

    try:
        local_f.write(line.encode('utf8'))
        local_f.flush()
    except ValueError:
        raise CloseException()

def decode(line):
    """Takes bytes and returns unicode. Tries utf8 and iso-8859-1."""

    try:
        return str(line, 'utf8')
    except UnicodeDecodeError:
        return str(line, 'iso-8859-1')
    except TypeError:
        # Already unicode
        return line

def mpad(msg, size):
    """Pad a byte string to multiple of size bytes. """
    amount = size - len(msg) % size
    return msg + b'\0' * amount

def parse_out(line):
    """Parses an outoing IRC message into prefix and body.
    e.g: "PRIVMSG #test :testing" ->
            prefix="PRIVMSG #test ", body="testing"
    Outgoing messages are simpler in format than incoming messages.
    """

    parts = line.strip().split(":")
    prefix = parts[0]
    body = ":".join(parts[1:])
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


class NotEncrypted(Exception):
    """Is not an encrypted message"""

class CloseException(Exception):
    """Client or server closed connection"""


## CRYPTO LIBRARY WRAPPERS
# This is our only entry points to the next section.

def croxy_encrypt(msg, key):
    """AES-256 encrypt the msg (str) with key (str).
    Returns base64 encoded (str).
    """
    msg = msg.encode('utf8')
    msg = mpad(msg, 32)
    derived = croxy_pbkdf2(key)
    iv = os.urandom(16)

    try:
        # If pycrypto is present use it
        from Crypto.Cipher import AES
        cipher = AES.new(derived, AES.MODE_CBC, iv)
    except ImportError:
        # Use our own from tlslite (inline below)
        cipher = Python_AES(derived, 2, iv)
        msg = bytearray(msg)

    sec = cipher.encrypt(msg)
    return str(base64.b64encode(iv + sec), 'ascii')

def croxy_decrypt(msg, key):
    """AES-256 decrypt the msg (str) with key (str).
    Return a str (unicode).
    """

    if isinstance(msg, str):
        try:
            msg = msg.encode('ascii')
        except UnicodeEncodeError:
            # If it's not ascii, then it's not base64, so not encrypted
            raise NotEncrypted()

    if len(msg) < 64:
        raise NotEncrypted()

    try:
        sec = base64.b64decode(msg)
    except binascii.Error:
        raise NotEncrypted()

    derived = croxy_pbkdf2(key)
    iv = sec[:16]
    sec = sec[16:]

    try:
        # If pycrypto is present use it
        from Crypto.Cipher import AES
        cipher = AES.new(derived, AES.MODE_CBC, iv)
    except ImportError:
        # Use our own from tlslite (inline below)
        cipher = Python_AES(derived, 2, iv)
        sec = bytearray(sec)

    try:
        clear = str(cipher.decrypt(sec), "utf8")
    except (ValueError, AssertionError):
        raise NotEncrypted()

    return clear.strip('\0')

def croxy_pbkdf2(key, iterations=PBKDF2_ITERATIONS, salt=DEFAULT_SALT):
    """32-bit PBKDF2 derived from 'key'"""

    bkey = key.encode("utf8")
    dklen = 32

    # Use our own from Django (inline below)
    derived = pbkdf2(bkey, salt, iterations, dklen=dklen)

    return derived

#####################################
# CRYPTO LIBRARIES - here be dragons
# AES FROM tlslite
# PBKDF2 FROM Django
#####################################

import hashlib
import operator
import struct
from functools import reduce

#
# pbkdf2 and support function (_fast_hmac, _bin_to_long, _long_to_bin)
# are from Django (git revision bc02a96).
#
# https://github.com/django/django/blob/master/django/utils/crypto.py
#
# The only changes are:
# - two force_bytes lines commented out (we pass bytes)
# - xrange -> range (python3 upgrade)
#

def pbkdf2(password, salt, iterations, dklen=0, digest=None):
    """
    Implements PBKDF2 as defined in RFC 2898, section 5.2

    HMAC+SHA256 is used as the default pseudo random function.

    Right now 10,000 iterations is the recommended default which takes
    100ms on a 2.2Ghz Core 2 Duo.  This is probably the bare minimum
    for security given 1000 iterations was recommended in 2001. This
    code is very well optimized for CPython and is only four times
    slower than openssl's implementation.
    """
    assert iterations > 0
    if not digest:
        digest = hashlib.sha256
    #password = force_bytes(password)
    #salt = force_bytes(salt)
    hlen = digest().digest_size
    if not dklen:
        dklen = hlen
    if dklen > (2 ** 32 - 1) * hlen:
        raise OverflowError('dklen too big')
    l = -(-dklen // hlen)
    r = dklen - (l - 1) * hlen

    hex_format_string = "%%0%ix" % (hlen * 2)

    def F(i):
        def U():
            u = salt + struct.pack(b'>I', i)
            for j in range(int(iterations)):
                u = _fast_hmac(password, u, digest).digest()
                yield _bin_to_long(u)
        return _long_to_bin(reduce(operator.xor, U()), hex_format_string)

    T = [F(x) for x in range(1, l + 1)]
    return b''.join(T[:-1]) + T[-1][:r]

_trans_5c = bytearray([(x ^ 0x5C) for x in range(256)])
_trans_36 = bytearray([(x ^ 0x36) for x in range(256)])

def _bin_to_long(x):
    """
    Convert a binary string into a long integer

    This is a clever optimization for fast xor vector math
    """
    return int(binascii.hexlify(x), 16)

def _long_to_bin(x, hex_format_string):
    """
    Convert a long integer into a binary string.
    hex_format_string is like "%020x" for padding 10 characters.
    """
    return binascii.unhexlify((hex_format_string % x).encode('ascii'))

def _fast_hmac(key, msg, digest):
    """
    A trimmed down version of Python's HMAC implementation.

    This function operates on bytes.
    """
    dig1, dig2 = digest(), digest()
    if len(key) > dig1.block_size:
        key = digest(key).digest()
    key += b'\x00' * (dig1.block_size - len(key))
    dig1.update(key.translate(_trans_36))
    dig1.update(msg)
    dig2.update(key.translate(_trans_5c))
    dig2.update(dig1.digest())
    return dig2

# Python_AES is from tlslite (git rev 82074b2), with following modifications:
#  - remove python2/3 support code, to make it Python3 only
#  - inline abstract AES superclass
#
# https://github.com/trevp/tlslite/blob/master/tlslite/utils/python_aes.py
#

# Author: Trevor Perrin

"""Pure-Python AES implementation."""

def new(key, mode, IV):
    return Python_AES(key, mode, IV)

class Python_AES():
    def __init__(self, key, mode, IV):

        if len(key) not in (16, 24, 32):
            raise AssertionError()
        if mode != 2:
            raise AssertionError()
        if len(IV) != 16:
            raise AssertionError()
        self.isBlockCipher = True
        self.block_size = 16
        if len(key)==16:
            self.name = "aes128"
        elif len(key)==24:
            self.name = "aes192"
        elif len(key)==32:
            self.name = "aes256"
        else:
            raise AssertionError()

        self.rijndael = rijndael(key, 16)
        self.IV = IV

    def encrypt(self, plaintext):
        assert(len(plaintext) % 16 == 0)

        plaintextBytes = plaintext[:]
        chainBytes = self.IV[:]

        #CBC Mode: For each block...
        for x in range(len(plaintextBytes)//16):

            #XOR with the chaining block
            blockBytes = plaintextBytes[x*16 : (x*16)+16]
            for y in range(16):
                blockBytes[y] ^= chainBytes[y]

            #Encrypt it
            encryptedBytes = self.rijndael.encrypt(blockBytes)

            #Overwrite the input with the output
            for y in range(16):
                plaintextBytes[(x*16)+y] = encryptedBytes[y]

            #Set the next chaining block
            chainBytes = encryptedBytes

        self.IV = chainBytes[:]
        return plaintextBytes

    def decrypt(self, ciphertext):
        assert(len(ciphertext) % 16 == 0)

        ciphertextBytes = ciphertext[:]
        chainBytes = self.IV[:]

        #CBC Mode: For each block...
        for x in range(len(ciphertextBytes)//16):

            #Decrypt it
            blockBytes = ciphertextBytes[x*16 : (x*16)+16]
            decryptedBytes = self.rijndael.decrypt(blockBytes)

            #XOR with the chaining block and overwrite the input with output
            for y in range(16):
                decryptedBytes[y] ^= chainBytes[y]
                ciphertextBytes[(x*16)+y] = decryptedBytes[y]

            #Set the next chaining block
            chainBytes = blockBytes

        self.IV = chainBytes[:]
        return ciphertextBytes

# -- Start rijndael.py
# https://github.com/trevp/tlslite/blob/master/tlslite/utils/rijndael.py


# Authors:
#   Bram Cohen
#   Trevor Perrin - various changes
#
# See the LICENSE file for legal information regarding use of this file.
# Also see Bram Cohen's statement below

"""
A pure python (slow) implementation of rijndael with a decent interface

To include -

from rijndael import rijndael

To do a key setup -

r = rijndael(key, block_size = 16)

key must be a string of length 16, 24, or 32
blocksize must be 16, 24, or 32. Default is 16

To use -

ciphertext = r.encrypt(plaintext)
plaintext = r.decrypt(ciphertext)

If any strings are of the wrong length a ValueError is thrown
"""

# ported from the Java reference code by Bram Cohen, bram@gawth.com, April 2001
# this code is public domain, unless someone makes
# an intellectual property claim against the reference
# code, in which case it can be made public domain by
# deleting all the comments and renaming all the variables

import copy

shifts = [[[0, 0], [1, 3], [2, 2], [3, 1]],
          [[0, 0], [1, 5], [2, 4], [3, 3]],
          [[0, 0], [1, 7], [3, 5], [4, 4]]]

# [keysize][block_size]
num_rounds = {16: {16: 10, 24: 12, 32: 14}, 24: {16: 12, 24: 12, 32: 14}, 32: {16: 14, 24: 14, 32: 14}}

A = [[1, 1, 1, 1, 1, 0, 0, 0],
     [0, 1, 1, 1, 1, 1, 0, 0],
     [0, 0, 1, 1, 1, 1, 1, 0],
     [0, 0, 0, 1, 1, 1, 1, 1],
     [1, 0, 0, 0, 1, 1, 1, 1],
     [1, 1, 0, 0, 0, 1, 1, 1],
     [1, 1, 1, 0, 0, 0, 1, 1],
     [1, 1, 1, 1, 0, 0, 0, 1]]

# produce log and alog tables, needed for multiplying in the
# field GF(2^m) (generator = 3)
alog = [1]
for i in range(255):
    j = (alog[-1] << 1) ^ alog[-1]
    if j & 0x100 != 0:
        j ^= 0x11B
    alog.append(j)

log = [0] * 256
for i in range(1, 255):
    log[alog[i]] = i

# multiply two elements of GF(2^m)
def mul(a, b):
    if a == 0 or b == 0:
        return 0
    return alog[(log[a & 0xFF] + log[b & 0xFF]) % 255]

# substitution box based on F^{-1}(x)
box = [[0] * 8 for i in range(256)]
box[1][7] = 1
for i in range(2, 256):
    j = alog[255 - log[i]]
    for t in range(8):
        box[i][t] = (j >> (7 - t)) & 0x01

B = [0, 1, 1, 0, 0, 0, 1, 1]

# affine transform:  box[i] <- B + A*box[i]
cox = [[0] * 8 for i in range(256)]
for i in range(256):
    for t in range(8):
        cox[i][t] = B[t]
        for j in range(8):
            cox[i][t] ^= A[t][j] * box[i][j]

# S-boxes and inverse S-boxes
S =  [0] * 256
Si = [0] * 256
for i in range(256):
    S[i] = cox[i][0] << 7
    for t in range(1, 8):
        S[i] ^= cox[i][t] << (7-t)
    Si[S[i] & 0xFF] = i

# T-boxes
G = [[2, 1, 1, 3],
    [3, 2, 1, 1],
    [1, 3, 2, 1],
    [1, 1, 3, 2]]

AA = [[0] * 8 for i in range(4)]

for i in range(4):
    for j in range(4):
        AA[i][j] = G[i][j]
        AA[i][i+4] = 1

for i in range(4):
    pivot = AA[i][i]
    if pivot == 0:
        t = i + 1
        while AA[t][i] == 0 and t < 4:
            t += 1
            assert t != 4, 'G matrix must be invertible'
            for j in range(8):
                AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
            pivot = AA[i][i]
    for j in range(8):
        if AA[i][j] != 0:
            AA[i][j] = alog[(255 + log[AA[i][j] & 0xFF] - log[pivot & 0xFF]) % 255]
    for t in range(4):
        if i != t:
            for j in range(i+1, 8):
                AA[t][j] ^= mul(AA[i][j], AA[t][i])
            AA[t][i] = 0

iG = [[0] * 4 for i in range(4)]

for i in range(4):
    for j in range(4):
        iG[i][j] = AA[i][j + 4]

def mul4(a, bs):
    if a == 0:
        return 0
    r = 0
    for b in bs:
        r <<= 8
        if b != 0:
            r = r | mul(a, b)
    return r

T1 = []
T2 = []
T3 = []
T4 = []
T5 = []
T6 = []
T7 = []
T8 = []
U1 = []
U2 = []
U3 = []
U4 = []

for t in range(256):
    s = S[t]
    T1.append(mul4(s, G[0]))
    T2.append(mul4(s, G[1]))
    T3.append(mul4(s, G[2]))
    T4.append(mul4(s, G[3]))

    s = Si[t]
    T5.append(mul4(s, iG[0]))
    T6.append(mul4(s, iG[1]))
    T7.append(mul4(s, iG[2]))
    T8.append(mul4(s, iG[3]))

    U1.append(mul4(t, iG[0]))
    U2.append(mul4(t, iG[1]))
    U3.append(mul4(t, iG[2]))
    U4.append(mul4(t, iG[3]))

# round constants
rcon = [1]
r = 1
for t in range(1, 30):
    r = mul(2, r)
    rcon.append(r)

del A
del AA
del pivot
del B
del G
del box
del log
del alog
del i
del j
del r
del s
del t
del mul
del mul4
del cox
del iG

class rijndael:
    def __init__(self, key, block_size = 16):

        if block_size != 16 and block_size != 24 and block_size != 32:
            raise ValueError('Invalid block size: ' + str(block_size))
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise ValueError('Invalid key size: ' + str(len(key)))
        self.block_size = block_size

        ROUNDS = num_rounds[len(key)][block_size]
        BC = block_size // 4
        # encryption round keys
        Ke = [[0] * BC for i in range(ROUNDS + 1)]
        # decryption round keys
        Kd = [[0] * BC for i in range(ROUNDS + 1)]
        ROUND_KEY_COUNT = (ROUNDS + 1) * BC
        KC = len(key) // 4

        # copy user material bytes into temporary ints
        tk = []
        for i in range(0, KC):
            tk.append((key[i * 4] << 24) | (key[i * 4 + 1] << 16) |
                (key[i * 4 + 2] << 8) | key[i * 4 + 3])

        # copy values into round key arrays
        t = 0
        j = 0
        while j < KC and t < ROUND_KEY_COUNT:
            Ke[t // BC][t % BC] = tk[j]
            Kd[ROUNDS - (t // BC)][t % BC] = tk[j]
            j += 1
            t += 1
        tt = 0
        rconpointer = 0
        while t < ROUND_KEY_COUNT:
            # extrapolate using phi (the round key evolution function)
            tt = tk[KC - 1]
            tk[0] ^= (S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^  \
                     (S[(tt >>  8) & 0xFF] & 0xFF) << 16 ^  \
                     (S[ tt        & 0xFF] & 0xFF) <<  8 ^  \
                     (S[(tt >> 24) & 0xFF] & 0xFF)       ^  \
                     (rcon[rconpointer]    & 0xFF) << 24
            rconpointer += 1
            if KC != 8:
                for i in range(1, KC):
                    tk[i] ^= tk[i-1]
            else:
                for i in range(1, KC // 2):
                    tk[i] ^= tk[i-1]
                tt = tk[KC // 2 - 1]
                tk[KC // 2] ^= (S[ tt        & 0xFF] & 0xFF)       ^ \
                              (S[(tt >>  8) & 0xFF] & 0xFF) <<  8 ^ \
                              (S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^ \
                              (S[(tt >> 24) & 0xFF] & 0xFF) << 24
                for i in range(KC // 2 + 1, KC):
                    tk[i] ^= tk[i-1]
            # copy values into round key arrays
            j = 0
            while j < KC and t < ROUND_KEY_COUNT:
                Ke[t // BC][t % BC] = tk[j]
                Kd[ROUNDS - (t // BC)][t % BC] = tk[j]
                j += 1
                t += 1
        # inverse MixColumn where needed
        for r in range(1, ROUNDS):
            for j in range(BC):
                tt = Kd[r][j]
                Kd[r][j] = U1[(tt >> 24) & 0xFF] ^ \
                           U2[(tt >> 16) & 0xFF] ^ \
                           U3[(tt >>  8) & 0xFF] ^ \
                           U4[ tt        & 0xFF]
        self.Ke = Ke
        self.Kd = Kd

    def encrypt(self, plaintext):
        if len(plaintext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Ke = self.Ke

        BC = self.block_size // 4
        ROUNDS = len(Ke) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][0]
        s2 = shifts[SC][2][0]
        s3 = shifts[SC][3][0]
        a = [0] * BC
        # temporary work array
        t = []
        # plaintext to ints + key
        for i in range(BC):
            t.append((plaintext[i * 4    ] << 24 |
                      plaintext[i * 4 + 1] << 16 |
                      plaintext[i * 4 + 2] <<  8 |
                      plaintext[i * 4 + 3]        ) ^ Ke[0][i])
        # apply round transforms
        for r in range(1, ROUNDS):
            for i in range(BC):
                a[i] = (T1[(t[ i           ] >> 24) & 0xFF] ^
                        T2[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T3[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T4[ t[(i + s3) % BC]        & 0xFF]  ) ^ Ke[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in range(BC):
            tt = Ke[ROUNDS][i]
            result.append((S[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((S[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((S[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return bytearray(result)

    def decrypt(self, ciphertext):
        if len(ciphertext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Kd = self.Kd

        BC = self.block_size // 4
        ROUNDS = len(Kd) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][1]
        s2 = shifts[SC][2][1]
        s3 = shifts[SC][3][1]
        a = [0] * BC
        # temporary work array
        t = [0] * BC
        # ciphertext to ints + key
        for i in range(BC):
            t[i] = (ciphertext[i * 4    ] << 24 |
                    ciphertext[i * 4 + 1] << 16 |
                    ciphertext[i * 4 + 2] <<  8 |
                    ciphertext[i * 4 + 3]        ) ^ Kd[0][i]
        # apply round transforms
        for r in range(1, ROUNDS):
            for i in range(BC):
                a[i] = (T5[(t[ i           ] >> 24) & 0xFF] ^
                        T6[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T7[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T8[ t[(i + s3) % BC]        & 0xFF]  ) ^ Kd[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in range(BC):
            tt = Kd[ROUNDS][i]
            result.append((Si[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Si[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((Si[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return bytearray(result)

def test():
    def t(kl, bl):
        b = b'b' * bl
        r = rijndael(b'a' * kl, bl)
        assert r.decrypt(r.encrypt(b)) == b
    t(16, 16)
    t(16, 24)
    t(16, 32)
    t(24, 16)
    t(24, 24)
    t(24, 32)
    t(32, 16)
    t(32, 24)
    t(32, 32)

# -- End rijndael.py

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
