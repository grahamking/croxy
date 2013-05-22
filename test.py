"""Unit tests for croxy.py.

Usage: python3 test.py
"""

import unittest
import io
import sys

import croxy


class TestClientServer(unittest.TestCase):
    """Test the ClientServer class which extends socketserver.TCPServer.
    """
    def test_init(self):
        addr = ("127.0.0.1", 1234)
        cs = croxy.ClientServer(addr, None, 'localhost', 6697, 's3cret')
        self.assertTrue(cs)
        cs.socket.close()

    def test_handle_client_line(self):

        old = suppress_stdout()

        msg = "This is a test"
        line = "PRIVMSG #test :" + msg
        password = "secret"
        remote_f = io.BytesIO()
        croxy.handle_client_line(line, password, remote_f)

        output = remote_f.getvalue()
        ciphertext = output.decode('utf8').split(":")[1]
        clear = croxy.croxy_decrypt(ciphertext, password)
        self.assertEqual(clear, msg)

        restore_stdout(old)


class TestServerWorker(unittest.TestCase):
    """Test the ServerWorker class which is a thread.
    """

    def test_handle_server_line(self):

        old = suppress_stdout()

        msg = "Test"
        password = "secret"
        ciphertext = croxy.croxy_encrypt(msg, password)
        line = ":gk3!~gk3@example.net PRIVMSG #secure :" + ciphertext

        local_f = io.BytesIO()
        croxy.handle_server_line(line, password, local_f)

        output = local_f.getvalue()
        clear = output.decode('utf8').split(":")[2].strip()
        self.assertEqual(clear, msg)

        restore_stdout(old)

    def test_handle_not_encrypted(self):
        """Make sure not encrypted messages get clearly marked.
        """

        old = suppress_stdout()

        password = "test"
        line = ":gk!~gk@example.net PRIVMSG #sectest :test"
        local_f = io.BytesIO()
        croxy.handle_server_line(line, password, local_f)

        output = local_f.getvalue()
        clear = output.decode('utf8').split(":")[2].strip()
        self.assertEqual(clear, "(I) test")

        restore_stdout(old)


class TestUtil(unittest.TestCase):
    """Test various utility functions.
    """

    def test_mpad(self):
        """Test the mpad function which pads a string.
        """
        self.assertEqual(len(croxy.mpad(b"Test", 32)), 32)
        self.assertEqual(len(croxy.mpad(b"123456789", 8)), 16)

        u1 = "Федерация"
        self.assertEqual(len(croxy.mpad(u1.encode("utf8"), 16)), 32)

    def test_decode_unicode_unchanged(self):
        """Test 'decode' returns unicode unchanged
        """
        u8 = "Καλώς ήλθατε στην Ελλάδα"
        self.assertEqual(croxy.decode(u8), u8)

    def test_decode_utf8(self):
        """Test decode can handle utf8"""
        u8 = "Καλώς ήλθατε στην Ελλάδα"
        self.assertEqual(croxy.decode(u8.encode("utf8")), u8)

    def test_decode_latin1(self):
        """Test decode can handle iso-8859-1 aka latin-1."""
        l1 = "On s'était dit..."
        self.assertEqual(croxy.decode(l1.encode("latin-1")), l1)

    def test_main_no_args(self):
        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()

        self.assertEqual(croxy.main([]), 1)
        self.assertTrue(len(buf.getvalue()) > 0)

        restore_stdout(old_stdout)

    def test_parse_args_default_port(self):

        h1, p1 = croxy.parse_args(["localhost"])
        self.assertEqual(h1, "localhost")
        self.assertEqual(p1, 6697)

    def test_parse_args(self):
        h2, p2 = croxy.parse_args(["localhost", 7000])
        self.assertEqual(h2, "localhost")
        self.assertEqual(p2, 7000)


class TestParse(unittest.TestCase):
    """Test parsing lines."""

    def test_parse_out(self):
        prefix, body = croxy.parse_out("PRIVMSG #test :bob: How's it going?")
        self.assertEqual(prefix, "PRIVMSG #test ")
        self.assertEqual(body, "bob: How's it going?")

    def test_parse_in_welcome(self):
        line = ":barjavel.freenode.net 001 graham_king :Welcome to the freenode Internet Relay Chat Network graham_king"
        prefix, command, args = croxy.parse_in(line)
        self.assertEqual(prefix, "barjavel.freenode.net")
        self.assertEqual(command, "001")
        self.assertEqual(args, ["graham_king", "Welcome to the freenode Internet Relay Chat Network graham_king"])

    def test_parse_in_privmsg(self):
        line = ":rnowak!~rnowak@q.ovron.com PRIVMSG #linode :totally"
        prefix, command, args = croxy.parse_in(line)
        self.assertEqual(prefix, "rnowak!~rnowak@q.ovron.com")
        self.assertEqual(command, "PRIVMSG")
        self.assertEqual(args, ["#linode", "totally"])

    def test_parse_in_andbang(self):
        line = ":alan!223@irc.andbang.com PRIVMSG #ab :hello @graham"
        prefix, command, args = croxy.parse_in(line)
        self.assertEqual(prefix, "alan!223@irc.andbang.com")
        self.assertEqual(command, "PRIVMSG")
        self.assertEqual(args, ["#ab", "hello @graham"])

    def test_parse_in_away(self):
        line = ":hybrid7.debian.local 301 graham_king graham :Not here"
        prefix, command, args = croxy.parse_in(line)
        self.assertEqual(prefix, "hybrid7.debian.local")
        self.assertEqual(command, "301")
        self.assertEqual(args, ["graham_king", "graham", "Not here"])

    def test_parse_in_list(self):
        line = ":oxygen.oftc.net 322 graham_king #linode 412 :Linode Community Support | http://www.linode.com/ | Linodes in Asia-Pacific! - http://bit.ly/ooBzhV"
        prefix, command, args = croxy.parse_in(line)
        self.assertEqual(prefix, "oxygen.oftc.net")
        self.assertEqual(command, "322")

    def test_parse_in_url(self):
        line = ":bob!~bob@example.com PRIVMSG #test :https://botbot.me"
        prefix, command, args = croxy.parse_in(line)
        self.assertEqual(prefix, "bob!~bob@example.com")
        self.assertEqual(command, "PRIVMSG")
        self.assertEqual(args, ["#test", "https://botbot.me"])



class TestCrypto(unittest.TestCase):
    """Test the crypto methods.
    """

    def setUp(self):
        self.key = "s3cret"

    def test_pbkdf2(self):
        """Test croxy_pbkdf2.
        """
        derived = b'n\x9aar\x97j\xb2\\\xeb\x04K\xce\xd3lM\xd4\x97p\xd1\xe36\xfa\x1a@d,\xced\xb8\xb6\xfb\xd7'
        self.assertEqual(
            croxy.croxy_pbkdf2(self.key, iterations=1000, salt=b'CROXYSALT'),
            derived)

    def test_not_encrypted(self):
        """Test trying to decrypt an unecrypted string.
        """
        try:
            croxy.croxy_decrypt("But I'm not encrypted!", self.key)
            self.fail("Decrypting cleartext should raise an exception")
        except croxy.NotEncrypted:
            pass

    def test_roundtrip(self):
        """Test decrypt(encrypt(clear)) == clear.
        """
        def rt(cleartext):
            ciphertext = croxy.croxy_encrypt(cleartext, self.key)
            cleartext2 = croxy.croxy_decrypt(ciphertext, self.key)
            self.assertEqual(cleartext, cleartext2)

        rt("Test")
        rt("Björk Guðmundsdóttir")
        rt("فُصْحَى")

    def test_does_something(self):
        """Because the IV for AES is random, we can't check the exact
        output of croxy_encrypt, so we test_roundtrip (above) to
        makes sure it works.
        Here we just makes sure encrypt doesn't return the cleartext.
        """
        self.assertTrue(croxy.croxy_encrypt('xyz', self.key) != 'xyz')

    def test_rijndael(self):
        """The rijndael code from tlslite has a 'test' function, so
        what the hell let's call it.
        """
        croxy.test()


def suppress_stdout():
    """Turn off write to screen, for pretty test output."""
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    return old_stdout

def restore_stdout(old_stdout):
    """Turn stdout back on."""
    sys.stdout = old_stdout

if __name__ == '__main__':
    unittest.main()
