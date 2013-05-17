"""Unit tests for croxy.py.

Usage: python3 test.py
"""

import unittest

import croxy


class TestClientServer(unittest.TestCase):
    """Test the ClientServer class which extends socketserver.TCPServer.
    """
    def test_init(self):
        addr = ("127.0.0.1", 1234)
        cs = croxy.ClientServer(addr, None, 'localhost', 6697, 's3cret')
        self.assertTrue(cs)
        cs.socket.close()

'''
class TestClientHandler(unittest.TestCase):
    """Test the ClientHandler class which
    extends socketserver.StreamRequestHandler.
    """

    def test_init(self):

        addr = ("127.0.0.1", 6667)
        cs = croxy.ClientServer(addr, None, 'localhost', 6697, 's3cret')

        h = croxy.ClientHandler(MockRequest(), addr, cs)
        self.assertTrue(h)

class MockRequest():

    """Just enough of socket connection.
    """
    def makefile(self, mode, *args, **kwargs):
        print(mode)
        return open("test.txt", "ab")

    def __init__(self):
        pass
'''

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


class TestCrypto(unittest.TestCase):
    """Test the crypto methods.
    """

    def setUp(self):
        self.key = "s3cret"

    def test_pbkdf2(self):
        """Test croxy_pbkdf2.
        """
        derived = b'\n\x84U\xba\x01\xca\xbf\xcbz\xf4\x8e\x01\xf5O\x93\n\x01\xc8\xb1\\-\xc2r\xaa\xef\xfb0\xae\x98\xfe8\x8f'
        self.assertEqual(croxy.croxy_pbkdf2(self.key), derived)

    def test_encrypt(self):
        """Test croxy_encrypt.
        """
        self.assertEqual(
                croxy.croxy_encrypt("Test", self.key),
                "ACZgnWZEWQVOjctD+oh3v9+LdouJhwYq23hqpS3DEHg=")
        self.assertEqual(
                croxy.croxy_encrypt("فُصْحَى", self.key),
                "6eS7Z6wRWgkT2AP/OxcZBrtGsP3ThAtpIW+6fV+WjQM=")

    def test_decrypt(self):
        """Test croxy_decrypt.
        """
        ciphertext = "ACZgnWZEWQVOjctD+oh3v9+LdouJhwYq23hqpS3DEHg="
        self.assertEqual(croxy.croxy_decrypt(ciphertext, self.key), "Test")

        ciphertext = "6eS7Z6wRWgkT2AP/OxcZBrtGsP3ThAtpIW+6fV+WjQM="
        self.assertEqual(croxy.croxy_decrypt(ciphertext, self.key), "فُصْحَى")

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
        cleartext = "Björk Guðmundsdóttir"
        ciphertext = croxy.croxy_encrypt(cleartext, self.key)
        cleartext2 = croxy.croxy_decrypt(ciphertext, self.key)
        self.assertEqual(cleartext, cleartext2)

    def test_rijndael(self):
        """The rijndael code from tlslite has a 'test' function, so
        what the hell let's call it.
        """
        croxy.test()


if __name__ == '__main__':
    unittest.main()
