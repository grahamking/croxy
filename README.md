# Croxy: Encrypting IRC proxy

Croxy sits between your IRC client and the IRC server, encrypting (AES-256) and decrypting all messages as they go through. People in the public channel without croxy, or with the wrong password, will see things like _3kOUXrxZzdJbqan21MpxNcycfrwylXNABtGSLyNCKWU=_ instead of your messages.

## Install

**Install**

There is no install, you just run the script.

1. Get python3 (You probably have this already).

2. Make sure you have pip for python3. On Ubuntu that's:

    `sudo apt-get install python3-setuptools`

    `sudo easy_install3 pip`

3. Install [pycrypto](https://pypi.python.org/pypi/pycrypto) 2.6+.

    `sudo pip-3.2 install pycrypto`

4. Clone this repository (or just download [croxy.py](https://raw.github.com/grahamking/croxy/master/croxy.py)):

    `git clone git://github.com/grahamking/croxy.git`

## Run

Just run the script, giving the address of the IRC server you want to connect to.

    python3 croxy.py irc.freenode.net

For other networks substitute `irc.freenode.net`.

It will ask you for the password to use for encryption. Everyone in the channel will need to use the same password to communicate.

Then point your IRC client to `localhost` (default port 6667), and away you go.

The window in which you started Croxy will display the traffic as the remote server sees it. If it's encrypted in that window, it's encrypted on the server. Only PRIVMSG are encrypted - that's the messages you type into your client. Nicknames changes, joining a channel, etc, are NOT encrypted (otherwise the remote IRC server would get very confused).

## Correct usage

Security of your messages depends on the security of the shared password. You need a way to exchange the password so that the recipients know it came from you, and only the recipients can read it. The answer is [GnuPG](http://www.gnupg.org/). Try [GPG Quick Start](http://www.madboa.com/geek/gpg-quickstart/).

A. Exchange public keys with all the people who will be in your channel.

 * Generate your own key, if you haven't already: `gpg --gen-key`
 * Export your public key: `gpg --armor --output pubkey.txt --export 'Your Name'`
 * Upload that public key: `gpg --keyserver pgp.mit.edu --send-keys 'Your Name'`
 * Get all your friends to do that too
 * Import your friends keys: `gpg --keyserver pgp.mit.edu --search-keys 'myfriend@example.com'`

B. Every day, send the password in an encrypted, signed message to those people.

 * `gpg --encrypt --sign --armor -r friend1 -r friend2 password.txt`

C. Start Croxy!

## Smallprint

### Vulerability to traffic analysis

Croxy protects **what you say, not who you say it too**. In other worlds people watching will be able to see who you are talking to, and when, but not what you are saying. If this concerns you, you should connect to the IRC server using [Tor](https://www.torproject.org/). It also makes sense to use a nick different than your usual one.

### Ensuring forward secrecy

You should change the password every day, so that if the password is compromised you lose a single day of logs. Ideally someone from your channel should send the new password (GnuPG encrypted and signed) to all participants, each morning.

### License

Croxy is free software, GPL licensed. See LICENSE.txt for details.

Happy safe chat!
