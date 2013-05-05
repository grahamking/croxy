# Croxy: Encrypting IRC proxy

Croxy sits between your IRC client and the IRC server, encrypting (AES-256) and decrypting all messages as they go through. People in the public channel without croxy, or with the wrong password, will see things like _3kOUXrxZzdJbqan21MpxNcycfrwylXNABtGSLyNCKWU=_ instead of your messages.

## Install

**Install**

1. Get python3 (You probably have this already).

2. Make sure you have pip for python3. On Ubuntu that's:

    sudo apt-get install python3-setuptools
    sudo easy_install3 pip

3. Install [pycrypto](https://pypi.python.org/pypi/pycrypto) 2.6+.

    sudo pip-3.2 install pycrypto

4. Clone this repository (or just download [croxy.py](https://raw.github.com/grahamking/croxy/master/croxy.py)):

    git clone git://github.com/grahamking/croxy.git

## Run

Just run the script, giving the address of the IRC server you want to connect to. Examples:

Freenode: `python3 croxy.py irc.freenode.net`
OFTC: `python3 croxy.py irc.oftc.net`
Mozilla: `python3 croxy.py irc.mozilla.org`
Coldfront: `python3 croxy.py irc.coldfront.net`

It will ask you for the password to use for encryption. Everyone in the channel will need to use the same password to communicate.

Then point your IRC client to `localhost` (default port 6667), and away you go.

The window in which you started Croxy will display the traffic as the remote server sees it. If it's encrypted in that window, it's encrypted on the server. Only PRIVMSG are encrypted - that's the messages you type into your client. Nicknames changes, joining a channel, etc, are NOT encrypted (otherwise the remote IRC server would get very confused).

## Correct usage

Security of your messages depends on the security of the shared password. You need a way to exchange the password so that the recipients know it came from you, and only the recipients can read it. The answer is [GnuPG](http://www.gnupg.org/). Try [GPG Quick Start](http://www.madboa.com/geek/gpg-quickstart/).

1. Exchange public keys with all the people who will be in your channel.

 * Generate your own key, if you haven't already: `gpg --gen-key`
 * Export your public key: `gpg --armor --output pubkey.txt --export 'Your Name'`
 * Upload that public key: `gpg --keyserver pgp.mit.edu --send-keys 'Your Name'`
 * Get all your friends to do that too
 * Import your friends keys: `gpg --keyserver pgp.mit.edu --search-keys 'myfriend@example.com'`

2. Every day, send the password in an encrypted, signed message to those people.

 * `gpg --encrypt --sign --armor -r friend1 -r friend2 password.txt`

3. Start Croxy!

Happy safe chat!
