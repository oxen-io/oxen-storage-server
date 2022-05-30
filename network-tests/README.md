# Storage server testnet test suite

This directory contains a Python/pytest-based test repository to perform tests against the live Oxen
testnet.

Usage:

- install the [https://ci.oxen.rocks/oxen-io/oxen-pyoxenmq](oxenmq Python module).  You can build it
  from source, or alternatively grab the python3-oxenmq deb package from our deb repo
  (https://deb.oxen.io)u.

- Run `py.test-3` to run the test suite.  (You likely need to install python3-pytest and
  python3-nacl, if not already installed).
