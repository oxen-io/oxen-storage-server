# Storage server testnet test suite

This directory contains a Python/pytest-based test repository to perform tests against the live Oxen
testnet.

Usage:

- install the pyoxenmq Python module from the pyoxenmq submodule.  You can do this locally via
  `python3 setup.py build` and then symlink the .so into the storage server tests/ directory (the
  file and directory names in this example are Python version and system dependent):

    ln -s pyoxenmq/build/lib.linux-x86_64-3.9/pyoxenmq.cpython-39-x86_64-linux-gnu.so .

  Alternatively, rather than symlinking, simply install as a user with:

    python3 setup.py install --user

- Run `py.test-3` to run the test suite.  (You likely need to install python3-pytest and
  python3-nacl, if not already installed).
