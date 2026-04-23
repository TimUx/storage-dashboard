"""Runtime access to objects re-exported on the storage_clients package.

Tests patch ``app.api.storage_clients._local_session``; vendor modules must not
bind the session at import time from a submodule, or patches would not apply.
"""
import sys


def local_session():
    """Return the process-wide requests.Session used for storage API calls."""
    return sys.modules['app.api.storage_clients']._local_session
