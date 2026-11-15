"""Offline defaults and test teardown guards for the whole test suite."""
from __future__ import annotations

import os
import threading

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

import pytest

from firewall.audit import SQLiteAuditStore

_STORES: list[SQLiteAuditStore] = []
_original_init = SQLiteAuditStore.__init__

def _track_store(self, *args, **kwargs):
    _original_init(self, *args, **kwargs)
    _STORES.append(self)

SQLiteAuditStore.__init__ = _track_store

@pytest.fixture(autouse=True)
def close_stores_and_check_threads():
    baseline = set(threading.enumerate())
    first_store = len(_STORES)
    yield
    failures = []
    for store in reversed(_STORES[first_store:]):
        try:
            store.close()
        except Exception as exc:
            failures.append(type(exc).__name__)
    del _STORES[first_store:]
    current = threading.current_thread()
    leaked = [thread.name for thread in threading.enumerate()
              if thread not in baseline and thread is not current and thread.is_alive() and not thread.daemon]
    if failures or leaked:
        pytest.fail("test teardown leaked resources: " +
                    (f"audit store close errors={failures}; " if failures else "") +
                    (f"non-daemon threads still alive={leaked}" if leaked else ""),
                    pytrace=False)
