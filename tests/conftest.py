# tests/conftest.py
# Adapted from taky conftest.py (taky-federation branch, commit e12a2af).
# Installs a pkg_resources shim before any test module is collected.
# Required on Python 3.12+ / setuptools >= 67 where pkg_resources is no longer
# bundled as a standalone module. Some transitive deps still import it; the
# shim provides the two symbols that matter.
# Also adds the proto package directory to sys.path so that the protoc-generated
# fig_pb2.py can resolve its bare `import binarypayload_pb2`.

import os
import sys
import types

# ── pkg_resources shim ────────────────────────────────────────────────────────
if "pkg_resources" not in sys.modules:
    _shim = types.ModuleType("pkg_resources")
    _shim.get_distribution = lambda x: type("D", (), {"version": "unknown"})()
    _shim.DistributionNotFound = Exception
    sys.modules["pkg_resources"] = _shim

# ── proto bare-import path shim ───────────────────────────────────────────────
_PROTO_DIR = os.path.join(
    os.path.dirname(__file__), "..", "ots_federation", "proto"
)
_PROTO_DIR = os.path.abspath(_PROTO_DIR)
if _PROTO_DIR not in sys.path:
    sys.path.insert(0, _PROTO_DIR)
