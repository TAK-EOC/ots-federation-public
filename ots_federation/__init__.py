# ots_federation/__init__.py
# Standalone TAK federation engine extracted from taky (taky-federation branch
# commit e12a2af). Implements the gRPC FederatedChannel v2 protocol (fig.proto /
# TAK Product Center FIG spec) with loop-prevention, hop-limit enforcement
# group mapping, and mTLS. No dependency on the full taky package.
# Entry points:
#   from ots_federation import FederationManager      — orchestrator
#   from ots_federation.bus import LocalBus           — event bus protocol
#   from ots_federation.config import get_federation_config  — INI config parser
#   from ots_federation import models                 — CoT event model (bundled)

from ots_federation.manager import FederationManager

__all__ = ["FederationManager"]
