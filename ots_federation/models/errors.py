# ots_federation/models/errors.py
# Bundled from taky.cot.models.errors (taky-federation branch, commit e12a2af).
# MIT License — copyright Tim K (tkuester). Bundled here to decouple the
# federation engine from the full taky package.


class UnmarshalError(Exception):
    """Raised when a CoT XML element cannot be unmarshalled into a model object."""
