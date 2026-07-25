# ots_federation/models/detail.py
# Bundled from taky.cot.models.detail (taky-federation branch, commit e12a2af).
# MIT License — copyright Tim K (tkuester). Bundled to decouple from taky.

from .errors import UnmarshalError


class Detail:
    """Generic CoT <detail> element holder."""

    def __init__(self, elm):
        self.elm = elm

    def __repr__(self):
        return "<GenericDetail>"

    @staticmethod
    def is_type(tags):  # pylint: disable=unused-argument
        # Base class always matches (catch-all after more specific types fail).
        return True

    @property
    def has_marti(self):
        if self.elm is None:
            return False
        marti = self.elm.find("marti")
        if marti is None:
            return False
        return len(list(self.marti_cs)) > 0

    @property
    def marti_cs(self):
        """Callsigns in the Marti routing tag (empty if absent)."""
        if self.elm is None:
            return
        marti = self.elm.find("marti")
        if marti is None:
            return
        for dest in marti.iterfind("dest"):
            yield dest.get("callsign")

    @property
    def as_element(self):
        """Return the underlying lxml element (may be None if not parsed from XML)."""
        return self.elm

    @staticmethod
    def from_elm(elm):
        if elm.tag != "detail":
            raise UnmarshalError("Cannot create Detail from %s" % elm.tag)
        return Detail(elm)
