# ots_federation/models/teams.py
# Bundled from taky.cot.models.teams (taky-federation branch, commit e12a2af).
# MIT License — copyright Tim K (tkuester). Bundled here to decouple the
# federation engine from the full taky package.
# The 15-value Teams enum matches the ATAK group colour palette exactly.
# Federation group policy (groups.py) uses .value strings for mapping;
# codec.py uses isinstance checks against this enum.

import enum


class Teams(enum.Enum):
    WHITE = "White"
    YELLOW = "Yellow"
    ORANGE = "Orange"
    MAGENTA = "Magenta"
    RED = "Red"
    MAROON = "Maroon"
    PURPLE = "Purple"
    DARK_BLUE = "Dark Blue"
    BLUE = "Blue"
    CYAN = "Cyan"
    TEAL = "Teal"
    GREEN = "Green"
    DARK_GREEN = "Dark Green"
    BROWN = "Brown"
    UNKNOWN = "Cyan"  # same .value as CYAN — fallback sentinel
