"""Compatibility module alias; the main application owns this implementation."""

import sys

from campus_autoconnect.services import package_inspection as shared

sys.modules[__name__] = shared
