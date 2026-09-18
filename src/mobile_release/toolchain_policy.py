"""Shared expected release baselines; importing this module performs no IO.

These constants describe policy, never observed or installed tool versions.
"""

XCODE_VERSION = "26.3"
XCODE_BUILD = "17C529"
BUNDLETOOL_VERSION = "1.18.3"
BUNDLETOOL_SHA256 = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
# Upstream release1.18.3 asset329035725 metadata, independently recorded before
# this constant was selected. The size is a bound, never a substitute for SHA256.
BUNDLETOOL_MAX_BYTES = 32_520_401
