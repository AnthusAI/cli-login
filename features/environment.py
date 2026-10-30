import sys


def before_scenario(context, scenario):
    # Locks are POSIX only until the Windows story lands.
    if "posix" in scenario.effective_tags and sys.platform == "win32":
        scenario.skip("POSIX locks only")
