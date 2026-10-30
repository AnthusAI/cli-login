import sys


def before_scenario(context, scenario):
    # The memory agent needs Unix sockets; Windows uses Credential Manager instead.
    if "unix" in scenario.effective_tags and sys.platform == "win32":
        scenario.skip("Unix sockets only")
