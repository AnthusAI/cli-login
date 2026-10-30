import cli_login


def test_the_package_names_its_version_and_protocol_version():
    assert cli_login.__version__
    assert cli_login.PROTOCOL_VERSION == 1


def test_the_package_version_matches_the_project_version():
    # The release bumps both; the CLI sends __version__ to the approval page, so they must never drift apart.
    import re
    from pathlib import Path

    import cli_login

    pyproject = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text()
    project = pyproject.split("[project]", 1)[1].split("\n[", 1)[0]  # tomllib needs Python 3.11
    assert cli_login.__version__ == re.search(r'^version = "([^"]+)"$', project, re.MULTILINE).group(1)
