import anthus_cli_login


def test_the_package_names_its_version_and_protocol_version():
    assert anthus_cli_login.__version__
    assert anthus_cli_login.PROTOCOL_VERSION == 1
