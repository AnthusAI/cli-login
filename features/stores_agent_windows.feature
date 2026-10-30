Feature: The memory agent on Windows
  The memory agent is not supported on Windows in this version. Windows uses Credential Manager, and anyone
  who tries to start the agent there is told so.

  Scenario: Windows is not supported yet
    Given a Windows machine
    Then starting the agent fails saying Windows is not supported
