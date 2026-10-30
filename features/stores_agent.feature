@unix
Feature: The memory agent
  On a cloud machine with no desktop keyring, a small agent holds the session in memory only, behind a private
  Unix socket, in the style of ssh-agent. It never writes a secret to disk, serves only its own user, and
  forgets everything when it stops.

  Scenario: A running agent stores and returns a session
    Given a running memory agent for the namespace "example-product"
    When the session "stored-session" is saved under the key "key-1" through the agent
    Then reading "key-1" through the agent returns "stored-session"

  Scenario: The socket and its directory are private
    Given a running memory agent for the namespace "example-product"
    Then the agent socket has mode 0600 inside a directory with mode 0700

  Scenario: The agent writes no secret to disk
    Given a running memory agent for the namespace "example-product"
    When the session "stored-session" is saved under the key "key-1" through the agent
    Then no file under the state directory contains "stored-session"

  Scenario: Stopping the agent forgets the session
    Given a running memory agent for the namespace "example-product"
    When the session "stored-session" is saved under the key "key-1" through the agent
    And the agent is stopped
    Then the agent is not running
    And its socket is gone
    And reading through the agent fails with guidance mentioning "agent serve"

  Scenario: Deleting a session removes it
    Given a running memory agent for the namespace "example-product"
    When the session "stored-session" is saved under the key "key-1" through the agent
    And the key "key-1" is deleted through the agent
    Then reading "key-1" through the agent returns nothing

  Scenario: Another product's client is refused
    Given a running memory agent for the namespace "example-product"
    Then a client for the namespace "other-product" at the same socket is unavailable

  Scenario: No agent running gives start-up guidance
    Given no memory agent is running
    Then a client store is unavailable with guidance mentioning "agent serve"

  Scenario: A second agent for the same product is refused
    Given a running memory agent for the namespace "example-product"
    Then starting another agent for the namespace "example-product" fails

  Scenario: A stale socket from a crashed agent is replaced
    Given a stale socket left by a crashed agent
    When an agent is started for the namespace "example-product"
    Then the agent answers a ping

  Scenario: A malformed request is rejected without harming the agent
    Given a running memory agent for the namespace "example-product"
    When a client sends garbage and an oversized length
    Then the agent still answers a ping

  Scenario: An invalid key is refused
    Given a running memory agent for the namespace "example-product"
    Then saving under the key "../x" through the agent fails

  Scenario: The command line starts, reports and stops an agent
    Given an empty private state directory
    When the agent command "serve --background" is run
    Then the agent command "status" reports it running
    And the agent command "stop" reports it stopped
    And the agent command "status" reports it not running
