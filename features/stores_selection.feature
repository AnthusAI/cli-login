Feature: Choosing a secure store
  The library picks the right store for the machine, in a fixed order, and never offers plaintext. When nothing
  is usable it says exactly what to do.

  Scenario: macOS uses the Keychain under the product namespace
    Given a macOS machine
    When a store is opened for the target
    Then it is the Keychain store for the namespace "example-product"

  Scenario: Linux prefers the Secret Service
    Given a Linux machine where every store works
    When a store is opened for the target
    Then the chosen store is "Secret Service"

  Scenario: Linux moves on from a locked Secret Service to the kernel keyring
    Given a Linux machine whose Secret Service is locked and whose kernel keyring works
    When a store is opened for the target
    Then the chosen store is "kernel keyring"

  @unix
  Scenario: A container uses the memory agent
    Given a Linux machine whose Secret Service is absent, whose kernel keyring is blocked, and whose memory agent runs
    When a store is opened for the target
    Then the chosen store is "memory agent"

  @unix
  Scenario: Nothing usable fails with exact recovery steps
    Given a Linux machine where no store is usable
    When a store is opened for the target
    Then it fails with guidance naming "agent serve", "anthus-cli-login[linux]" and each store's reason
    And the guidance says plaintext storage is never used

  Scenario: Windows uses Credential Manager
    Given a Windows machine
    When a store is opened for the target
    Then the chosen store is "Windows Credential Manager"

  Scenario: An operator can choose a store explicitly
    Given a Linux machine where every store works
    When a store is opened for the target choosing "kernel-keyring"
    Then the chosen store is "kernel keyring"

  Scenario Outline: Plaintext can never be chosen
    Given a Linux machine where every store works
    When a store is opened for the target choosing "<choice>"
    Then it fails saying plaintext storage is never used

    Examples:
      | choice    |
      | file      |
      | plaintext |
      | keyring   |

  Scenario: An explicit choice that is unusable does not fall back
    Given a Linux machine whose Secret Service is locked and whose kernel keyring works
    When a store is opened for the target choosing "secret-service"
    Then it fails with guidance mentioning "unlock"

  Scenario: An explicit choice from the wrong platform is refused
    Given a Linux machine where every store works
    When a store is opened for the target choosing "credential-manager"
    Then it fails saying the store is not available on this platform
