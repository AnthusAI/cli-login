Feature: The Linux kernel keyring store
  On a Linux machine without a desktop keyring the session can live in the kernel keyring. It lasts until the
  machine restarts, or until the persistent keyring expires. Containers that block the system calls are
  detected before anything is stored.

  Scenario: A session is saved and read back
    Given a working kernel keyring
    When a kernel keyring store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    Then reading "key-1" returns "stored-session"

  Scenario: Saving again replaces the session in place
    Given a working kernel keyring
    When a kernel keyring store is opened for the namespace "example-product"
    And the session "first" is saved under the key "key-1"
    And the session "second" is saved under the key "key-1"
    Then reading "key-1" returns "second"
    And the keyring holds 1 session

  Scenario: Another product does not see the session
    Given a working kernel keyring
    When a kernel keyring store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    Then a store for the namespace "other-product" reading "key-1" returns nothing

  Scenario: Deleting removes the session and deleting twice is harmless
    Given a working kernel keyring
    When a kernel keyring store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    And the key "key-1" is deleted
    And the key "key-1" is deleted
    Then reading "key-1" returns nothing

  Scenario: A kernel without persistent keyrings uses the user keyring
    Given a kernel keyring without persistent keyrings
    When a kernel keyring store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    Then reading "key-1" returns "stored-session"

  Scenario Outline: A container that blocks the system calls is unavailable
    Given a kernel keyring blocked with <error>
    When a kernel keyring store is probed
    Then it is unavailable with guidance mentioning "memory agent"

    Examples:
      | error  |
      | EPERM  |
      | ENOSYS |

  Scenario: A probe leaves nothing behind
    Given a working kernel keyring
    When a kernel keyring store is probed
    Then the keyring holds 0 sessions
