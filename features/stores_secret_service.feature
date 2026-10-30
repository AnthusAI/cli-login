Feature: The Linux Secret Service store
  On a Linux desktop the session lives in the user's keyring, attributed by product and key. A keyring that is
  absent or locked is reported as unavailable with guidance, and nothing is ever written to a file instead.

  Scenario: A session is saved and read back
    Given an unlocked Secret Service keyring
    When a Secret Service store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    Then reading "key-1" returns "stored-session"
    And the keyring item is labelled "example-product/key-1"

  Scenario: Saving again replaces the session
    Given an unlocked Secret Service keyring
    When a Secret Service store is opened for the namespace "example-product"
    And the session "first" is saved under the key "key-1"
    And the session "second" is saved under the key "key-1"
    Then reading "key-1" returns "second"

  Scenario: Another product does not see the session
    Given an unlocked Secret Service keyring
    When a Secret Service store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    Then a store for the namespace "other-product" reading "key-1" returns nothing

  Scenario: Deleting removes the session
    Given an unlocked Secret Service keyring
    When a Secret Service store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    And the key "key-1" is deleted
    Then reading "key-1" returns nothing

  Scenario: A locked keyring is unavailable and says how to unlock it
    Given a locked Secret Service keyring
    When a Secret Service store is probed
    Then it is unavailable with guidance mentioning "unlock"

  Scenario: No D-Bus is unavailable and no raw text leaks
    Given a machine with no Secret Service
    When a Secret Service store is probed
    Then it is unavailable with guidance mentioning "memory agent"
    And the guidance contains no backend text

  Scenario: A keyring that locks after selection fails closed
    Given an unlocked Secret Service keyring
    When a Secret Service store is opened for the namespace "example-product"
    And the keyring becomes locked
    Then reading "key-1" fails with guidance mentioning "unlock"

  Scenario: A missing optional dependency is unavailable and names the extra
    Given the secretstorage package is not installed
    When a Secret Service store is probed
    Then it is unavailable with guidance mentioning "cli-login[linux]"
