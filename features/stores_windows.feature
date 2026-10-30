Feature: The Windows Credential Manager store
  On Windows the session lives in Credential Manager under the target name "<namespace>/<key>". A credential
  holds at most 2,560 bytes, so a larger session is split into chunks, written so that an interrupted save
  never leaves a mixture of old and new pieces.

  Scenario: A small session is saved in one credential
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And the session "stored-session" is saved under the key "key-1"
    Then reading "key-1" returns "stored-session"
    And the credential "example-product/key-1" exists
    And the Credential Manager holds 1 credential

  Scenario: A large session is split into chunks and read back whole
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And a session of 7000 characters is saved under the key "key-1"
    Then reading "key-1" returns the long session
    And no credential holds more than 2560 bytes
    And the Credential Manager holds 4 credentials

  Scenario: Multi-byte characters survive chunk boundaries
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And a session of 3000 two-byte characters is saved under the key "key-1"
    Then reading "key-1" returns the long session

  Scenario: Replacing a large session with a small one removes the stale chunks
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And a session of 7000 characters is saved under the key "key-1"
    And the session "small" is saved under the key "key-1"
    Then reading "key-1" returns "small"
    And the Credential Manager holds 1 credential

  Scenario: Replacing a large session with another large one leaves only the new chunks
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And a session of 7000 characters is saved under the key "key-1"
    And a session of 5000 characters is saved under the key "key-1"
    Then reading "key-1" returns the long session
    And the Credential Manager holds 3 credentials

  Scenario Outline: An interrupted save never mixes old and new chunks
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And a session of 7000 characters is saved under the key "key-1"
    And a save of a different 7000-character session is interrupted after <writes> writes
    Then reading "key-1" returns either the old or the new session, whole

    Examples:
      | writes |
      | 0      |
      | 1      |
      | 2      |
      | 3      |
      | 4      |

  Scenario: Deleting removes the header and every chunk
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And a session of 7000 characters is saved under the key "key-1"
    And the key "key-1" is deleted
    Then reading "key-1" returns nothing
    And the Credential Manager holds 0 credentials

  Scenario: A damaged chunk is reported, not returned
    Given an empty Credential Manager
    When a Windows store is opened for the namespace "example-product"
    And a session of 7000 characters is saved under the key "key-1"
    And one stored chunk is altered
    Then reading "key-1" fails saying the session is damaged

  Scenario: A Credential Manager that refuses access fails closed without leaking text
    Given a Credential Manager that refuses access
    When a Windows store is opened for the namespace "example-product"
    Then reading "key-1" fails with guidance and no secret text
