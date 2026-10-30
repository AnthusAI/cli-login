Feature: The macOS Keychain store
  Sessions saved by an earlier tool keep working, and a missing Keychain never degrades to plain text.

  Scenario: An existing session is found under the same service and key
    Given a Keychain holding a session under service "papyrus-newsroom-oauth" and key "site-key-1"
    When a store is opened for the namespace "papyrus-newsroom-oauth"
    Then reading "site-key-1" returns that session

  Scenario: A different namespace does not see the session
    Given a Keychain holding a session under service "papyrus-newsroom-oauth" and key "site-key-1"
    When a store is opened for the namespace "other-product"
    Then reading "site-key-1" returns nothing

  Scenario: An unavailable Keychain fails closed
    Given a Keychain that cannot be read
    When a store is opened for the namespace "papyrus-newsroom-oauth"
    Then reading fails with recovery guidance and no secret text
