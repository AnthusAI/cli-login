
Feature: A renewable command-line session
  A person signs in once and the command-line tool keeps working without asking again, while every
  secret stays in the operating system's secure store and no token is ever shown.

  Scenario: Local sign-in stores a session and reveals no token
    Given a target with an isolated provider and secure store
    When the person completes the local sign-in
    Then the tool reports the person's identity
    And the report contains no token
    And the secure store holds the session

  Scenario: A restarted tool renews after 25 simulated hours without a browser
    Given a target with an isolated provider and secure store
    And the person has signed in
    When a restarted tool is used after 25 simulated hours
    Then it renews with the stored refresh token and opens no browser
    And this evidence is labelled simulated rather than elapsed live testing

  Scenario: A provider outage keeps the session
    Given a target with an isolated provider and secure store
    And the person has signed in
    When the provider is unavailable at renewal time
    Then the tool reports a temporary failure
    And the stored session is unchanged

  Scenario: A revoked session ends and never widens access
    Given a target with an isolated provider and secure store
    And the person has signed in
    When the provider says the refresh token was revoked
    Then the tool asks the person to sign in again
    And the stored session is removed

  Scenario: A token for another person is refused
    Given a target with an isolated provider and secure store
    And the person has signed in
    When the provider returns a token for a different subject
    Then nothing new is saved
    And the stored session is unchanged

  Scenario: A token for another issuer or client is refused
    Given a target with an isolated provider and secure store
    When the provider returns a token for another issuer
    Then nothing is saved

  Scenario: Logout with the provider offline is honest
    Given a target with an isolated provider and secure store
    And the person has signed in
    When the person signs out while the provider is unreachable
    Then the local session is removed
    And remote revocation is reported as unconfirmed

  Scenario: Logout with the provider reachable revokes the token
    Given a target with an isolated provider and secure store
    And the person has signed in
    When the person signs out while the provider is reachable
    Then the local session is removed
    And remote revocation is reported as confirmed

  Scenario: A locked store fails closed
    Given a target with an isolated provider and secure store
    And the person has signed in
    When the secure store is locked
    Then asking for headers fails with recovery guidance
    And the provider is not contacted

  Scenario: Local sign-in without enrollment hooks is unchanged
    Given a target with an isolated provider and secure store
    When the person completes the local sign-in
    Then the sign-in request carries no nonce
    And the secure store holds the session

  Scenario: Local sign-in enrolls the login before storing it
    Given a target with an isolated provider and secure store
    And the product prepares an enrollment with a nonce
    When the person completes the local sign-in with enrollment
    Then the sign-in request carries the product's nonce
    And enrollment ran with the raw state and the opaque enrollment
    And the secure store held nothing while enrolling
    And the secure store holds the session

  Scenario: A sign-in answered for a different nonce is refused
    Given a target with an isolated provider and secure store
    And the product prepares an enrollment with a nonce
    And the provider answers tokens for a different nonce
    When the person tries the local sign-in with enrollment
    Then the sign-in is refused with "nonce_mismatch"
    And the secure store holds no session
    And the refresh token was revoked

  Scenario: A failed enrollment stores nothing and revokes the refresh token
    Given a target with an isolated provider and secure store
    And the product prepares an enrollment with a nonce
    And enrollment will fail
    When the person tries the local sign-in with enrollment
    Then the sign-in is refused with "enrollment failed"
    And the secure store holds no session
    And the refresh token was revoked
