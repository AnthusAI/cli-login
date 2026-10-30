Feature: A product's target names where remote sign-in returns
  Remote sign-in sends the browser back to a callback page the product serves over HTTPS, not to the loopback
  callback a local sign-in uses. The CLI checks the broker's redirect against that address, so a target that
  configures a broker must name it, and a target without a broker must not.

  Scenario: A target with a broker names its HTTPS remote callback
    Given a target with a broker and an HTTPS remote callback
    Then the target is accepted
    And it keeps its loopback callback for local sign-in

  Scenario: A broker without a remote callback is refused
    Given a target with a broker and no remote callback
    Then the target is refused because it needs a remote callback

  Scenario: A remote callback without a broker is refused
    Given a target with a remote callback and no broker
    Then the target is refused because it needs a broker

  Scenario: A remote callback over plain HTTP is refused
    Given a target with a broker and a plain HTTP remote callback
    Then the target is refused
