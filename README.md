# cli-login

One CLI login for every Anthus product, without long-lived keys.

- **Sign in on this machine or from another device.** `login --remote` prints a URL and a short matching code; you
  approve on your phone or laptop, and the waiting CLI receives its own renewable session. No access key, pasted
  code or token passes through chat.
- **Secure storage, never plain text.** macOS Keychain, Linux Secret Service, the Linux kernel keyring, a
  memory-only agent for cloud machines, or Windows Credential Manager.
- **Renewal and honest logout.** Sessions renew with the refresh token. Logout revokes it, and says so when it
  could not.
- **A broker per deployment.** A small Lambda function and DynamoDB table that hands one authorization code to the
  one CLI that asked for it, and never holds a token.

Status: design. See [docs/design.md](docs/design.md). Nothing is released yet.

The library targets Cognito user pools with the authorization-code flow and PKCE. Each product supplies its own
issuer, client and endpoints; this repository holds none.

## License

MIT
