# Broker protocol, version 1

This is the contract between a CLI, a product's broker and the product's approval pages. A client in any
language implements the CLI side from this page and runs `features/remote_sign_in.feature` against it. The
Python client is `anthus_cli_login.remote`; the broker is `anthus_cli_login.broker`.

Every broker answer carries `"protocol": 1`. A change to anything below bumps the version.

## Roles and secrets

| Who | Knows | Sends |
|---|---|---|
| The CLI | the PKCE verifier V, the poll secret P, the OpenID nonce | `S256(V)`, `sha256(P)` (hex), the nonce |
| The broker | the hashes, the matching code, the authorization code until it is collected | nothing secret except the code, once, to a poll that knows P |
| The approval pages | a browser nonce N (in a first-party cookie) | `sha256(N)` to the broker on bind, N on complete |

The broker never holds a token, and the authorization code is useless without V.

**T and the matching code together are an approval capability.** Whoever opens the URL and signs in first owns the
session the waiting CLI receives, and the URL and code are often relayed through chat. A CLI that knows who should
approve passes that person's email (`expected_email` in the Python client). It then refuses, and stores nothing,
when someone else approved. The CLI always prints the identity it signed in as.

## Function URL (public; the CLI calls it)

Both routes take and answer JSON with `cache-control: no-store` and `x-content-type-options: nosniff`.

Each caller is rate-limited per route. A caller is an IPv4 address or an IPv6 /64, because one IPv6 host can use
many addresses. Too many calls answer `429 {"error": "too_many_requests", "retry_after": 60}` with a
`retry-after` header.

Malformed input answers `400 {"error": "invalid_request"}`, never a server error. The broker's reserved
concurrency bounds what it can cost in total.

### `POST /start`

```json
{
  "protocol": 1,
  "client_id": "<the product's Cognito client id>",
  "target": "<the API endpoint to sign in to>",
  "code_challenge": "<base64url S256 of V, 43 characters>",
  "code_challenge_method": "S256",
  "poll_secret_hash": "<hex sha256 of P>",
  "nonce": "<16 to 128 characters of [A-Za-z0-9_-]>",
  "requester": {"host": "<machine name>", "version": "<CLI version>", "note": "<optional>"}
}
```

`200`:

```json
{
  "protocol": 1,
  "transaction": "<T, 22 characters>",
  "matching_code": "BCDF-GHJK",
  "approval_url": "https://<product>/cli/approve?t=<T>",
  "interval": 5,
  "expires_at": 1767225600
}
```

`400` with `error`:
- `unsupported_protocol`;
- `invalid_client`;
- `invalid_target`;
- `invalid_request` (with `field`).

A requester too large for one DynamoDB item, the platform's 400 KB limit, is `invalid_request` on `requester`.

The CLI prints only the approval URL and the matching code.

### `POST /poll`

```json
{"transaction": "<T>", "poll_secret": "<P>"}
```

| Answer | Meaning | The CLI |
|---|---|---|
| `200 {"code": "...", "redirect_uri": "https://<product>/cli/callback"}` | Approved. The code is handed over once, and the transaction is deleted. | Exchanges the code |
| `400 {"error": "authorization_pending", "interval": n}` | Nobody has approved yet | Waits `interval` seconds and polls again |
| `400 {"error": "slow_down", "interval": n}` | Polled sooner than the interval | Uses the new, longer interval |
| `400 {"error": "access_denied"}` | Denied on the approval page or at the provider | Stops |
| `400 {"error": "expired_token"}` | Expired, already collected, unknown, or a wrong P (these are indistinguishable) | Stops |

A network failure while polling is safe to retry.

### The exchange (CLI to provider)

`POST <token endpoint>` with `grant_type=authorization_code`, `client_id`, `code`, `redirect_uri` (from the
poll) and `code_verifier=V`.

The CLI checks:
- that `redirect_uri` equals its target's `remote_callback_uri`, and that the `approval_url` from `/start` is
  on that URI's origin. A target with a broker must name its remote callback, even when its local sign-in uses a
  loopback callback;
- that the ID token's `nonce` equals its own;
- that the approver's email is the expected one, when one is given.

It then passes the response to the session store, which checks issuer, audience, `token_use` and expiry.

A network failure during the exchange is **not** retried, because the code may already be spent. The CLI starts
again.

The CLI clamps the broker's timing, whatever the broker says:
- the poll interval stays between 1 and 60 seconds;
- the wait for an approval is at most 900 seconds.

## Direct invocation (private; the product's pages call it with IAM)

Each invocation takes and answers a JSON object. It carries `"cli_login": "private-v1"` and no `requestContext`.
Anything with a `requestContext` is treated as a function URL request.

A failure answers `{"ok": false, "error": "unavailable"}` and says nothing more.

| `operation` | Fields | Effect |
|---|---|---|
| `describe` | `transaction` | For a pending, unexpired transaction: `client_id`, `target`, `requester`, `matching_code`, `code_challenge`, `nonce`, `redirect_uri`, `expires_at` |
| `bind` | `transaction`, `nonce_hash` | Pending to bound, once. After this, nobody else can approve it. |
| `complete` | `transaction`, `nonce`, `code` | Bound to approved, only when `sha256(nonce)` equals the bound hash |
| `deny` | `transaction` | Pending or bound to denied |

## The pages (on the product's own domain)

1. **`GET /cli/approve?t=T`.** The page calls `describe` and shows the requester, the matching code, the target
   and what the session can do, and says that the CLI will be signed in as the approver. It sets the CSRF cookie
   `__Secure-cli_login_csrf` (`SameSite=Strict`, `Path=/cli/approve`).
2. **`POST /cli/approve`.** The page checks the CSRF value against the cookie.
   - **Deny** calls `deny`.
   - **Approve** needs the "this code matches" confirmation. The page then:
     - makes N;
     - calls `bind` with `sha256(N)`;
     - sets N in the cookie `__Secure-cli_login_nonce` (`SameSite=Lax`, `Path=/cli/callback`, ten minutes);
     - redirects to `/oauth2/authorize` with the transaction's `client_id`, `redirect_uri`, `code_challenge`
       (S256) and `nonce`, and `state=T.N`.
3. **`GET /cli/callback?state=T.N&code=...`.** The page checks N against its cookie, then calls `complete`. An
   `error` from the provider calls `deny` instead.

Every page sends:
- `Cache-Control: no-store`;
- `Referrer-Policy: no-referrer`;
- `X-Frame-Options: DENY`;
- `X-Content-Type-Options: nosniff`;
- a CSP with `frame-ancestors 'none'` and `form-action 'self' <the provider's origin>`. The approve POST's 303 to
  the provider counts as a form submission.

## Lifetimes

- A transaction lasts 600 seconds. DynamoDB's TTL deletes it later, so the broker also checks `expires_at` on
  every read.
- The poll interval starts at 5 seconds, and each `slow_down` adds 5.
- The rate limits per caller are 10 starts and 120 polls a minute.
