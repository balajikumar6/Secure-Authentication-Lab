# Authentication Security Note

## Controls implemented
1. **Password storage:** passwords are hashed with Werkzeug's scrypt password-hashing implementation. Plaintext passwords are never stored.
2. **Server-side validation:** usernames are restricted to 3–32 alphanumeric/underscore characters; passwords must be 12–128 characters.
3. **Rate limiting:** login attempts are limited to five attempts per username/IP key per 60-second window. Excess requests receive HTTP 429.
4. **Generic errors:** login failures use the same message for unknown users and incorrect passwords, reducing account enumeration.
5. **Session protection:** successful login clears the previous session before assigning the user ID; sessions are permanent with a 15-minute lifetime. Cookies are HttpOnly and SameSite=Lax. Secure is enabled through `COOKIE_SECURE=1` when deployed behind HTTPS.
6. **Logout:** clears the session and expires the session cookie.
7. **Database safety:** SQL statements use parameterized queries.

## Test evidence
The automated test suite checks password hashing, successful login, password validation, generic login failures, rate limiting, authenticated route access, logout and duplicate registration handling. The captured test output is in `TEST_OUTPUT.txt`.

## Limitations / next steps
- The in-memory rate limiter is only suitable for a single-process demonstration; production should use a shared store and consider account-wide and network-wide throttles.
- Enable `COOKIE_SECURE=1` in HTTPS deployments and provide a stable secret through a secret manager.
- Add CSRF tokens or a robust origin-check strategy for browser-based cookie authentication.
- Add password reset with single-use expiring tokens, MFA, audit logging, monitoring and account recovery controls.
- Use HTTPS, a production database, backup/restore testing, dependency scanning and security review before real deployment.
- Do not deploy this lab as-is or use real user credentials.
