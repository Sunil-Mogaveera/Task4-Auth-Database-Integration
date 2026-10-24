# Authentication Flow Documentation

## Routes
| Method | Route | Purpose |
|---|---|---|
| GET | `/register` | Show registration form |
| POST | `/register` | Validate and create account |
| GET | `/login` | Show login form |
| POST | `/login` | Verify password and create session |
| POST | `/logout` | Destroy current session |
| GET | `/dashboard` | Protected page; redirects if logged out |
| GET | `/forgot-password` | Show password reset request form |
| POST | `/forgot-password` | Create expiring reset token |
| GET | `/reset-password/:token` | Show new-password form |
| POST | `/reset-password/:token` | Validate token and update password |
| GET | `/health` | Health-check JSON |

## Database model
`users`: `id`, `name`, `email` (unique), `password_hash`, `reset_token_hash`, `reset_expires_at`, `created_at`.

Session data is stored in PostgreSQL using `connect-pg-simple`.

## Security measures
- Passwords are hashed with bcryptjs (12 rounds); plaintext passwords are not stored.
- SQL statements use parameterized queries.
- Server-side validation checks names, email addresses, and password length.
- Login/register/reset endpoints have rate limiting.
- Session cookies are HTTP-only and use SameSite=Lax.
- Session ID is regenerated after successful login.
- Reset tokens are random, stored as hashes, expire after 15 minutes, and are cleared after use.
- Helmet adds common HTTP security headers.

## Important limitation
Actual password-reset email delivery requires SMTP credentials. Without SMTP, the reset link is printed to the local server terminal for development/testing only. Do not expose development reset links in production.
