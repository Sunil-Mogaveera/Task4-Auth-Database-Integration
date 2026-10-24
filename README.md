# Task 4: Authentication & Database Integration

A beginner-friendly starter app using Node.js, Express, PostgreSQL, bcrypt password hashing, and database-backed sessions.

## Features
- Registration with server-side validation
- Login and logout
- Password hashing with bcryptjs
- Protected `/dashboard` route
- Password reset tokens stored as hashes and expiring after 15 minutes
- PostgreSQL user table and PostgreSQL-backed sessions
- Rate limiting for authentication forms, Helmet security headers, and HTTP-only session cookies
- Health endpoint at `/health`

## Requirements
- Node.js 22.x
- PostgreSQL database (local or hosted)
- npm

## Run locally
1. Install Node.js 22.x and PostgreSQL.
2. Create a database named `task4_auth`.
3. Copy `.env.example` to `.env`.
4. Update `DATABASE_URL` and set a long random `SESSION_SECRET`.
5. Run `npm install`.
6. Run `npm start`.
7. Open `http://localhost:3000`.

## Test
- `GET /health` should return JSON with `success: true`.
- Open `/register` and create an account.
- Confirm you are redirected to `/dashboard`.
- Log out, then log in with the same account.
- Open `/dashboard` in a logged-out browser to confirm it redirects to `/login`.
- Use `/forgot-password`. Without SMTP settings, the reset link is printed to the local server terminal for development only.
- Configure SMTP variables in `.env` to send actual password-reset emails.

## Environment variables
See `.env.example`. For hosted PostgreSQL providers requiring TLS, set `PGSSL=true` if their connection instructions require it.

## Security notes
- Never commit `.env` or secrets.
- Reset tokens expire after 15 minutes and are stored as SHA-256 hashes.
- The local-development reset link printed in the terminal must not be exposed in production.
- Use HTTPS in production.
- Configure SMTP before claiming that password reset emails are delivered.
- This starter is a foundation; test all flows and review deployment provider requirements before submission.

## Deployment

**Live Application:** https://task4-auth-database-integration-2.onrender.com

**GitHub Repository:** https://github.com/poojarym738-may/Task4-Auth-Database-Integration

The application is deployed on Render using Node.js, Express, and PostgreSQL.

### Deployment Configuration
- Build Command: `npm install`
- Start Command: `npm start`
- Environment variables: `DATABASE_URL`, `SESSION_SECRET`, and `NODE_ENV=production`
- Configure `PGSSL=true` if required by the PostgreSQL provider.
- Configure SMTP variables if password-reset emails are required.

### Deployment Testing
- Health endpoint: `/health`
- Registration: Tested
- Login with correct credentials: Tested
- Login with incorrect credentials: Tested
- Logout: Tested
- Protected dashboard after logout: Tested
- Password reset: Not yet verified

## Deliverables Checklist

- [x] GitHub repository
- [x] Live deployment URL
- [x] README documentation
- [ ] API/auth-flow documentation (verify whether a separate file exists)
- [ ] Screenshots or short demo in a shareable Drive folder
- [x] Signup, login, incorrect-password, logout, and protected-route tests
- [ ] Password-reset flow tested on the deployed application
-
