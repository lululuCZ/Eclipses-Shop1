# Eclipses Shop — server

Real backend: SQLite database (shared by everyone), bcrypt-hashed passwords,
signed httpOnly session cookies. Replaces the old localStorage-only version.

## Run it

```
npm install
npm start
```

Then open http://localhost:3000

On first run an admin account is created and its one-time password is
printed in the terminal — copy it now, it won't be shown again.

## Deploying for real

- Set a fixed `JWT_SECRET` env var (a long random string) so sessions
  survive restarts and aren't shared/guessable across deployments.
- Set `NODE_ENV=production` so session cookies require HTTPS.
- Put it behind HTTPS (e.g. Render, Railway, Fly.io, or your own server
  with a reverse proxy + Let's Encrypt) — cookies and passwords should
  never travel over plain HTTP.
- The SQLite file (`data.sqlite`) is your whole database — back it up.

## What's real now vs. before

- Accounts, catalog, and orders live in one shared SQLite database, not
  per-browser localStorage — every visitor sees the same shop and admin
  sees every order.
- Passwords are hashed with bcrypt server-side and never touch client code.
- Sessions are signed JWTs in httpOnly cookies — can't be forged or read
  from devtools the way a localStorage string could.
- Admin-only routes are enforced on the server, not just hidden in the UI.
