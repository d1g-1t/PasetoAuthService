# PasetoForge

PASETO v4 auth service on FastAPI. Stateless access tokens (Ed25519), encrypted refresh tokens (XChaCha20-Poly1305), token family rotation with reuse detection.

## Quick Start

```bash
git clone https://github.com/d1g-1t/PasetoAuthService.git
cd PasetoAuthService
make setup
```

API available at **http://localhost:8420/docs**

No local Python required — everything runs in Docker.

On Windows without `make`:
```bash
copy .env.example .env
docker compose up --build -d
```

## Architecture

```
POST /api/v1/auth/register     → create account (Argon2id)
POST /api/v1/auth/login        → access token (v4.public) + refresh cookie (v4.local)
POST /api/v1/auth/refresh      → rotate tokens (family reuse detection)
POST /api/v1/auth/logout       → blacklist access token + revoke refresh
POST /api/v1/auth/logout-all   → revoke all sessions
GET  /api/v1/auth/me           → current user
GET  /api/v1/auth/.well-known/paseto-public-key → public key (PASERK)
```

### Token Strategy

| Token   | PASETO   | Algorithm                   | Stored              | Lifetime |
|---------|----------|-----------------------------|---------------------|----------|
| Access  | v4.public | Ed25519                    | Client only         | 15 min   |
| Refresh | v4.local  | XChaCha20-Poly1305 + BLAKE2b | HttpOnly cookie + DB hash | 30 days  |

Access tokens are **signed** — any microservice can verify with the public key.
Refresh tokens are **encrypted** — payload hidden from client.

### Security

- **Argon2id** password hashing (auto-rehash on login)
- **Token family reuse detection** — compromised refresh token invalidates entire family
- **Redis blacklist** for immediate access token revocation on logout
- **Sliding window rate limiting** + account lockout after failed attempts
- **SHA-256(jti)** stored in DB — raw tokens never persisted
- **HttpOnly / Secure / SameSite=strict** cookies
- **PASERK** key serialization with rotation support (current + previous keys)

## Stack

Python 3.12 · FastAPI · pyseto · SQLAlchemy 2.0 (async) · asyncpg · PostgreSQL 16 · Redis 7 · Alembic · Pydantic v2

## Project Structure

```
src/paseto_forge/
├── api/                 # FastAPI routes + dependencies
│   └── v1/auth.py       # auth endpoints
├── models/              # SQLAlchemy ORM
├── schemas/             # Pydantic v2
├── repositories/        # data access layer
├── services/
│   ├── paseto_service   # token encode/decode/rotate
│   └── auth_service     # login/logout/refresh logic
├── config.py            # pydantic-settings
├── database.py          # async engine
├── redis_client.py      # connection pool
├── exceptions.py        # error hierarchy
└── main.py              # app factory + lifespan
```

## Key Management

Generate fresh keys:
```bash
make keys
```

Output:
```
PASETO_PRIVATE_KEY_PASERK=k4.secret.xxxxx
PASETO_PUBLIC_KEY_PASERK=k4.public.xxxxx
PASETO_LOCAL_KEY_PASERK=k4.local.xxxxx
```

For key rotation, set the old local key in `PASETO_PREVIOUS_LOCAL_KEYS_PASERK` (comma-separated). Both keys are tried on decode — zero-downtime rotation.

## Commands

```bash
make setup     # build + start (one command)
make down      # stop
make logs      # tail app logs
make test      # run tests
make clean     # remove everything
make keys      # generate new PASETO keys
make migrate   # run alembic migrations
```

## Ports

| Service    | Port |
|------------|------|
| API        | 8420 |
| PostgreSQL | 5499 |
| Redis      | 6399 |

Non-default ports — no conflicts with local services.

## Tests

```bash
make test
```

Unit tests cover PasetoService (token roundtrips, key isolation, error handling) and AuthService (login flow, rate limiting, reuse detection) without external dependencies.

## License

MIT
