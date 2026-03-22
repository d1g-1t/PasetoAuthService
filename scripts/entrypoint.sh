#!/bin/bash
set -e

if [ "$PASETO_PRIVATE_KEY_PASERK" = "auto" ]; then
    echo "Generating PASETO v4 keys..."
    eval "$(python scripts/generate_keys.py --env)"
    echo "Keys generated (ephemeral — set real keys for production)"
fi

echo "Waiting for PostgreSQL..."
python -c "
import socket, time, sys
for _ in range(30):
    try:
        s = socket.create_connection(('db', 5432), timeout=2)
        s.close()
        sys.exit(0)
    except (OSError, ConnectionRefusedError):
        time.sleep(1)
print('PostgreSQL not reachable', file=sys.stderr)
sys.exit(1)
"

echo "Running migrations..."
alembic upgrade head

echo "Starting PasetoAuthService..."
exec "$@"
