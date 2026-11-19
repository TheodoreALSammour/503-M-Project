#!/bin/sh
set -e

# Wait for PostgreSQL, create tables, seed demo data (only on an empty DB).
python - <<'EOF'
import time
from app import create_app
from app.extensions import db
from app.seed import seed

app = create_app()
for attempt in range(60):
    try:
        with app.app_context():
            db.create_all()
            seed()
        break
    except Exception as exc:  # database not ready yet
        print(f"waiting for database ({type(exc).__name__})...", flush=True)
        time.sleep(1)
else:
    raise SystemExit("database never became available")
EOF

exec gunicorn --bind 0.0.0.0:8000 --workers 3 --threads 4 --access-logfile - wsgi:app
