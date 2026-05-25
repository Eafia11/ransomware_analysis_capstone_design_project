#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../backend"
python -c "from app.core.config import settings; from app.db.session import init_db; init_db(); print(f'Database initialized: {settings.database_url}')"
