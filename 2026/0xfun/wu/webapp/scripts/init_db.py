#!/usr/bin/env python3
"""Initialize challenge database with seeded users and profile data."""
from app.app import init_db


if __name__ == "__main__":
    init_db()
    print("database initialized")
