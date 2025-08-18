"""
Database models for POR (Purchase Order Request) system.
Defines the POR table structure and database configuration.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Database configuration - will be set dynamically based on company
DATABASE_URL = os.environ.get('DATABASE_URL', "sqlite:///a&p_por.db")

print("Using database at:", DATABASE_URL)

# Handle Railway's PostgreSQL URL format
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine with optimized settings
engine = create_engine(
    DATABASE_URL,
    future=True,
    poolclass=StaticPool,  # Better for single-threaded apps
    pool_pre_ping=True,    # Verify connections before use
    echo=False             # Set to True for SQL debugging
)

def get_session():
    """Get a new database session."""
    Session = sessionmaker(bind=engine)
    return Session()
