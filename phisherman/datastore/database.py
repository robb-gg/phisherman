"""SQLAlchemy async database configuration and session management."""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from phisherman.config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


# Global variables initialized directly
engine = create_async_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    pool_pre_ping=True,
    echo=settings.debug,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


def get_engine():
    """Get the async engine."""
    return engine


def get_session_local():
    """Get the async session factory."""
    return AsyncSessionLocal


async def init_db() -> None:
    """Initialize database (create tables if they don't exist)."""
    # Import all models to ensure they are registered with Base
    from phisherman.datastore import models  # noqa: F401

    async with engine.begin() as conn:
        # In production, you should use Alembic migrations instead
        # This is just for development convenience
        if settings.debug:
            await conn.run_sync(Base.metadata.create_all)
