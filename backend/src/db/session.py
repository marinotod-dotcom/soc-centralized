from contextlib import contextmanager
from typing import Iterator

from sqlalchemy.orm import Session

from config.database import SessionLocal


@contextmanager
def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
