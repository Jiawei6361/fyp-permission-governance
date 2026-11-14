"""SQLAlchemy schema for the Milestone 1 benchmark database (SQLite)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

DB_PATH = Path(__file__).resolve().parent / "fyp_governance.db"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    department: Mapped[str] = mapped_column(String, nullable=False)
    job_title: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class File(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    site_name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    file_name: Mapped[str] = mapped_column(String, nullable=False)
    file_path: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    # None | Public | General | Confidential | Highly Confidential
    sensitivity_label: Mapped[str] = mapped_column(String, nullable=False)
    is_copilot_indexed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    permissions: Mapped[list["Permission"]] = relationship(back_populates="file")


class Permission(Base):
    """One Graph v1.0 driveItem permission, flattened.

    `principal_id` is polymorphic and therefore not a foreign key: it holds a user id
    (principal_type 'user'), a group id ('group'), the literal
    'everyone_except_external' ('everyone_except_external'), or the permission id of a
    sharing link ('link'). verify_milestone1.py checks that every 'user' principal
    resolves to users.id.
    """

    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # Graph permission id
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), nullable=False)
    principal_id: Mapped[str] = mapped_column(String, nullable=False)
    principal_type: Mapped[str] = mapped_column(String, nullable=False)
    roles_json: Mapped[list] = mapped_column(JSON, nullable=False)
    link_scope: Mapped[str | None] = mapped_column(String)  # anonymous | organization | users | None
    inherited_from: Mapped[str | None] = mapped_column(String)  # inheritedFrom.path, None if direct
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime)

    file: Mapped[File] = relationship(back_populates="permissions")

    __table_args__ = (Index("ix_permissions_file_id", "file_id"),)


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    flow_name: Mapped[str] = mapped_column(String, nullable=False)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    target_file_id: Mapped[str] = mapped_column(ForeignKey("files.id"), nullable=False)
    connection_type: Mapped[str] = mapped_column(String, nullable=False)  # user | service_principal
    is_critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    raw_definition_json: Mapped[dict] = mapped_column(JSON, nullable=False)


class Assessment(Base):
    """Milestone 2: one scored, flow-correlated permission within an immutable scan snapshot."""

    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    reference_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    permission_id: Mapped[str] = mapped_column(String, nullable=False)
    file_id: Mapped[str] = mapped_column(String, nullable=False)
    drive_id: Mapped[str] = mapped_column(String, nullable=False)
    principal_id: Mapped[str] = mapped_column(String, nullable=False)
    principal_type: Mapped[str] = mapped_column(String, nullable=False)
    roles_json: Mapped[list] = mapped_column(JSON, nullable=False)
    link_scope: Mapped[str | None] = mapped_column(String)
    exposure: Mapped[str | None] = mapped_column(String)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    score_breakdown: Mapped[dict] = mapped_column(JSON, nullable=False)
    reasons: Mapped[list] = mapped_column(JSON, nullable=False)
    is_overshared: Mapped[bool] = mapped_column(Boolean, nullable=False)
    is_stale: Mapped[bool] = mapped_column(Boolean, nullable=False)
    days_since_access: Mapped[int | None] = mapped_column(Integer)
    # BREAKAGE_CRITICAL | SAFE_TO_REVOKE | KEEP_REQUIRED
    classification: Mapped[str] = mapped_column(String, nullable=False, index=True)
    dependent_flows: Mapped[list] = mapped_column(JSON, nullable=False)
    mitigation: Mapped[str | None] = mapped_column(String)


@event.listens_for(Engine, "connect")
def _enable_sqlite_fk(dbapi_connection, _record):  # pragma: no cover - trivial
    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


def make_engine(path: Path | str = DB_PATH) -> Engine:
    return create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})


def init_db(engine: Engine) -> None:
    """Create any missing tables (e.g. `assessments`) without touching existing seeded data."""
    Base.metadata.create_all(engine, checkfirst=True)
