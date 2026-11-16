"""SQLAlchemy schema, split over two SQLite files.

* Tenant (simulator) database, `tenant_sim.db`: `users`, `files`, `permissions`, `flows`,
  `connections`. Owned by `SimulatorAdapter`; nothing else may open it.
* App database, `fyp_governance.db`: `assessments`, `remediation_plans`, `remediation_steps`.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

DB_PATH = Path(__file__).resolve().parent / "fyp_governance.db"  # app database
TENANT_DB_PATH = Path(__file__).resolve().parent / "tenant_sim.db"  # simulator state


class TenantBase(DeclarativeBase):
    """Tables of the simulated tenant."""


class AppBase(DeclarativeBase):
    """Tables this application owns."""


class User(TenantBase):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    department: Mapped[str] = mapped_column(String, nullable=False)
    job_title: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class File(TenantBase):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    site_name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    file_name: Mapped[str] = mapped_column(String, nullable=False)
    file_path: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    # None | Public | General | Confidential | Highly Confidential
    sensitivity_label: Mapped[str] = mapped_column(String, nullable=False)
    is_copilot_indexed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    permissions: Mapped[list["Permission"]] = relationship(back_populates="file")


class Permission(TenantBase):
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
    graph_json: Mapped[dict] = mapped_column(JSON, nullable=False)  # the Graph permission resource as served

    file: Mapped[File] = relationship(back_populates="permissions")

    __table_args__ = (Index("ix_permissions_file_id", "file_id"),)


class Flow(TenantBase):
    __tablename__ = "flows"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    flow_name: Mapped[str] = mapped_column(String, nullable=False)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    target_file_id: Mapped[str] = mapped_column(ForeignKey("files.id"), nullable=False)
    connection_type: Mapped[str] = mapped_column(String, nullable=False)  # user | service_principal
    is_critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    raw_definition_json: Mapped[dict] = mapped_column(JSON, nullable=False)


class Connection(TenantBase):
    """A Power Platform connection: the identity a flow's SharePoint actions run as."""

    __tablename__ = "connections"

    name: Mapped[str] = mapped_column(String, primary_key=True)  # connectionReferences[*].connectionName
    connection_type: Mapped[str] = mapped_column(String, nullable=False)  # user | service_principal
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))  # None for a service principal


class Assessment(AppBase):
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


class RemediationPlan(AppBase):
    """One approved-then-executed removal of a flagged permission. States and steps: see remediation.py."""

    __tablename__ = "remediation_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    state: Mapped[str] = mapped_column(String, nullable=False, index=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), nullable=False)
    permission_id: Mapped[str] = mapped_column(String, nullable=False, index=True)  # copied from the assessment
    file_id: Mapped[str] = mapped_column(String, nullable=False)
    strategy: Mapped[str] = mapped_column(String, nullable=False)  # service_principal | scoped_identity_grant
    exposed_before: Mapped[int | None] = mapped_column(Integer)  # exposed user counts: not computed yet
    exposed_after: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String)
    executed_by: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)

    steps: Mapped[list["RemediationStep"]] = relationship(
        back_populates="plan", order_by="RemediationStep.seq", cascade="all, delete-orphan")


class RemediationStep(AppBase):
    __tablename__ = "remediation_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    # PENDING | SUCCEEDED | FAILED | SKIPPED | ROLLED_BACK | ROLLBACK_FAILED
    status: Mapped[str] = mapped_column(String, nullable=False)
    before_state: Mapped[dict | None] = mapped_column(JSON)  # what the rollback needs to undo this step
    result: Mapped[dict | None] = mapped_column(JSON)  # flow run outcomes of PREFLIGHT / POSTFLIGHT
    error: Mapped[str | None] = mapped_column(String)

    plan: Mapped[RemediationPlan] = relationship(back_populates="steps")


@event.listens_for(Engine, "connect")
def _enable_sqlite_fk(dbapi_connection, _record):  # pragma: no cover - trivial
    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


def make_engine(path: Path | str = DB_PATH) -> Engine:
    return create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})


def init_db(engine: Engine) -> None:
    """Create any missing app tables. Never creates or touches tenant tables."""
    AppBase.metadata.create_all(engine, checkfirst=True)
