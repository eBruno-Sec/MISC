from sqlalchemy import Column, String, Text, DateTime, Float, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


class MissionStatus:
    PENDING = "pending"
    PLANNING = "planning"
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"
    COMPLETE = "complete"
    AWAITING_APPROVAL = "awaiting_approval"
    FAILED = "failed"


class Mission(Base):
    __tablename__ = "missions"

    id = Column(String, primary_key=True, default=_uuid)
    target = Column(String, nullable=False)
    scope = Column(Text, default="")
    status = Column(String, default=MissionStatus.PENDING)
    mode = Column(String, default="passive")
    current_phase = Column(String, nullable=True)
    context = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    logs = relationship("AgentLog", back_populates="mission", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="mission", cascade="all, delete-orphan")
    approvals = relationship("ApprovalRequest", back_populates="mission", cascade="all, delete-orphan")


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    agent = Column(String, nullable=False)
    level = Column(String, default="info")
    message = Column(Text, nullable=False)
    raw_output = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    mission = relationship("Mission", back_populates="logs")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, default="info")
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    remediation = Column(Text, nullable=True)
    found_by = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    mission = relationship("Mission", back_populates="findings")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    agent = Column(String, nullable=False)
    action = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    mission = relationship("Mission", back_populates="approvals")
