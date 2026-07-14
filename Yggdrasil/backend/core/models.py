from sqlalchemy import Column, String, Text, DateTime, Float, Integer, JSON, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from core.timeutil import utcnow
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


class FindingTag:
    NONE = None
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"
    FIXED = "fixed"


class Confidence:
    """How sure Yggdrasil is that a finding is real. Every finding is REPORTED;
    the label tells the analyst how much to trust it, so nothing is hidden and
    nothing is over-claimed.
      confirmed - actively proven/exploited (differential bypass, DB error with a
                  clean control, template evaluated, forged token accepted, IDOR
                  differential, sqlmap-confirmed).
      high      - strong tool/differential signal, not exploited (active ZAP
                  alert, raw HTML reflection, exact-version CVE).
      medium    - heuristic / pattern match (missing header, tech fingerprint,
                  exposed manifest, unverified secret).
      low       - weak or single signal; needs manual review (reachable path,
                  possible reflection in a non-HTML context, suspected-pending).
    """
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ORDER = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}

    @staticmethod
    def infer(severity: str) -> str:
        """Default label when a finding site doesn't set one explicitly, derived
        from severity so every finding still carries a sensible confidence."""
        s = (severity or "info").lower()
        if s in ("critical", "high"):
            return "high"
        if s == "medium":
            return "medium"
        return "low"


class Mission(Base):
    __tablename__ = "missions"

    id = Column(String, primary_key=True, default=_uuid)
    target = Column(String, nullable=False)
    scope = Column(Text, default="")
    status = Column(String, default=MissionStatus.PENDING)
    mode = Column(String, default="passive")
    current_phase = Column(String, nullable=True)
    context = Column(JSON, default=dict)
    scope_rules = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime, nullable=True)

    logs = relationship("AgentLog", back_populates="mission", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="mission", cascade="all, delete-orphan")
    approvals = relationship("ApprovalRequest", back_populates="mission", cascade="all, delete-orphan")
    notes = relationship("MissionNote", back_populates="mission", cascade="all, delete-orphan")
    exchanges = relationship("HttpExchange", back_populates="mission", cascade="all, delete-orphan")
    auth_profiles = relationship("AuthProfile", back_populates="mission", cascade="all, delete-orphan")


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    agent = Column(String, nullable=False)
    level = Column(String, default="info")
    message = Column(Text, nullable=False)
    raw_output = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utcnow)

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
    # How sure we are it's real: confirmed | high | medium | low. Every finding is
    # reported; this labels trust rather than gating disclosure.
    confidence = Column(String, default="medium")
    # Pentester workflow fields
    tag = Column(String, nullable=True)           # confirmed | false_positive | reported | fixed
    is_manual = Column(Boolean, default=False)    # added manually by user
    analyst_notes = Column(Text, nullable=True)   # inline analyst commentary
    timestamp = Column(DateTime, default=utcnow)

    mission = relationship("Mission", back_populates="findings")
    exchanges = relationship("HttpExchange", back_populates="finding", cascade="all, delete-orphan")


class HttpExchange(Base):
    """A captured HTTP request/response pair — first-class PoC evidence.

    The scanners already issue the request that proves a finding; we persist it
    here (linked to the finding) so the analyst gets reproducible curl / raw HTTP
    and a copy-ready report block. Sensitive request/response headers are redacted
    at rest (see BaseAgent.add_exchange)."""
    __tablename__ = "http_exchanges"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=True)
    method = Column(String, default="GET")
    url = Column(Text, nullable=False)
    request_headers = Column(JSON, default=dict)
    request_body = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    response_headers = Column(JSON, default=dict)
    response_body = Column(Text, nullable=True)     # snippet, capped
    duration_ms = Column(Integer, nullable=True)
    source = Column(String, nullable=True)          # tool/agent that produced it
    notes = Column(Text, nullable=True)
    redacted = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    mission = relationship("Mission", back_populates="exchanges")
    finding = relationship("Finding", back_populates="exchanges")


class AuthProfile(Base):
    """A named session/role used for cross-role access-control testing (IDOR/BOLA).

    Holds the auth headers (Cookie / Authorization / ...) that authenticate one
    account. Values are stored as supplied so the workbench can replay a request
    as that role; the API always redacts them on read (see routers._profile_dict)."""
    __tablename__ = "auth_profiles"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    name = Column(String, nullable=False)
    role = Column(String, nullable=True)
    headers = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)

    mission = relationship("Mission", back_populates="auth_profiles")


class MissionNote(Base):
    __tablename__ = "mission_notes"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=utcnow)

    mission = relationship("Mission", back_populates="notes")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(String, primary_key=True, default=_uuid)
    mission_id = Column(String, ForeignKey("missions.id"), nullable=False)
    agent = Column(String, nullable=False)
    action = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime, nullable=True)

    mission = relationship("Mission", back_populates="approvals")
