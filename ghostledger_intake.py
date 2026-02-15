#!/usr/bin/env python3
"""
GhostLedger Intake Pipeline
============================
FastAPI service that receives Google Form submissions via webhook,
validates them, converts to IntakeSubmission → Claim, and publishes
to the event bus.

This is the bridge between the live Google Form and the full system.

Usage:
    uvicorn ghostledger_intake:app --host 0.0.0.0 --port 8081

Requires:
    pip install fastapi uvicorn pydantic

Version: 1.0  —  February 2026
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request, status, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from pydantic import BaseModel, Field, field_validator

# ── Logging ──
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gl-intake")


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Environment-driven configuration. Reads from env vars in production."""
    INTAKE_API_KEY: str = os.environ.get("INTAKE_API_KEY", "gl_live_sk_intake_placeholder")
    WEBHOOK_SECRET: str = os.environ.get("WEBHOOK_SECRET", "whsec_placeholder")
    NATS_URL: str = os.environ.get("NATS_URL", "nats://localhost:4222")
    MAX_CLAIM_AMOUNT: float = float(os.environ.get("MAX_CLAIM_AMOUNT", "10000000"))
    CONSENT_EXPIRY_DAYS: int = int(os.environ.get("CONSENT_EXPIRY_DAYS", "90"))


config = Config()


# ============================================================================
# ENUMS (mirrors ghostledger_types.py)
# ============================================================================

class SupportContactStatus(str, Enum):
    YES_NO_RESOLUTION = "yes_no_resolution"
    YES_STILL_WAITING = "yes_still_waiting"
    NO_NOT_YET = "no_not_yet"


class ReferralSource(str, Enum):
    REDDIT = "reddit"
    TWITTER_X = "twitter_x"
    DISCORD = "discord"
    WORD_OF_MOUTH = "word_of_mouth"
    TIKTOK = "tiktok"
    OTHER = "other"


class HarmType(str, Enum):
    WAGE_THEFT = "wage_theft"
    PLATFORM_LOCKOUT = "platform_lockout"
    PAYOUT_WITHHOLDING = "payout_withholding"
    UNDISCLOSED_FEE = "undisclosed_fee"
    OTHER = "other"


class CaseStatus(str, Enum):
    DRAFT = "draft"
    FILED = "filed"
    UNDER_REVIEW = "under_review"
    ESCALATED = "escalated"
    AWAITING_PROFESSIONAL = "awaiting_professional"
    IN_RESOLUTION = "in_resolution"
    RESOLVED = "resolved"
    CLOSED = "closed"
    APPEALED = "appealed"


# Valid status transitions: from_status → set of allowed to_statuses
# Prevents invalid jumps (e.g., filed → closed) and documents the lifecycle
VALID_STATUS_TRANSITIONS: Dict[str, set] = {
    "draft":         {"filed"},
    "filed":         {"under_review", "escalated", "closed"},
    "under_review":  {"escalated", "awaiting_professional", "in_resolution", "filed", "closed"},
    "escalated":     {"in_resolution", "awaiting_professional", "under_review", "closed"},
    "awaiting_professional": {"in_resolution", "escalated", "closed"},
    "in_resolution": {"resolved", "escalated", "closed"},
    "resolved":      {"closed", "appealed"},
    "closed":        {"appealed"},
    "appealed":      {"under_review", "escalated", "in_resolution"},
}


# SLA Rules: max days a claim should spend in each active status
# Exceeding these triggers SLA breach. Warning at 75% of limit.
SLA_RULES: Dict[str, Dict[str, Any]] = {
    "filed":         {"max_days": 3,  "label": "Initial Review",     "warn_pct": 0.75},
    "under_review":  {"max_days": 7,  "label": "Review Completion",  "warn_pct": 0.75},
    "escalated":     {"max_days": 5,  "label": "Escalation Action",  "warn_pct": 0.75},
    "awaiting_professional": {"max_days": 10, "label": "Professional Assignment", "warn_pct": 0.75},
    "in_resolution": {"max_days": 21, "label": "Resolution Target",  "warn_pct": 0.75},
    "appealed":      {"max_days": 14, "label": "Appeal Processing",  "warn_pct": 0.75},
}


# Automated Escalation Rules
# Each rule: condition matcher → recommended action
ESCALATION_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "sla_breach_auto_escalate",
        "name": "SLA Breach → Escalate",
        "description": "Claims breaching SLA in filed status should be escalated to under_review",
        "condition": {"status": "filed", "sla_status": "breached"},
        "action": {"type": "status_change", "target_status": "under_review"},
        "priority": "high",
        "enabled": True,
    },
    {
        "rule_id": "high_value_stale_review",
        "name": "High-Value Stale Review",
        "description": "Claims >$10K in under_review for >5 days should escalate",
        "condition": {"status": "under_review", "min_amount": 10000, "min_days_in_status": 5},
        "action": {"type": "status_change", "target_status": "escalated"},
        "priority": "high",
        "enabled": True,
    },
    {
        "rule_id": "triage_flag_escalate",
        "name": "Triage-Flagged → Escalate",
        "description": "Claims flagged for human triage that are still in filed/under_review",
        "condition": {"statuses": ["filed", "under_review"], "requires_triage": True},
        "action": {"type": "status_change", "target_status": "escalated"},
        "priority": "medium",
        "enabled": True,
    },
    {
        "rule_id": "strategic_fast_track",
        "name": "Strategic Claims Fast-Track",
        "description": "Strategic band (>$250K) claims should skip to escalated within 1 day",
        "condition": {"status": "filed", "value_band": "strategic", "min_days_in_status": 1},
        "action": {"type": "status_change", "target_status": "escalated"},
        "priority": "critical",
        "enabled": True,
    },
    {
        "rule_id": "resolution_stall_alert",
        "name": "Resolution Stall Alert",
        "description": "Claims in resolution >14 days need attention",
        "condition": {"status": "in_resolution", "min_days_in_status": 14},
        "action": {"type": "flag", "flag": "resolution_stall"},
        "priority": "medium",
        "enabled": True,
    },
    {
        "rule_id": "repeat_respondent_escalate",
        "name": "Repeat Respondent Escalate",
        "description": "Claims against respondents with 3+ existing claims should escalate faster",
        "condition": {"status": "filed", "min_respondent_claims": 3, "min_days_in_status": 1},
        "action": {"type": "status_change", "target_status": "under_review"},
        "priority": "medium",
        "enabled": True,
    },
]


class DisputeType(str, Enum):
    PAYMENT_WITHHELD = "payment_withheld"
    WAGE_THEFT = "wage_theft"
    PLATFORM_FUND_FREEZE = "platform_fund_freeze"
    CONTRACT_BREACH = "contract_breach"
    MARKETPLACE_DISPUTE = "marketplace_dispute"
    DEPLATFORMING = "deplatforming"
    CROSS_BORDER_NONPAYMENT = "cross_border_nonpayment"
    UNDISCLOSED_FEES = "undisclosed_fees"
    GIG_WORKER_DISPUTE = "gig_worker_dispute"
    CREATOR_REVENUE_DISPUTE = "creator_revenue_dispute"
    OTHER = "other"


class ValueBand(str, Enum):
    MICRO = "micro"          # < $500
    SMALL = "small"          # $500 – $5k
    MEDIUM = "medium"        # $5k – $50k
    LARGE = "large"          # $50k – $250k
    STRATEGIC = "strategic"  # $250k+


class RecoveryPath(str, Enum):
    INFORMAL_DEMAND = "informal_demand"
    PLATFORM_ESCALATION = "platform_escalation"
    ARBITRATION = "arbitration"
    LITIGATION = "litigation"
    INFORMATIONAL_ONLY = "informational_only"


class JurisdictionalScope(str, Enum):
    DOMESTIC = "domestic"
    CROSS_BORDER = "cross_border"
    UNKNOWN = "unknown"


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================

class IntakeRequest(BaseModel):
    """
    Maps directly to the Google Form fields.
    Google Apps Script sends this payload to our webhook.
    """
    full_name: str = Field(..., min_length=1, max_length=200,
        description="Full Name from form")
    email: str = Field(..., min_length=3, max_length=320,
        description="Email Address from form")
    phone: Optional[str] = Field(None, max_length=30,
        description="Phone Number (optional)")
    platform_or_company: str = Field(..., min_length=1, max_length=500,
        description="Platform or Company Owing You Money")
    estimated_amount_usd: float = Field(..., gt=0,
        description="Estimated Amount Owed ($)")
    last_expected_payment: Optional[str] = Field(None,
        description="Date of Last Expected Payment (ISO 8601 or form format)")
    platform_reason: str = Field(..., min_length=1, max_length=5000,
        description="What reason did the platform give (if any)?")
    contacted_support: str = Field(...,
        description="Have you already contacted support?")
    referral_source: Optional[str] = Field(None,
        description="How did you hear about GhostLedger?")
    authorization: bool = Field(...,
        description="Authorization checkbox — must be True")

    @field_validator("estimated_amount_usd")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        if v > Config.MAX_CLAIM_AMOUNT:
            raise ValueError(f"Amount exceeds maximum ({Config.MAX_CLAIM_AMOUNT})")
        return round(v, 2)

    @field_validator("authorization")
    @classmethod
    def validate_authorization(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Authorization must be granted to proceed")
        return v


class IntakeResponse(BaseModel):
    """Returned after successful intake processing."""
    submission_id: str
    claim_id: str
    status: str
    message: str
    created_at: str


class ClaimResponse(BaseModel):
    """Full claim detail response."""
    claim_id: str
    status: str
    claimant_name: str
    respondent_entity: str
    amount_claimed_usd: float
    harm_type: str
    contacted_support: str
    filed_at: str
    execution_score: float


class HealthResponse(BaseModel):
    service: str = "gl-intake"
    status: str = "healthy"
    uptime_seconds: float = 0.0
    submissions_processed: int = 0


# ============================================================================
# RESPONDENT NORMALIZATION
# ============================================================================

# Canonical mappings: common variants → normalized (display_name, normalized_id)
_RESPONDENT_ALIASES: Dict[str, tuple] = {
    "stripe": ("Stripe", "stripe"),
    "stripe inc": ("Stripe", "stripe"),
    "stripe, inc.": ("Stripe", "stripe"),
    "stripe.com": ("Stripe", "stripe"),
    "paypal": ("PayPal", "paypal"),
    "paypal inc": ("PayPal", "paypal"),
    "paypal holdings": ("PayPal", "paypal"),
    "venmo": ("Venmo (PayPal)", "paypal_venmo"),
    "uber": ("Uber", "uber"),
    "uber technologies": ("Uber", "uber"),
    "uber eats": ("Uber Eats", "uber_eats"),
    "lyft": ("Lyft", "lyft"),
    "lyft inc": ("Lyft", "lyft"),
    "doordash": ("DoorDash", "doordash"),
    "doordash inc": ("DoorDash", "doordash"),
    "instacart": ("Instacart", "instacart"),
    "amazon": ("Amazon", "amazon"),
    "amazon.com": ("Amazon", "amazon"),
    "tiktok": ("TikTok", "tiktok"),
    "tiktok inc": ("TikTok", "tiktok"),
    "bytedance": ("TikTok (ByteDance)", "tiktok"),
    "shiftsmart": ("Shiftsmart", "shiftsmart"),
    "shiftsmart inc": ("Shiftsmart", "shiftsmart"),
    "shiftsmart.inc": ("Shiftsmart", "shiftsmart"),
    "square": ("Square (Block)", "square"),
    "block": ("Block (Square)", "square"),
    "cashapp": ("Cash App (Block)", "square_cashapp"),
    "cash app": ("Cash App (Block)", "square_cashapp"),
    "fiverr": ("Fiverr", "fiverr"),
    "upwork": ("Upwork", "upwork"),
    "etsy": ("Etsy", "etsy"),
    "shopify": ("Shopify", "shopify"),
    "grubhub": ("Grubhub", "grubhub"),
}


def normalize_respondent(raw: str) -> Dict[str, str]:
    """
    Normalize a respondent entity name for consistent pattern detection.
    Returns dict with display_name, normalized_id, and original.
    """
    original = (raw or "").strip()
    lookup = original.lower().strip().rstrip(".")
    # Remove common suffixes for matching
    for suffix in [" inc", " inc.", " llc", " ltd", " corp", " co"]:
        if lookup.endswith(suffix):
            lookup = lookup[: -len(suffix)].strip()

    if lookup in _RESPONDENT_ALIASES:
        display, norm_id = _RESPONDENT_ALIASES[lookup]
        return {"display_name": display, "normalized_id": norm_id, "original": original}

    # Fallback: clean capitalization, generate slug id
    if not original or original.lower() in ("no clue", "unknown", "n/a", "none", ""):
        return {"display_name": "Unknown", "normalized_id": "unknown", "original": original}

    # Title-case the display, slugify the id
    display = original.title()
    norm_id = original.lower().strip().replace(" ", "_").replace(".", "")
    return {"display_name": display, "normalized_id": norm_id, "original": original}


# ============================================================================
# CLAIMANT NAME NORMALIZATION
# ============================================================================

def normalize_claimant_name(raw: str) -> str:
    """
    Normalize a claimant name for consistent storage and pattern detection.
    Enforces Title Case, strips extra whitespace, and fixes common issues.
    """
    if not raw or not raw.strip():
        return "Unknown"
    name = " ".join(raw.strip().split())  # collapse multiple spaces
    # Title-case each word, respecting existing capitalization of known patterns
    parts = []
    for word in name.split():
        # Handle common suffixes/prefixes
        lower = word.lower()
        if lower in ("ii", "iii", "iv", "jr", "jr.", "sr", "sr."):
            parts.append(word.upper() if lower in ("ii", "iii", "iv") else word.capitalize())
        elif lower in ("de", "van", "von", "la", "le", "el", "al", "bin", "ibn"):
            parts.append(lower)  # keep lowercase for name particles
        else:
            parts.append(word.capitalize())
    return " ".join(parts)


# ============================================================================
# CASE CLASSIFICATION ENGINE (CCE)
# ============================================================================

def classify_value_band(amount_usd: float) -> ValueBand:
    """Classify claim into value band."""
    if amount_usd < 500:
        return ValueBand.MICRO
    elif amount_usd < 5_000:
        return ValueBand.SMALL
    elif amount_usd < 50_000:
        return ValueBand.MEDIUM
    elif amount_usd < 250_000:
        return ValueBand.LARGE
    return ValueBand.STRATEGIC


def classify_dispute_type(harm_type: str, platform: str, reason: str) -> DisputeType:
    """Map harm_type + context into a detailed dispute type."""
    combined = f"{platform} {reason}".lower()

    # Platform-specific patterns
    gig_platforms = ["uber", "lyft", "doordash", "instacart", "fiverr", "upwork", "taskrabbit", "shiftsmart", "wonolo", "instawork", "staffing", "gopuff", "grubhub", "postmates", "flex", "shipt", "favor"]
    creator_platforms = ["youtube", "tiktok", "twitch", "patreon", "substack", "onlyfans", "spotify"]
    marketplace_platforms = ["amazon", "ebay", "etsy", "shopify", "mercari", "poshmark"]

    platform_lower = platform.lower()

    if any(p in platform_lower for p in gig_platforms):
        return DisputeType.GIG_WORKER_DISPUTE
    if any(p in platform_lower for p in creator_platforms):
        return DisputeType.CREATOR_REVENUE_DISPUTE
    if any(p in platform_lower for p in marketplace_platforms):
        return DisputeType.MARKETPLACE_DISPUTE

    # Keyword patterns
    if any(kw in combined for kw in ["freeze", "frozen", "held", "locked funds"]):
        return DisputeType.PLATFORM_FUND_FREEZE
    if any(kw in combined for kw in ["deplatform", "banned", "terminated", "suspended account"]):
        return DisputeType.DEPLATFORMING
    if any(kw in combined for kw in ["contract", "agreement", "breach", "terms"]):
        return DisputeType.CONTRACT_BREACH
    if any(kw in combined for kw in ["fee", "charge", "deduction", "commission"]):
        return DisputeType.UNDISCLOSED_FEES
    if any(kw in combined for kw in ["wage", "salary", "employer"]):
        return DisputeType.WAGE_THEFT
    if any(kw in combined for kw in ["international", "cross-border", "foreign", "overseas"]):
        return DisputeType.CROSS_BORDER_NONPAYMENT

    # Fall back to harm_type mapping
    fallback = {
        "wage_theft": DisputeType.WAGE_THEFT,
        "platform_lockout": DisputeType.DEPLATFORMING,
        "payout_withholding": DisputeType.PAYMENT_WITHHELD,
        "undisclosed_fee": DisputeType.UNDISCLOSED_FEES,
    }
    return fallback.get(harm_type, DisputeType.PAYMENT_WITHHELD)


def compute_complexity(
    amount: float,
    harm_type: str,
    contacted_support: str,
    reason: str,
) -> int:
    """Score complexity 1-5 based on case signals."""
    score = 1

    # Higher amounts = more complex
    if amount >= 50_000:
        score += 2
    elif amount >= 5_000:
        score += 1

    # Already tried support = more entrenched
    if contacted_support in ("yes_no_resolution", "yes_still_waiting"):
        score += 1

    # Long reason text suggests complicated situation
    if len(reason) > 500:
        score += 1

    # Certain harm types are inherently complex
    if harm_type in ("platform_lockout", "wage_theft"):
        score += 1

    return min(score, 5)


def determine_recovery_path(
    value_band: ValueBand,
    complexity: int,
    contacted_support: str,
) -> RecoveryPath:
    """Recommend recovery path based on case profile."""
    if value_band == ValueBand.MICRO:
        return RecoveryPath.INFORMAL_DEMAND

    if contacted_support == "no_not_yet":
        return RecoveryPath.PLATFORM_ESCALATION

    if value_band in (ValueBand.LARGE, ValueBand.STRATEGIC):
        if complexity >= 4:
            return RecoveryPath.LITIGATION
        return RecoveryPath.ARBITRATION

    if complexity >= 3:
        return RecoveryPath.ARBITRATION

    return RecoveryPath.PLATFORM_ESCALATION


def check_human_triage(
    complexity: int,
    value_band: ValueBand,
    systemic_flag: bool = False,
) -> bool:
    """Determine if case needs human review before routing."""
    return (
        complexity >= 4
        or value_band == ValueBand.STRATEGIC
        or systemic_flag
    )


def run_cce(claim_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the full Case Classification Engine on a claim.
    Returns classification dict to be merged into the claim.
    """
    amount = claim_data.get("amount_claimed_usd", 0)
    harm_type = claim_data.get("harm_type", "other")
    platform = claim_data.get("respondent_entity", "")
    reason = claim_data.get("description", "")
    contacted = claim_data.get("contacted_support", "no_not_yet")

    value_band = classify_value_band(amount)
    dispute_type = classify_dispute_type(harm_type, platform, reason)
    complexity = compute_complexity(amount, harm_type, contacted, reason)
    recovery_path = determine_recovery_path(value_band, complexity, contacted)
    needs_triage = check_human_triage(complexity, value_band)

    return {
        "classification": {
            "value_band": value_band.value,
            "dispute_type": dispute_type.value,
            "complexity_score": complexity,
            "recovery_path": recovery_path.value,
            "jurisdictional_scope": JurisdictionalScope.UNKNOWN.value,
            "requires_human_triage": needs_triage,
            "systemic_flag": False,
            "classified_at": datetime.utcnow().isoformat(),
            "classified_by": "cce_auto",
        }
    }


# ============================================================================
# SQLITE PERSISTENT STORE
# ============================================================================

DB_PATH = os.environ.get(
    "GL_DB_PATH",
    str(Path(__file__).parent / "ghostledger.db"),
)


def _get_db() -> sqlite3.Connection:
    """Get a thread-local SQLite connection with WAL mode for concurrency."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _db():
    """Safe database context manager. Auto-closes and handles errors."""
    conn = None
    try:
        conn = _get_db()
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={"code": "DB_ERROR", "message": "Database operation failed"},
        )
    finally:
        if conn:
            conn.close()


def _init_db():
    """Create tables if they don't exist. Safe to call multiple times."""
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS submissions (
            submission_id   TEXT PRIMARY KEY,
            data            TEXT NOT NULL,
            submitted_at    TEXT NOT NULL,
            converted_to    TEXT
        );

        CREATE TABLE IF NOT EXISTS claims (
            claim_id            TEXT PRIMARY KEY,
            submission_id       TEXT,
            vertical            TEXT NOT NULL DEFAULT 'platform_dispute',
            status              TEXT NOT NULL DEFAULT 'filed',
            claimant_name       TEXT NOT NULL,
            claimant_email      TEXT,
            respondent_entity   TEXT,
            harm_type           TEXT,
            amount_claimed_usd  REAL DEFAULT 0,
            description         TEXT,
            contacted_support   TEXT,
            referral_source     TEXT,
            execution_score     REAL DEFAULT 0,
            data                TEXT NOT NULL,
            filed_at            TEXT NOT NULL,
            updated_at          TEXT,
            FOREIGN KEY (submission_id) REFERENCES submissions(submission_id)
        );

        CREATE TABLE IF NOT EXISTS events (
            event_id    TEXT PRIMARY KEY,
            topic       TEXT NOT NULL,
            payload     TEXT NOT NULL,
            timestamp   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notes (
            note_id     TEXT PRIMARY KEY,
            claim_id    TEXT NOT NULL,
            author      TEXT NOT NULL DEFAULT 'operator',
            content     TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id    TEXT PRIMARY KEY,
            action      TEXT NOT NULL,
            actor       TEXT NOT NULL DEFAULT 'system',
            detail      TEXT NOT NULL DEFAULT '{}',
            timestamp   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status);
        CREATE INDEX IF NOT EXISTS idx_claims_respondent ON claims(respondent_entity);
        CREATE INDEX IF NOT EXISTS idx_events_topic ON events(topic);
        CREATE INDEX IF NOT EXISTS idx_notes_claim ON notes(claim_id);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);

        CREATE TABLE IF NOT EXISTS ilf_lawyers (
            lawyer_id           TEXT PRIMARY KEY,
            full_name           TEXT NOT NULL,
            email               TEXT NOT NULL UNIQUE,
            bar_number          TEXT,
            jurisdiction        TEXT NOT NULL DEFAULT 'US-General',
            specializations     TEXT NOT NULL DEFAULT '[]',
            status              TEXT NOT NULL DEFAULT 'active',
            max_caseload        INTEGER NOT NULL DEFAULT 10,
            registered_at       TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            verification_status TEXT NOT NULL DEFAULT 'unverified',
            verified_at         TEXT,
            verified_by         TEXT
        );

        CREATE TABLE IF NOT EXISTS ilf_referrals (
            referral_id        TEXT PRIMARY KEY,
            claim_id           TEXT NOT NULL,
            lawyer_id          TEXT NOT NULL,
            status             TEXT NOT NULL DEFAULT 'pending',
            referred_at        TEXT NOT NULL,
            responded_at       TEXT,
            notes              TEXT NOT NULL DEFAULT '',
            claimant_consent_at TEXT,
            consent_version    TEXT NOT NULL DEFAULT '1.0',
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id),
            FOREIGN KEY (lawyer_id) REFERENCES ilf_lawyers(lawyer_id)
        );

        CREATE INDEX IF NOT EXISTS idx_ilf_referrals_lawyer ON ilf_referrals(lawyer_id);
        CREATE INDEX IF NOT EXISTS idx_ilf_referrals_claim ON ilf_referrals(claim_id);
        CREATE INDEX IF NOT EXISTS idx_ilf_referrals_status ON ilf_referrals(status);
        CREATE INDEX IF NOT EXISTS idx_ilf_lawyers_status ON ilf_lawyers(status);
    """)
    conn.commit()

    # ── Migrations (safe to re-run) ──
    try:
        conn.execute("ALTER TABLE claims ADD COLUMN vertical TEXT NOT NULL DEFAULT 'platform_dispute'")
        conn.commit()
    except Exception:
        pass  # Column already exists

    # Create index on vertical (runs after migration ensures column exists)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_vertical ON claims(vertical)")
        conn.commit()
    except Exception:
        pass

    # ── Recovery Tracking table (migration-safe) ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS recoveries (
            recovery_id         TEXT PRIMARY KEY,
            claim_id            TEXT NOT NULL,
            amount_recovered    REAL NOT NULL DEFAULT 0,
            recovery_method     TEXT NOT NULL DEFAULT 'direct_refund',
            recovered_by        TEXT NOT NULL DEFAULT 'operator',
            notes               TEXT NOT NULL DEFAULT '',
            recorded_at         TEXT NOT NULL,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_recoveries_claim ON recoveries(claim_id)")
    conn.commit()

    # ── Saved Views table (migration-safe) ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS saved_views (
            view_id     TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            filters     TEXT NOT NULL DEFAULT '{}',
            sort_by     TEXT NOT NULL DEFAULT 'filed_at',
            sort_dir    TEXT NOT NULL DEFAULT 'desc',
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )
    """)
    conn.commit()

    # ── Outreach Templates & Communication Log ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS outreach_templates (
            template_id   TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            category      TEXT NOT NULL DEFAULT 'demand_letter',
            subject       TEXT NOT NULL DEFAULT '',
            body          TEXT NOT NULL DEFAULT '',
            variables     TEXT NOT NULL DEFAULT '[]',
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS outreach_log (
            outreach_id   TEXT PRIMARY KEY,
            claim_id      TEXT NOT NULL,
            template_id   TEXT,
            channel        TEXT NOT NULL DEFAULT 'email',
            recipient      TEXT NOT NULL DEFAULT '',
            subject        TEXT NOT NULL DEFAULT '',
            body           TEXT NOT NULL DEFAULT '',
            status         TEXT NOT NULL DEFAULT 'drafted',
            sent_at        TEXT,
            created_at     TEXT NOT NULL,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.commit()

    # Seed default templates if none exist
    existing = conn.execute("SELECT COUNT(*) FROM outreach_templates").fetchone()[0]
    if existing == 0:
        now_str = datetime.utcnow().isoformat() + "Z"
        default_templates = [
            {
                "template_id": "tpl_initial_demand",
                "name": "Initial Demand Letter",
                "category": "demand_letter",
                "subject": "Formal Demand: Resolution of Claim #{claim_id} — {claimant_name}",
                "body": "Dear {respondent},\n\nI am writing on behalf of {claimant_name} regarding an unresolved financial dispute involving your platform.\n\nClaim Reference: #{claim_id}\nAmount in Dispute: ${amount}\nDate Filed: {filed_date}\nNature of Dispute: {harm_type}\n\nDespite prior attempts to resolve this matter through your standard support channels, the issue remains unaddressed. We are formally requesting:\n\n1. A full review of the account activity related to this dispute\n2. Restoration of {claimant_name}'s access to the disputed funds (${amount})\n3. A written explanation of the actions taken and timeline for resolution\n\nPlease respond within 10 business days of receipt. Failure to respond may result in escalation to relevant regulatory bodies and consumer protection agencies.\n\nRegards,\nGhostLedger Claims Operations\nOn behalf of {claimant_name}",
                "variables": '["claim_id","claimant_name","respondent","amount","filed_date","harm_type"]',
            },
            {
                "template_id": "tpl_followup_reminder",
                "name": "Follow-Up Reminder",
                "category": "follow_up",
                "subject": "Follow-Up: Claim #{claim_id} — Awaiting Response",
                "body": "Dear {respondent},\n\nThis is a follow-up regarding Claim #{claim_id} filed by {claimant_name} on {filed_date}.\n\nWe previously contacted you on {last_outreach_date} requesting resolution of a ${amount} dispute. We have not yet received a substantive response.\n\nWe respectfully urge you to address this matter promptly. Our records indicate this claim has been active for {days_active} days.\n\nPlease provide a status update within 5 business days.\n\nRegards,\nGhostLedger Claims Operations",
                "variables": '["claim_id","claimant_name","respondent","amount","filed_date","last_outreach_date","days_active"]',
            },
            {
                "template_id": "tpl_escalation_notice",
                "name": "Escalation Notice",
                "category": "escalation",
                "subject": "ESCALATION NOTICE: Claim #{claim_id} — Unresolved Dispute",
                "body": "Dear {respondent},\n\nThis notice serves as formal escalation of Claim #{claim_id}.\n\nClaimant: {claimant_name}\nAmount: ${amount}\nDays Active: {days_active}\nPrevious Outreach Attempts: {outreach_count}\n\nDespite {outreach_count} prior communication(s), this dispute remains unresolved. We are escalating this matter and may pursue the following actions:\n\n• Filing complaints with relevant regulatory bodies (FTC, CFPB, state AG offices)\n• Engaging legal counsel for potential litigation\n• Publishing a public accountability report\n\nThis escalation can be avoided by providing a satisfactory resolution within 5 business days.\n\nRegards,\nGhostLedger Claims Operations\nEscalation Division",
                "variables": '["claim_id","claimant_name","respondent","amount","days_active","outreach_count"]',
            },
            {
                "template_id": "tpl_resolution_confirm",
                "name": "Resolution Confirmation",
                "category": "resolution",
                "subject": "Resolution Confirmation: Claim #{claim_id}",
                "body": "Dear {claimant_name},\n\nWe are pleased to confirm that Claim #{claim_id} against {respondent} has been resolved.\n\nResolution Details:\n• Amount Recovered: ${amount_recovered}\n• Recovery Method: {recovery_method}\n• Resolution Date: {resolution_date}\n\nIf you have any concerns about this resolution or need further assistance, please don't hesitate to reach out.\n\nThank you for your patience throughout this process.\n\nRegards,\nGhostLedger Claims Operations",
                "variables": '["claim_id","claimant_name","respondent","amount_recovered","recovery_method","resolution_date"]',
            },
            {
                "template_id": "tpl_claimant_update",
                "name": "Claimant Status Update",
                "category": "status_update",
                "subject": "Status Update: Your Claim #{claim_id}",
                "body": "Dear {claimant_name},\n\nWe are writing to update you on the status of your claim against {respondent}.\n\nClaim Reference: #{claim_id}\nCurrent Status: {status}\nAmount: ${amount}\n\n{status_message}\n\nWe will continue to keep you informed of any developments. If you have questions, please reference your claim ID in any correspondence.\n\nRegards,\nGhostLedger Claims Operations",
                "variables": '["claim_id","claimant_name","respondent","status","amount","status_message"]',
            },
        ]
        for t in default_templates:
            conn.execute(
                "INSERT INTO outreach_templates (template_id, name, category, subject, body, variables, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (t["template_id"], t["name"], t["category"], t["subject"], t["body"], t["variables"], now_str, now_str),
            )
        conn.commit()

    # ── Operators & Case Assignment ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS operators (
            operator_id   TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            email         TEXT NOT NULL DEFAULT '',
            role          TEXT NOT NULL DEFAULT 'analyst',
            status        TEXT NOT NULL DEFAULT 'active',
            max_caseload  INTEGER NOT NULL DEFAULT 25,
            created_at    TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assignments (
            claim_id      TEXT NOT NULL,
            operator_id   TEXT NOT NULL,
            assigned_at   TEXT NOT NULL,
            assigned_by   TEXT NOT NULL DEFAULT 'system',
            PRIMARY KEY (claim_id),
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id),
            FOREIGN KEY (operator_id) REFERENCES operators(operator_id)
        )
    """)
    conn.commit()

    # Seed default operators if none exist
    op_count = conn.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
    if op_count == 0:
        now_str = datetime.utcnow().isoformat() + "Z"
        default_ops = [
            ("op_lead", "Seun Akinlosotu", "lovecity4real@gmail.com", "lead", "active", 30),
            ("op_analyst_1", "Claims Analyst 1", "analyst1@ghostledger.io", "analyst", "active", 25),
            ("op_analyst_2", "Claims Analyst 2", "analyst2@ghostledger.io", "analyst", "active", 25),
            ("op_escalation", "Escalation Specialist", "escalation@ghostledger.io", "escalation", "active", 15),
        ]
        for oid, name, email, role, status, cap in default_ops:
            conn.execute(
                "INSERT INTO operators (operator_id, name, email, role, status, max_caseload, created_at) VALUES (?,?,?,?,?,?,?)",
                (oid, name, email, role, status, cap, now_str),
            )
        conn.commit()

    # ── Settlement & Resolution tables ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settlements (
            settlement_id   TEXT PRIMARY KEY,
            claim_id        TEXT NOT NULL,
            offer_type      TEXT NOT NULL DEFAULT 'initial_offer',
            offered_by      TEXT NOT NULL DEFAULT 'respondent',
            amount_offered  REAL NOT NULL DEFAULT 0,
            terms           TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'pending',
            response_deadline TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            resolved_at     TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_settle_claim ON settlements(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_settle_status ON settlements(status)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS resolutions (
            resolution_id   TEXT PRIMARY KEY,
            claim_id        TEXT NOT NULL UNIQUE,
            settlement_id   TEXT,
            resolution_type TEXT NOT NULL DEFAULT 'full_settlement',
            amount_settled  REAL NOT NULL DEFAULT 0,
            amount_claimed  REAL NOT NULL DEFAULT 0,
            settlement_ratio REAL NOT NULL DEFAULT 0,
            terms_summary   TEXT NOT NULL DEFAULT '',
            resolution_notes TEXT NOT NULL DEFAULT '',
            resolved_at     TEXT NOT NULL,
            created_at      TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_resolution_claim ON resolutions(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_resolution_type ON resolutions(resolution_type)")

    # ── Workflow Rules Engine tables ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS workflow_rules (
            rule_id         TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            trigger_event   TEXT NOT NULL,
            conditions      TEXT NOT NULL DEFAULT '{}',
            actions         TEXT NOT NULL DEFAULT '[]',
            enabled         INTEGER NOT NULL DEFAULT 1,
            priority        INTEGER NOT NULL DEFAULT 50,
            execution_count INTEGER NOT NULL DEFAULT 0,
            last_executed   TEXT,
            created_at      TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wf_trigger ON workflow_rules(trigger_event)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS workflow_executions (
            execution_id    TEXT PRIMARY KEY,
            rule_id         TEXT NOT NULL,
            claim_id        TEXT NOT NULL,
            trigger_event   TEXT NOT NULL,
            actions_taken   TEXT NOT NULL DEFAULT '[]',
            status          TEXT NOT NULL DEFAULT 'success',
            executed_at     TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wfx_rule ON workflow_executions(rule_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wfx_claim ON workflow_executions(claim_id)")

    # Seed default workflow rules
    wf_now_str = datetime.utcnow().isoformat() + "Z"
    existing_rules = conn.execute("SELECT COUNT(*) as c FROM workflow_rules").fetchone()["c"]
    if existing_rules == 0:
        default_rules = [
            ("wfr_high_value_escalate", "High-Value Auto-Escalate",
             "Automatically escalate claims over $5,000 to prioritize review",
             "claim.filed",
             json.dumps({"min_amount": 5000}),
             json.dumps([{"type": "change_status", "target": "escalated", "reason": "Auto-escalated: high-value claim (>$5,000)"}]),
             1, 10),
            ("wfr_auto_assign_new", "Auto-Assign New Claims",
             "Automatically assign new claims to the operator with most available capacity",
             "claim.filed",
             json.dumps({}),
             json.dumps([{"type": "auto_assign"}]),
             1, 20),
            ("wfr_stale_claim_flag", "Stale Claim Alert",
             "Flag claims that have been in filed status for more than 7 days without action",
             "scheduled.daily",
             json.dumps({"status": "filed", "min_days_in_status": 7}),
             json.dumps([{"type": "change_status", "target": "escalated", "reason": "Auto-escalated: stale claim (>7 days in filed status)"}]),
             1, 30),
            ("wfr_systemic_respondent", "Systemic Respondent Alert",
             "Flag respondents with 3+ claims as potential systemic abusers",
             "claim.filed",
             json.dumps({"min_respondent_claims": 3}),
             json.dumps([{"type": "add_note", "category": "system", "text": "SYSTEMIC ALERT: This respondent has multiple claims filed against them. Consider coordinated action."}]),
             1, 15),
            ("wfr_settlement_followup", "Settlement Follow-Up",
             "Send follow-up when a settlement offer has been pending for 14+ days",
             "scheduled.daily",
             json.dumps({"pending_settlement_days": 14}),
             json.dumps([{"type": "add_note", "category": "system", "text": "REMINDER: Settlement offer pending for 14+ days. Follow up with respondent."}]),
             1, 40),
        ]
        for rid, name, desc, trigger, conds, actions, enabled, priority in default_rules:
            conn.execute(
                "INSERT INTO workflow_rules (rule_id, name, description, trigger_event, conditions, actions, enabled, priority, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (rid, name, desc, trigger, conds, actions, enabled, priority, wf_now_str),
            )
    conn.commit()

    # ── Document / Evidence Management ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            document_id     TEXT PRIMARY KEY,
            claim_id        TEXT NOT NULL,
            filename        TEXT NOT NULL,
            file_type       TEXT NOT NULL DEFAULT 'other',
            category        TEXT NOT NULL DEFAULT 'evidence',
            description     TEXT NOT NULL DEFAULT '',
            file_size_bytes INTEGER NOT NULL DEFAULT 0,
            mime_type       TEXT NOT NULL DEFAULT 'application/octet-stream',
            storage_path    TEXT NOT NULL DEFAULT '',
            content_b64     TEXT,
            hash_sha256     TEXT NOT NULL DEFAULT '',
            uploaded_by     TEXT NOT NULL DEFAULT 'operator',
            tags            TEXT NOT NULL DEFAULT '[]',
            metadata        TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_claim ON documents(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_category ON documents(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_type ON documents(file_type)")
    conn.commit()

    # ── Notification Center ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            notification_id TEXT PRIMARY KEY,
            type            TEXT NOT NULL,
            severity        TEXT NOT NULL DEFAULT 'info',
            title           TEXT NOT NULL,
            message         TEXT NOT NULL DEFAULT '',
            claim_id        TEXT,
            source          TEXT NOT NULL DEFAULT 'system',
            action_url      TEXT NOT NULL DEFAULT '',
            action_label    TEXT NOT NULL DEFAULT '',
            read            INTEGER NOT NULL DEFAULT 0,
            dismissed       INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL,
            read_at         TEXT,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_type ON notifications(type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_read ON notifications(read)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_claim ON notifications(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_severity ON notifications(severity)")
    conn.commit()

    # ── Case Groups & Multi-Claim Linking ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_groups (
            group_id        TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            group_type      TEXT NOT NULL DEFAULT 'respondent',
            status          TEXT NOT NULL DEFAULT 'active',
            respondent_key  TEXT,
            tags            TEXT NOT NULL DEFAULT '[]',
            strategy_notes  TEXT NOT NULL DEFAULT '',
            created_by      TEXT NOT NULL DEFAULT 'operator',
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cg_type ON case_groups(group_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cg_status ON case_groups(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cg_respondent ON case_groups(respondent_key)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS claim_links (
            link_id         TEXT PRIMARY KEY,
            group_id        TEXT NOT NULL,
            claim_id        TEXT NOT NULL,
            role            TEXT NOT NULL DEFAULT 'member',
            linked_at       TEXT NOT NULL,
            linked_by       TEXT NOT NULL DEFAULT 'operator',
            notes           TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (group_id) REFERENCES case_groups(group_id),
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id),
            UNIQUE(group_id, claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cl_group ON claim_links(group_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cl_claim ON claim_links(claim_id)")
    conn.commit()

    # ── Triage Actions ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS triage_actions (
            action_id      TEXT PRIMARY KEY,
            claim_id       TEXT NOT NULL,
            action_type    TEXT NOT NULL DEFAULT 'priority_override',
            previous_value TEXT,
            new_value      TEXT,
            reason         TEXT DEFAULT '',
            performed_by   TEXT DEFAULT 'operator',
            created_at     TEXT NOT NULL,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_triage_claim ON triage_actions(claim_id)")
    conn.commit()

    # ── Tags & Custom Fields ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tags (
            tag_id      TEXT PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            color       TEXT DEFAULT '#58a6ff',
            category    TEXT DEFAULT 'general',
            description TEXT DEFAULT '',
            usage_count INTEGER DEFAULT 0,
            created_by  TEXT DEFAULT 'operator',
            created_at  TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tags_category ON tags(category)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS claim_tags (
            claim_id   TEXT NOT NULL,
            tag_id     TEXT NOT NULL,
            tagged_by  TEXT DEFAULT 'operator',
            tagged_at  TEXT NOT NULL,
            PRIMARY KEY (claim_id, tag_id),
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id),
            FOREIGN KEY (tag_id) REFERENCES tags(tag_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ctags_claim ON claim_tags(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ctags_tag ON claim_tags(tag_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_fields (
            field_id    TEXT PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            field_type  TEXT NOT NULL DEFAULT 'text',
            description TEXT DEFAULT '',
            options     TEXT DEFAULT '[]',
            required    INTEGER DEFAULT 0,
            created_by  TEXT DEFAULT 'operator',
            created_at  TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS claim_custom_values (
            claim_id   TEXT NOT NULL,
            field_id   TEXT NOT NULL,
            value      TEXT DEFAULT '',
            updated_by TEXT DEFAULT 'operator',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (claim_id, field_id),
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id),
            FOREIGN KEY (field_id) REFERENCES custom_fields(field_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ccv_claim ON claim_custom_values(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ccv_field ON claim_custom_values(field_id)")
    conn.commit()

    # ── Data Quality & Deduplication ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS duplicate_pairs (
            pair_id        TEXT PRIMARY KEY,
            claim_id_a     TEXT NOT NULL,
            claim_id_b     TEXT NOT NULL,
            similarity     REAL NOT NULL DEFAULT 0,
            match_fields   TEXT DEFAULT '[]',
            status         TEXT DEFAULT 'pending',
            resolved_by    TEXT,
            resolved_at    TEXT,
            created_at     TEXT NOT NULL,
            UNIQUE(claim_id_a, claim_id_b)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dup_a ON duplicate_pairs(claim_id_a)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dup_b ON duplicate_pairs(claim_id_b)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dup_status ON duplicate_pairs(status)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS merge_history (
            merge_id       TEXT PRIMARY KEY,
            source_claim_id TEXT NOT NULL,
            target_claim_id TEXT NOT NULL,
            fields_merged  TEXT DEFAULT '[]',
            merged_by      TEXT DEFAULT 'operator',
            merged_at      TEXT NOT NULL
        )
    """)
    conn.commit()

    # ── Webhooks & Integrations ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id   TEXT PRIMARY KEY,
            url          TEXT NOT NULL,
            events       TEXT NOT NULL DEFAULT '["*"]',
            secret       TEXT NOT NULL DEFAULT '',
            status       TEXT NOT NULL DEFAULT 'active',
            description  TEXT NOT NULL DEFAULT '',
            created_by   TEXT NOT NULL DEFAULT 'operator',
            created_at   TEXT NOT NULL,
            last_triggered TEXT,
            failure_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            delivery_id  TEXT PRIMARY KEY,
            webhook_id   TEXT NOT NULL,
            event        TEXT NOT NULL,
            payload      TEXT NOT NULL DEFAULT '{}',
            status_code  INTEGER,
            response     TEXT NOT NULL DEFAULT '',
            success      INTEGER NOT NULL DEFAULT 0,
            delivered_at TEXT NOT NULL,
            FOREIGN KEY (webhook_id) REFERENCES webhooks(webhook_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wh_status ON webhooks(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_whd_webhook ON webhook_deliveries(webhook_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_whd_event ON webhook_deliveries(event)")
    conn.commit()

    # ── Saved Searches ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS saved_searches (
            search_id    TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            description  TEXT NOT NULL DEFAULT '',
            filters      TEXT NOT NULL DEFAULT '{}',
            sort_by      TEXT NOT NULL DEFAULT 'filed_at',
            sort_order   TEXT NOT NULL DEFAULT 'desc',
            created_by   TEXT NOT NULL DEFAULT 'operator',
            created_at   TEXT NOT NULL,
            last_used    TEXT,
            use_count    INTEGER NOT NULL DEFAULT 0,
            is_pinned    INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ss_pinned ON saved_searches(is_pinned)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ss_created ON saved_searches(created_by)")

    # ── Reminders & Follow-up Scheduler ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reminders (
            reminder_id   TEXT PRIMARY KEY,
            claim_id      TEXT,
            title         TEXT NOT NULL,
            description   TEXT NOT NULL DEFAULT '',
            reminder_type TEXT NOT NULL DEFAULT 'manual',
            due_at        TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'pending',
            priority      TEXT NOT NULL DEFAULT 'normal',
            assigned_to   TEXT NOT NULL DEFAULT 'operator',
            created_by    TEXT NOT NULL DEFAULT 'operator',
            created_at    TEXT NOT NULL,
            completed_at  TEXT,
            snoozed_until TEXT,
            recurrence    TEXT,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rem_claim ON reminders(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rem_due ON reminders(due_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rem_status ON reminders(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rem_assigned ON reminders(assigned_to)")

    # ── Claim Templates ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS claim_templates (
            template_id     TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            category        TEXT NOT NULL DEFAULT 'general',
            vertical        TEXT NOT NULL DEFAULT 'platform_dispute',
            harm_type       TEXT NOT NULL DEFAULT '',
            default_fields  TEXT NOT NULL DEFAULT '{}',
            field_prompts   TEXT NOT NULL DEFAULT '{}',
            is_active       INTEGER NOT NULL DEFAULT 1,
            use_count       INTEGER NOT NULL DEFAULT 0,
            created_by      TEXT NOT NULL DEFAULT 'operator',
            created_at      TEXT NOT NULL,
            updated_at      TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ct_category ON claim_templates(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ct_active ON claim_templates(is_active)")

    # ── Knowledge Base & SOPs ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kb_articles (
            article_id    TEXT PRIMARY KEY,
            title         TEXT NOT NULL,
            content       TEXT NOT NULL DEFAULT '',
            category      TEXT NOT NULL DEFAULT 'general',
            tags          TEXT NOT NULL DEFAULT '[]',
            author        TEXT NOT NULL DEFAULT 'operator',
            status        TEXT NOT NULL DEFAULT 'published',
            priority      INTEGER NOT NULL DEFAULT 0,
            helpful_votes INTEGER NOT NULL DEFAULT 0,
            view_count    INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL,
            updated_at    TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_kb_category ON kb_articles(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_kb_status ON kb_articles(status)")

    # ── Compliance & Regulatory Framework ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_rules (
            rule_id       TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            description   TEXT NOT NULL DEFAULT '',
            category      TEXT NOT NULL DEFAULT 'general',
            jurisdiction  TEXT NOT NULL DEFAULT 'global',
            applies_to    TEXT NOT NULL DEFAULT 'all_claims',
            conditions    TEXT NOT NULL DEFAULT '{}',
            deadline_days INTEGER,
            severity      TEXT NOT NULL DEFAULT 'medium',
            status        TEXT NOT NULL DEFAULT 'active',
            auto_flag     INTEGER NOT NULL DEFAULT 0,
            created_by    TEXT NOT NULL DEFAULT 'operator',
            created_at    TEXT NOT NULL,
            updated_at    TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_comp_category ON compliance_rules(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_comp_jurisdiction ON compliance_rules(jurisdiction)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_comp_status ON compliance_rules(status)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_checks (
            check_id     TEXT PRIMARY KEY,
            rule_id      TEXT NOT NULL REFERENCES compliance_rules(rule_id),
            claim_id     TEXT NOT NULL REFERENCES claims(claim_id),
            status       TEXT NOT NULL DEFAULT 'pending',
            checked_by   TEXT NOT NULL DEFAULT 'system',
            checked_at   TEXT,
            notes        TEXT NOT NULL DEFAULT '',
            due_at       TEXT,
            created_at   TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cc_rule ON compliance_checks(rule_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cc_claim ON compliance_checks(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cc_status ON compliance_checks(status)")

    # ── Correspondence & Communication Log ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS correspondence (
            message_id    TEXT PRIMARY KEY,
            claim_id      TEXT NOT NULL REFERENCES claims(claim_id),
            direction     TEXT NOT NULL DEFAULT 'outbound',
            channel       TEXT NOT NULL DEFAULT 'email',
            subject       TEXT NOT NULL DEFAULT '',
            body          TEXT NOT NULL DEFAULT '',
            sender        TEXT NOT NULL DEFAULT '',
            recipient     TEXT NOT NULL DEFAULT '',
            status        TEXT NOT NULL DEFAULT 'draft',
            priority      TEXT NOT NULL DEFAULT 'normal',
            template_used TEXT,
            related_to    TEXT,
            sent_at       TEXT,
            delivered_at  TEXT,
            responded_at  TEXT,
            created_by    TEXT NOT NULL DEFAULT 'operator',
            created_at    TEXT NOT NULL,
            updated_at    TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_claim ON correspondence(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_direction ON correspondence(direction)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_status ON correspondence(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_channel ON correspondence(channel)")

    # ── Claim Watchlist & Operator Bookmarks ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS watchlist (
            watch_id     TEXT PRIMARY KEY,
            claim_id     TEXT NOT NULL REFERENCES claims(claim_id),
            operator_id  TEXT NOT NULL,
            label        TEXT NOT NULL DEFAULT '',
            notes        TEXT NOT NULL DEFAULT '',
            priority     TEXT NOT NULL DEFAULT 'normal',
            color        TEXT NOT NULL DEFAULT '#58a6ff',
            notify       INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT NOT NULL,
            updated_at   TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wl_claim ON watchlist(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wl_operator ON watchlist(operator_id)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_wl_unique ON watchlist(claim_id, operator_id)")

    # ── Settlement Negotiation Tracker ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS negotiations (
            negotiation_id TEXT PRIMARY KEY,
            claim_id       TEXT NOT NULL REFERENCES claims(claim_id),
            round_number   INTEGER NOT NULL DEFAULT 1,
            initiated_by   TEXT NOT NULL DEFAULT 'claimant',
            offer_amount   REAL NOT NULL DEFAULT 0,
            counter_amount REAL,
            terms          TEXT NOT NULL DEFAULT '',
            status         TEXT NOT NULL DEFAULT 'pending',
            deadline       TEXT,
            response_note  TEXT NOT NULL DEFAULT '',
            responded_by   TEXT,
            responded_at   TEXT,
            created_by     TEXT NOT NULL DEFAULT 'operator',
            created_at     TEXT NOT NULL,
            updated_at     TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_neg_claim ON negotiations(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_neg_status ON negotiations(status)")

    # ── Task Queue & Operator Assignments ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id         TEXT PRIMARY KEY,
            claim_id        TEXT,
            title           TEXT NOT NULL,
            description     TEXT DEFAULT '',
            task_type       TEXT NOT NULL DEFAULT 'manual',
            priority        TEXT NOT NULL DEFAULT 'normal',
            status          TEXT NOT NULL DEFAULT 'open',
            assigned_to     TEXT,
            created_by      TEXT NOT NULL DEFAULT 'system',
            due_at          TEXT,
            started_at      TEXT,
            completed_at    TEXT,
            estimated_minutes INTEGER,
            actual_minutes  INTEGER,
            tags            TEXT DEFAULT '[]',
            parent_task_id  TEXT,
            depends_on      TEXT DEFAULT '[]',
            metadata        TEXT DEFAULT '{}',
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_claim ON tasks(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_at)")

    # ── Export & Download Center ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS export_jobs (
            export_id       TEXT PRIMARY KEY,
            export_type     TEXT NOT NULL DEFAULT 'claims',
            format          TEXT NOT NULL DEFAULT 'json',
            filters         TEXT DEFAULT '{}',
            status          TEXT NOT NULL DEFAULT 'completed',
            record_count    INTEGER DEFAULT 0,
            file_size_bytes INTEGER DEFAULT 0,
            created_by      TEXT NOT NULL DEFAULT 'operator',
            created_at      TEXT NOT NULL,
            completed_at    TEXT,
            download_url    TEXT,
            metadata        TEXT DEFAULT '{}'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_export_type ON export_jobs(export_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_export_created ON export_jobs(created_at)")

    # ── Case Milestones & Progress Tracking ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS milestones (
            milestone_id    TEXT PRIMARY KEY,
            claim_id        TEXT NOT NULL,
            title           TEXT NOT NULL,
            description     TEXT DEFAULT '',
            category        TEXT NOT NULL DEFAULT 'general',
            sequence_order  INTEGER DEFAULT 0,
            status          TEXT NOT NULL DEFAULT 'pending',
            target_date     TEXT,
            completed_at    TEXT,
            completed_by    TEXT,
            notes           TEXT DEFAULT '',
            auto_trigger    TEXT DEFAULT '{}',
            created_by      TEXT NOT NULL DEFAULT 'operator',
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ms_claim ON milestones(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ms_status ON milestones(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ms_category ON milestones(category)")

    # ── Feature #43: Claimant Satisfaction Surveys ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS satisfaction_surveys (
            survey_id       TEXT PRIMARY KEY,
            claim_id        TEXT NOT NULL,
            trigger_event   TEXT NOT NULL DEFAULT 'resolution',
            status          TEXT NOT NULL DEFAULT 'pending',
            rating          INTEGER,
            feedback_text   TEXT,
            categories      TEXT DEFAULT '[]',
            respondent_name TEXT,
            claimant_email  TEXT,
            sent_at         TEXT,
            completed_at    TEXT,
            created_at      TEXT NOT NULL,
            expires_at      TEXT,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_surv_claim ON satisfaction_surveys(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_surv_status ON satisfaction_surveys(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_surv_trigger ON satisfaction_surveys(trigger_event)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_surv_rating ON satisfaction_surveys(rating)")

    # ── Feature #44: Escalation Playbooks ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS escalation_playbooks (
            playbook_id     TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT DEFAULT '',
            trigger_type    TEXT NOT NULL DEFAULT 'manual',
            trigger_config  TEXT DEFAULT '{}',
            steps           TEXT DEFAULT '[]',
            is_active       BOOLEAN DEFAULT 1,
            cooldown_hours  INTEGER DEFAULT 24,
            max_executions  INTEGER DEFAULT 0,
            created_by      TEXT DEFAULT 'system',
            created_at      TEXT NOT NULL,
            updated_at      TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbook_executions (
            execution_id    TEXT PRIMARY KEY,
            playbook_id     TEXT NOT NULL,
            claim_id        TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'running',
            current_step    INTEGER DEFAULT 0,
            total_steps     INTEGER DEFAULT 0,
            step_results    TEXT DEFAULT '[]',
            started_at      TEXT NOT NULL,
            completed_at    TEXT,
            error_message   TEXT,
            FOREIGN KEY (playbook_id) REFERENCES escalation_playbooks(playbook_id),
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pb_active ON escalation_playbooks(is_active)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pbe_playbook ON playbook_executions(playbook_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pbe_claim ON playbook_executions(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pbe_status ON playbook_executions(status)")

    # ── Feature #45: Communication Channel Registry ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comm_channels (
            channel_id      TEXT PRIMARY KEY,
            respondent_entity TEXT NOT NULL,
            channel_type    TEXT NOT NULL,
            contact_value   TEXT NOT NULL,
            label           TEXT DEFAULT '',
            is_primary      BOOLEAN DEFAULT 0,
            is_verified     BOOLEAN DEFAULT 0,
            status          TEXT DEFAULT 'active',
            success_count   INTEGER DEFAULT 0,
            fail_count      INTEGER DEFAULT 0,
            last_used_at    TEXT,
            notes           TEXT DEFAULT '',
            created_at      TEXT NOT NULL,
            updated_at      TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cc_respondent ON comm_channels(respondent_entity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cc_type ON comm_channels(channel_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cc_status ON comm_channels(status)")

    # ── Feature #46: Fee & Billing Tracker ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS billing_entries (
            entry_id        TEXT PRIMARY KEY,
            claim_id        TEXT NOT NULL,
            entry_type      TEXT NOT NULL DEFAULT 'contingency_fee',
            description     TEXT NOT NULL DEFAULT '',
            amount_usd      REAL NOT NULL DEFAULT 0.0,
            fee_pct         REAL DEFAULT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            due_date        TEXT,
            paid_date       TEXT,
            payment_method  TEXT DEFAULT '',
            invoice_number  TEXT DEFAULT '',
            notes           TEXT DEFAULT '',
            created_by      TEXT DEFAULT 'system',
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_be_claim ON billing_entries(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_be_status ON billing_entries(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_be_type ON billing_entries(entry_type)")

    # ── Feature #47: Claim Dependencies & Linked Cases ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS claim_dependencies (
            dep_id          TEXT PRIMARY KEY,
            source_claim_id TEXT NOT NULL,
            target_claim_id TEXT NOT NULL,
            link_type       TEXT NOT NULL DEFAULT 'related',
            description     TEXT DEFAULT '',
            strength        REAL DEFAULT 1.0,
            created_by      TEXT DEFAULT 'system',
            created_at      TEXT NOT NULL,
            FOREIGN KEY (source_claim_id) REFERENCES claims(claim_id),
            FOREIGN KEY (target_claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cd_source ON claim_dependencies(source_claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cd_target ON claim_dependencies(target_claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cd_type ON claim_dependencies(link_type)")

    # ── Feature #48: Claim Evidence Vault ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence_items (
            evidence_id     TEXT PRIMARY KEY,
            claim_id        TEXT NOT NULL,
            evidence_type   TEXT NOT NULL DEFAULT 'document',
            title           TEXT NOT NULL DEFAULT '',
            description     TEXT DEFAULT '',
            source_url      TEXT DEFAULT '',
            file_hash       TEXT DEFAULT '',
            file_size_bytes INTEGER DEFAULT 0,
            mime_type       TEXT DEFAULT '',
            tags            TEXT DEFAULT '[]',
            verified        INTEGER DEFAULT 0,
            verified_by     TEXT DEFAULT '',
            verified_at     TEXT,
            chain_of_custody TEXT DEFAULT '[]',
            status          TEXT NOT NULL DEFAULT 'pending',
            uploaded_by     TEXT DEFAULT 'system',
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_claim ON evidence_items(claim_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_type ON evidence_items(evidence_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_status ON evidence_items(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_verified ON evidence_items(verified)")


    # ── Feature #49: LITMUS Scoring Engine ──
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS litmus_scores (
            score_id TEXT PRIMARY KEY, claim_id TEXT NOT NULL,
            l_score REAL DEFAULT 0.0, l_reasoning TEXT DEFAULT '', l_flags TEXT DEFAULT '[]',
            i_score REAL DEFAULT 0.0, i_reasoning TEXT DEFAULT '', i_flags TEXT DEFAULT '[]',
            t_score REAL DEFAULT 0.0, t_reasoning TEXT DEFAULT '', t_flags TEXT DEFAULT '[]',
            m_score REAL DEFAULT 0.0, m_reasoning TEXT DEFAULT '', m_flags TEXT DEFAULT '[]',
            u_score REAL DEFAULT 0.0, u_reasoning TEXT DEFAULT '', u_flags TEXT DEFAULT '[]',
            s_score REAL DEFAULT 0.0, s_reasoning TEXT DEFAULT '', s_flags TEXT DEFAULT '[]',
            composite_score REAL DEFAULT 0.0, pass_threshold BOOLEAN DEFAULT 0,
            action_level TEXT DEFAULT 'monitor', scored_at TEXT NOT NULL, scored_by TEXT DEFAULT 'system',
            FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
        );
        CREATE INDEX IF NOT EXISTS idx_litmus_claim ON litmus_scores(claim_id);
        CREATE INDEX IF NOT EXISTS idx_litmus_composite ON litmus_scores(composite_score);
    """)

    conn.commit()

    conn.close()
    logger.info(f"Database ready: {DB_PATH}")


    # ── Supported Verticals ──
SUPPORTED_VERTICALS = {
    "platform_dispute": {
        "label": "Platform Dispute",
        "description": "Withheld funds, payout disputes, platform account issues",
        "status": "active",
    },
    "insurance_auto": {
        "label": "Auto Insurance",
        "description": "Auto insurance claim coordination, documentation, and escalation routing",
        "status": "coming_soon",
    },
    "insurance_property": {
        "label": "Property Insurance",
        "description": "Property insurance claim coordination, documentation, and escalation routing",
        "status": "coming_soon",
    },
}


class Store:
    """SQLite-backed persistent store. Survives restarts."""

    def __init__(self):
        _init_db()
        self.start_time = datetime.utcnow()

    @property
    def submission_count(self) -> int:
        conn = _get_db()
        row = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()
        conn.close()
        return row[0]

    def save_submission(self, data: Dict[str, Any]) -> str:
        sid = f"sub_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        data["submission_id"] = sid
        data["submitted_at"] = now
        conn = _get_db()
        conn.execute(
            "INSERT INTO submissions (submission_id, data, submitted_at) VALUES (?, ?, ?)",
            (sid, json.dumps(data), now),
        )
        conn.commit()
        conn.close()
        return sid

    def link_submission_to_claim(self, submission_id: str, claim_id: str):
        conn = _get_db()
        conn.execute(
            "UPDATE submissions SET converted_to = ? WHERE submission_id = ?",
            (claim_id, submission_id),
        )
        conn.commit()
        conn.close()

    def get_submission(self, submission_id: str) -> Optional[Dict[str, Any]]:
        conn = _get_db()
        row = conn.execute(
            "SELECT data, converted_to FROM submissions WHERE submission_id = ?",
            (submission_id,),
        ).fetchone()
        conn.close()
        if not row:
            return None
        result = json.loads(row["data"])
        if row["converted_to"]:
            result["converted_to_claim_id"] = row["converted_to"]
        return result

    def save_claim(self, data: Dict[str, Any]) -> str:
        cid = f"clm_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        data["claim_id"] = cid
        data["filed_at"] = now
        conn = _get_db()
        conn.execute(
            """INSERT INTO claims
               (claim_id, submission_id, vertical, status, claimant_name, claimant_email,
                respondent_entity, harm_type, amount_claimed_usd, description,
                contacted_support, referral_source, execution_score, data, filed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cid,
                data.get("intake_submission_id"),
                data.get("vertical", "platform_dispute"),
                data.get("status", "filed"),
                data.get("claimant_name", ""),
                data.get("claimant_email"),
                data.get("respondent_entity"),
                data.get("harm_type"),
                data.get("amount_claimed_usd", 0),
                data.get("description"),
                data.get("contacted_support"),
                data.get("referral_source"),
                data.get("execution_score", 0),
                json.dumps(data),
                now,
            ),
        )
        conn.commit()
        conn.close()
        return cid

    def get_claim(self, claim_id: str) -> Optional[Dict[str, Any]]:
        conn = _get_db()
        row = conn.execute(
            "SELECT data FROM claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        return json.loads(row["data"])

    def list_claims(
        self,
        status_filter: Optional[str] = None,
        respondent: Optional[str] = None,
        vertical: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        conn = _get_db()
        query = "SELECT data FROM claims WHERE 1=1"
        params: list = []
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        if respondent:
            query += " AND LOWER(respondent_entity) LIKE ?"
            params.append(f"%{respondent.lower()}%")
        if vertical:
            query += " AND vertical = ?"
            params.append(vertical)
        query += " ORDER BY filed_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [json.loads(r["data"]) for r in rows]

    def lookup_by_email(self, email: str) -> List[Dict[str, Any]]:
        """Find all claims associated with an email address (for claimant portal)."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT data FROM claims WHERE LOWER(claimant_email) = ? ORDER BY filed_at DESC",
            (email.lower().strip(),),
        ).fetchall()
        conn.close()
        return [json.loads(r["data"]) for r in rows]

    def update_claim_status(self, claim_id: str, new_status: str):
        conn = _get_db()
        now = datetime.utcnow().isoformat()
        # Update both the column and the JSON blob
        row = conn.execute(
            "SELECT data FROM claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row:
            data = json.loads(row["data"])
            data["status"] = new_status
            data["updated_at"] = now
            conn.execute(
                "UPDATE claims SET status = ?, data = ?, updated_at = ? WHERE claim_id = ?",
                (new_status, json.dumps(data), now, claim_id),
            )
            conn.commit()
        conn.close()

    def reclassify_claim(self, claim_id: str, classification: Dict[str, Any]):
        """Update classification on an existing claim."""
        conn = _get_db()
        now = datetime.utcnow().isoformat()
        row = conn.execute(
            "SELECT data FROM claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row:
            data = json.loads(row["data"])
            data["classification"] = classification
            data["updated_at"] = now
            conn.execute(
                "UPDATE claims SET data = ?, updated_at = ? WHERE claim_id = ?",
                (json.dumps(data), now, claim_id),
            )
            conn.commit()
        conn.close()

    def get_claim_events(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get all events related to a specific claim."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM events WHERE payload LIKE ? ORDER BY timestamp ASC",
            (f'%{claim_id}%',),
        ).fetchall()
        conn.close()
        return [
            {
                "event_id": r["event_id"],
                "topic": r["topic"],
                "payload": json.loads(r["payload"]),
                "timestamp": r["timestamp"],
            }
            for r in rows
        ]

    def add_note(self, claim_id: str, content: str, author: str = "operator") -> str:
        """Add a note to a claim."""
        nid = f"note_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        conn = _get_db()
        conn.execute(
            "INSERT INTO notes (note_id, claim_id, author, content, created_at) VALUES (?, ?, ?, ?, ?)",
            (nid, claim_id, author, content, now),
        )
        conn.commit()
        conn.close()
        return nid

    def get_notes(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get all notes for a claim."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM notes WHERE claim_id = ? ORDER BY created_at ASC",
            (claim_id,),
        ).fetchall()
        conn.close()
        return [
            {
                "note_id": r["note_id"],
                "claim_id": r["claim_id"],
                "author": r["author"],
                "content": r["content"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def get_followups(self) -> List[Dict[str, Any]]:
        """
        Compute follow-up actions needed for all active claims.
        Escalation timeline:
          Day 1-3:  Initial Recovery Notice
          Day 5-10: Second Escalation
          Day 10-21: Compliance Escalation
          Day 21+:  ILF Referral / Legal Review
        """
        conn = _get_db()
        rows = conn.execute(
            "SELECT data FROM claims WHERE status NOT IN ('resolved', 'closed')"
        ).fetchall()
        conn.close()

        now = datetime.utcnow()
        followups = []
        for row in rows:
            claim = json.loads(row["data"])
            filed_str = claim.get("filed_at", "")
            if not filed_str:
                continue
            try:
                filed = datetime.fromisoformat(filed_str.replace("Z", "+00:00").replace("+00:00", ""))
            except (ValueError, TypeError):
                filed = now

            age_days = (now - filed).days
            claim_id = claim.get("claim_id", "")
            respondent = claim.get("respondent_entity", "Unknown")
            amount = claim.get("amount_claimed_usd", 0)
            claimant = claim.get("claimant_name", "")
            status_val = claim.get("status", "filed")
            cc = claim.get("classification", {})

            # Determine escalation stage
            if age_days < 1:
                stage = "new"
                action = "Prepare initial recovery notice"
                urgency = "low"
                template = "initial"
            elif age_days <= 3:
                stage = "initial_demand"
                action = "Send Initial Recovery Notice"
                urgency = "medium"
                template = "initial"
            elif age_days <= 5:
                stage = "awaiting_response"
                action = "Monitor for platform response"
                urgency = "low"
                template = None
            elif age_days <= 10:
                stage = "second_escalation"
                action = "Send Second Escalation Notice"
                urgency = "high"
                template = "second"
            elif age_days <= 21:
                stage = "compliance_escalation"
                action = "Send Compliance Reference (cite applicable frameworks)"
                urgency = "high"
                template = "compliance"
            else:
                stage = "legal_review"
                action = "Refer to ILF for legal review"
                urgency = "critical"
                template = None

            # Skip if already resolved/closed
            if status_val in ("resolved", "closed"):
                continue

            # Find last contact event (letter generation or status change)
            last_contact = None
            try:
                conn2 = _get_db()
                evt_row = conn2.execute(
                    "SELECT timestamp FROM events WHERE claim_id = ? AND topic IN ('doc.letter.generated','claim.status.changed') ORDER BY timestamp DESC LIMIT 1",
                    (claim_id,),
                ).fetchone()
                if evt_row:
                    last_contact = evt_row["timestamp"]
                conn2.close()
            except Exception:
                pass

            followups.append({
                "claim_id": claim_id,
                "claimant": claimant,
                "respondent": respondent,
                "amount": amount,
                "status": status_val,
                "filed_at": filed_str,
                "age_days": age_days,
                "stage": stage,
                "action": action,
                "urgency": urgency,
                "template": template,
                "value_band": cc.get("value_band", "unknown"),
                "recovery_path": cc.get("recovery_path", "unknown"),
                "last_contacted": last_contact,
            })

        # Sort by urgency (critical first) then age
        urgency_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        followups.sort(key=lambda f: (urgency_order.get(f["urgency"], 9), -f["age_days"]))
        return followups

    def publish_event(self, topic: str, payload: Dict[str, Any]):
        """Persist event and log it. In production, also sends to NATS."""
        eid = f"bus_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        conn = _get_db()
        conn.execute(
            "INSERT INTO events (event_id, topic, payload, timestamp) VALUES (?, ?, ?, ?)",
            (eid, topic, json.dumps(payload), now),
        )
        conn.commit()
        conn.close()
        logger.info(f"Event published: {topic} -> {eid}")

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate dashboard statistics from claims table."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        total_claimed = conn.execute(
            "SELECT COALESCE(SUM(amount_claimed_usd), 0) FROM claims"
        ).fetchone()[0]
        resolved = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status IN ('resolved', 'closed')"
        ).fetchone()[0]
        active = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status IN ('filed', 'under_review', 'in_resolution')"
        ).fetchone()[0]
        escalated = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status = 'escalated'"
        ).fetchone()[0]

        # Value band breakdown
        bands = {}
        for row in conn.execute("SELECT data FROM claims").fetchall():
            d = json.loads(row["data"])
            vb = d.get("classification", {}).get("value_band", "unclassified")
            bands[vb] = bands.get(vb, 0) + 1

        # Dispute type breakdown
        dispute_types = {}
        for row in conn.execute("SELECT data FROM claims").fetchall():
            d = json.loads(row["data"])
            dt = d.get("classification", {}).get("dispute_type", "unclassified")
            dispute_types[dt] = dispute_types.get(dt, 0) + 1

        # Recovery path breakdown
        recovery_paths = {}
        for row in conn.execute("SELECT data FROM claims").fetchall():
            d = json.loads(row["data"])
            rp = d.get("classification", {}).get("recovery_path", "unclassified")
            recovery_paths[rp] = recovery_paths.get(rp, 0) + 1

        # Triage queue
        triage_needed = 0
        for row in conn.execute("SELECT data FROM claims").fetchall():
            d = json.loads(row["data"])
            if d.get("classification", {}).get("requires_human_triage", False):
                triage_needed += 1

        # Top respondents
        respondents = {}
        for row in conn.execute("SELECT respondent_entity, COUNT(*) as cnt FROM claims GROUP BY respondent_entity ORDER BY cnt DESC LIMIT 10").fetchall():
            respondents[row["respondent_entity"] or "Unknown"] = row["cnt"]

        conn.close()

        resolution_rate = round((resolved / total * 100), 1) if total > 0 else 0.0

        return {
            "total_claims": total,
            "total_claimed_usd": round(total_claimed, 2),
            "resolved": resolved,
            "active": active,
            "escalated": escalated,
            "resolution_rate": resolution_rate,
            "triage_queue": triage_needed,
            "value_bands": bands,
            "dispute_types": dispute_types,
            "recovery_paths": recovery_paths,
            "top_respondents": respondents,
        }

    def list_events(
        self, topic: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        conn = _get_db()
        if topic:
            rows = conn.execute(
                "SELECT * FROM events WHERE topic = ? ORDER BY timestamp DESC LIMIT ?",
                (topic, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        conn.close()
        return [
            {
                "event_id": r["event_id"],
                "topic": r["topic"],
                "payload": json.loads(r["payload"]),
                "timestamp": r["timestamp"],
            }
            for r in rows
        ]


    # ── Audit Log ──

    def audit(self, action: str, detail: Dict[str, Any] = None, actor: str = "system"):
        """Write an immutable audit log entry."""
        aid = f"aud_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        conn = _get_db()
        conn.execute(
            "INSERT INTO audit_log (audit_id, action, actor, detail, timestamp) VALUES (?, ?, ?, ?, ?)",
            (aid, action, actor, json.dumps(detail or {}), now),
        )
        conn.commit()
        conn.close()
        logger.info(f"Audit: {action} by {actor} -> {aid}")

    def get_audit_log(self, action: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve audit log entries, newest first. Includes monotonic seq for ordering."""
        conn = _get_db()
        if action:
            rows = conn.execute(
                "SELECT rowid, * FROM audit_log WHERE action = ? ORDER BY rowid DESC LIMIT ?",
                (action, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT rowid, * FROM audit_log ORDER BY rowid DESC LIMIT ?", (limit,),
            ).fetchall()
        conn.close()
        return [
            {
                "seq": r["rowid"],
                "audit_id": r["audit_id"],
                "action": r["action"],
                "actor": r["actor"],
                "detail": json.loads(r["detail"]),
                "timestamp": r["timestamp"],
            }
            for r in rows
        ]


    # ── Respondent Intelligence ──

    def get_respondent_profiles(self) -> List[Dict[str, Any]]:
        """
        Aggregate claim data per respondent entity into intelligence profiles.
        Returns: per-respondent metrics including claim count, amounts,
        status distribution, resolution rate, harm types, and risk score.
        """
        conn = _get_db()
        rows = conn.execute("SELECT data FROM claims ORDER BY filed_at DESC").fetchall()
        conn.close()

        # Build per-respondent aggregation
        respondents: Dict[str, Dict[str, Any]] = {}
        now = datetime.utcnow()

        for row in rows:
            claim = json.loads(row["data"])
            entity = (claim.get("respondent_entity") or "Unknown").strip()
            if entity not in respondents:
                respondents[entity] = {
                    "entity": entity,
                    "total_claims": 0,
                    "total_amount": 0.0,
                    "statuses": {},
                    "harm_types": {},
                    "value_bands": {},
                    "dispute_types": {},
                    "recovery_paths": {},
                    "ages_days": [],
                    "first_claim": None,
                    "last_claim": None,
                    "claims": [],
                }

            r = respondents[entity]
            r["total_claims"] += 1
            r["total_amount"] += claim.get("amount_claimed_usd", 0)

            # Status distribution
            st = claim.get("status", "filed")
            r["statuses"][st] = r["statuses"].get(st, 0) + 1

            # Harm type distribution
            ht = claim.get("harm_type", "other")
            r["harm_types"][ht] = r["harm_types"].get(ht, 0) + 1

            # Classification breakdowns
            cc = claim.get("classification", {})
            vb = cc.get("value_band", "unclassified")
            r["value_bands"][vb] = r["value_bands"].get(vb, 0) + 1
            dt = cc.get("dispute_type", "unclassified")
            r["dispute_types"][dt] = r["dispute_types"].get(dt, 0) + 1
            rp = cc.get("recovery_path", "unclassified")
            r["recovery_paths"][rp] = r["recovery_paths"].get(rp, 0) + 1

            # Age tracking
            filed_str = claim.get("filed_at", "")
            if filed_str:
                try:
                    filed = datetime.fromisoformat(filed_str.replace("Z", "+00:00").replace("+00:00", ""))
                    age = (now - filed).days
                    r["ages_days"].append(age)
                    if r["first_claim"] is None or filed_str < r["first_claim"]:
                        r["first_claim"] = filed_str
                    if r["last_claim"] is None or filed_str > r["last_claim"]:
                        r["last_claim"] = filed_str
                except (ValueError, TypeError):
                    pass

            # Compact claim reference
            r["claims"].append({
                "claim_id": claim.get("claim_id", ""),
                "amount": claim.get("amount_claimed_usd", 0),
                "status": st,
                "harm_type": ht,
                "filed_at": filed_str,
                "value_band": vb,
            })

        # Compute derived metrics per respondent
        profiles = []
        for entity, r in respondents.items():
            resolved = r["statuses"].get("resolved", 0) + r["statuses"].get("closed", 0)
            total = r["total_claims"]
            resolution_rate = round((resolved / total * 100), 1) if total > 0 else 0.0
            avg_age = round(sum(r["ages_days"]) / len(r["ages_days"]), 1) if r["ages_days"] else 0.0
            active = total - resolved

            # Risk score (0-100): higher = more problematic respondent
            # Factors: claim volume, active ratio, avg amount, lack of resolution
            volume_score = min(total * 10, 30)  # 0-30 based on claim count
            active_ratio = (active / total * 25) if total > 0 else 0  # 0-25 based on unresolved %
            amount_score = min(r["total_amount"] / 10000 * 20, 25)  # 0-25 based on total $
            age_score = min(avg_age / 30 * 20, 20)  # 0-20 based on avg claim age
            risk_score = round(min(volume_score + active_ratio + amount_score + age_score, 100))

            risk_level = "low"
            if risk_score >= 70:
                risk_level = "critical"
            elif risk_score >= 50:
                risk_level = "high"
            elif risk_score >= 30:
                risk_level = "medium"

            # Top harm type
            top_harm = max(r["harm_types"], key=r["harm_types"].get) if r["harm_types"] else "unknown"

            profiles.append({
                "entity": entity,
                "total_claims": total,
                "active_claims": active,
                "resolved_claims": resolved,
                "total_amount": round(r["total_amount"], 2),
                "avg_amount": round(r["total_amount"] / total, 2) if total > 0 else 0,
                "resolution_rate": resolution_rate,
                "avg_age_days": avg_age,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "top_harm_type": top_harm,
                "statuses": r["statuses"],
                "harm_types": r["harm_types"],
                "value_bands": r["value_bands"],
                "dispute_types": r["dispute_types"],
                "recovery_paths": r["recovery_paths"],
                "first_claim": r["first_claim"],
                "last_claim": r["last_claim"],
                "claims": r["claims"],
            })

        # Sort by risk score descending
        profiles.sort(key=lambda p: p["risk_score"], reverse=True)
        return profiles

    def get_respondent_detail(self, entity_name: str) -> Optional[Dict[str, Any]]:
        """Get a single respondent profile by entity name."""
        profiles = self.get_respondent_profiles()
        for p in profiles:
            if p["entity"].lower() == entity_name.lower():
                return p
        return None

    # ── Escalation Rules Engine ──

    def evaluate_escalation_rules(self) -> Dict[str, Any]:
        """
        Evaluate all active claims against escalation rules.
        Returns recommended actions (not yet executed).
        """
        conn = _get_db()
        now = datetime.utcnow()
        active_statuses = {"filed", "under_review", "escalated", "in_resolution", "appealed"}

        claims = conn.execute(
            "SELECT claim_id, claimant_name, respondent_entity, status, amount_claimed_usd, harm_type, filed_at, updated_at, data FROM claims WHERE status IN ({})".format(
                ",".join(["?"] * len(active_statuses))
            ),
            tuple(active_statuses),
        ).fetchall()

        # Last status change per claim
        last_change = {}
        for row in conn.execute(
            "SELECT detail, timestamp FROM audit_log WHERE action = 'status.changed' ORDER BY timestamp ASC"
        ).fetchall():
            try:
                d = json.loads(row["detail"])
                cid = d.get("claim_id", "")
                if cid:
                    last_change[cid] = row["timestamp"]
            except (json.JSONDecodeError, KeyError):
                pass

        # Respondent claim counts
        respondent_counts = {}
        for row in conn.execute(
            "SELECT respondent_entity, COUNT(*) as cnt FROM claims GROUP BY respondent_entity"
        ).fetchall():
            respondent_counts[row["respondent_entity"] or "Unknown"] = row["cnt"]

        conn.close()

        recommendations = []

        for rule in ESCALATION_RULES:
            if not rule.get("enabled", True):
                continue

            cond = rule["condition"]
            action = rule["action"]

            for row in claims:
                cid = row["claim_id"]
                status = row["status"]
                amount = row["amount_claimed_usd"] or 0
                respondent = row["respondent_entity"] or ""

                try:
                    data = json.loads(row["data"])
                except (json.JSONDecodeError, TypeError):
                    data = {}
                cc = data.get("classification", {})

                # Check status match
                if "status" in cond and status != cond["status"]:
                    continue
                if "statuses" in cond and status not in cond["statuses"]:
                    continue

                # Check amount threshold
                if "min_amount" in cond and amount < cond["min_amount"]:
                    continue

                # Check days in status
                if "min_days_in_status" in cond:
                    entered_str = last_change.get(cid, row["filed_at"])
                    try:
                        entered = datetime.fromisoformat(entered_str.replace("Z", "+00:00")).replace(tzinfo=None)
                    except (ValueError, AttributeError):
                        entered = now
                    days_in = (now - entered).total_seconds() / 86400
                    if days_in < cond["min_days_in_status"]:
                        continue

                # Check SLA status
                if "sla_status" in cond:
                    sla_rule = SLA_RULES.get(status)
                    if sla_rule:
                        entered_str = last_change.get(cid, row["filed_at"])
                        try:
                            entered = datetime.fromisoformat(entered_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        except (ValueError, AttributeError):
                            entered = now
                        days_in = (now - entered).total_seconds() / 86400
                        max_d = sla_rule["max_days"]
                        if cond["sla_status"] == "breached" and days_in <= max_d:
                            continue
                        if cond["sla_status"] == "at_risk" and days_in < max_d * sla_rule["warn_pct"]:
                            continue
                    else:
                        continue

                # Check triage flag
                if cond.get("requires_triage") and not cc.get("requires_human_triage", False):
                    continue

                # Check value band
                if "value_band" in cond and cc.get("value_band") != cond["value_band"]:
                    continue

                # Check respondent claim count
                if "min_respondent_claims" in cond:
                    rc = respondent_counts.get(respondent, 0)
                    if rc < cond["min_respondent_claims"]:
                        continue

                # Validate the action is a valid transition
                if action["type"] == "status_change":
                    target = action["target_status"]
                    allowed = VALID_STATUS_TRANSITIONS.get(status, set())
                    if target not in allowed:
                        continue

                # All conditions matched — create recommendation
                recommendations.append({
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "priority": rule["priority"],
                    "claim_id": cid,
                    "claimant": row["claimant_name"],
                    "respondent": respondent,
                    "amount": amount,
                    "current_status": status,
                    "action": action,
                })

        # Deduplicate: only keep highest-priority recommendation per claim
        priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        seen = {}
        for rec in recommendations:
            cid = rec["claim_id"]
            rank = priority_rank.get(rec["priority"], 9)
            if cid not in seen or rank < priority_rank.get(seen[cid]["priority"], 9):
                seen[cid] = rec
        deduped = sorted(seen.values(), key=lambda r: (priority_rank.get(r["priority"], 9), -r["amount"]))

        return {
            "total_evaluated": len(claims),
            "rules_active": sum(1 for r in ESCALATION_RULES if r.get("enabled", True)),
            "recommendations": deduped,
            "total_recommendations": len(deduped),
            "by_priority": {
                "critical": sum(1 for r in deduped if r["priority"] == "critical"),
                "high": sum(1 for r in deduped if r["priority"] == "high"),
                "medium": sum(1 for r in deduped if r["priority"] == "medium"),
                "low": sum(1 for r in deduped if r["priority"] == "low"),
            },
        }

    # ── Saved Views ──

    def list_saved_views(self) -> List[Dict[str, Any]]:
        conn = _get_db()
        rows = conn.execute("SELECT * FROM saved_views ORDER BY updated_at DESC").fetchall()
        conn.close()
        result = []
        for r in rows:
            result.append({
                "view_id": r["view_id"],
                "name": r["name"],
                "filters": json.loads(r["filters"]),
                "sort_by": r["sort_by"],
                "sort_dir": r["sort_dir"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return result

    def save_view(self, name: str, filters: Dict, sort_by: str = "filed_at", sort_dir: str = "desc") -> Dict[str, Any]:
        conn = _get_db()
        view_id = f"view_{uuid.uuid4().hex[:10]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO saved_views (view_id, name, filters, sort_by, sort_dir, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (view_id, name, json.dumps(filters), sort_by, sort_dir, now, now),
        )
        conn.commit()
        conn.close()
        return {"view_id": view_id, "name": name, "filters": filters, "sort_by": sort_by, "sort_dir": sort_dir, "created_at": now}

    def delete_saved_view(self, view_id: str) -> bool:
        conn = _get_db()
        cur = conn.execute("DELETE FROM saved_views WHERE view_id = ?", (view_id,))
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    # ── SLA Engine ──

    def check_sla(self) -> Dict[str, Any]:
        """
        Evaluate all active claims against SLA rules.
        Returns per-claim SLA status and aggregate compliance metrics.
        """
        conn = _get_db()
        now = datetime.utcnow()
        active_statuses = set(SLA_RULES.keys())

        claims = conn.execute(
            "SELECT claim_id, claimant_name, respondent_entity, status, amount_claimed_usd, filed_at, updated_at FROM claims WHERE status IN ({})".format(
                ",".join(["?"] * len(active_statuses))
            ),
            tuple(active_statuses),
        ).fetchall()

        # Get last status change from audit log per claim
        last_status_change = {}
        for row in conn.execute(
            "SELECT detail, timestamp FROM audit_log WHERE action = 'status.changed' ORDER BY timestamp ASC"
        ).fetchall():
            try:
                d = json.loads(row["detail"])
                cid = d.get("claim_id", "")
                if cid:
                    last_status_change[cid] = row["timestamp"]
            except (json.JSONDecodeError, KeyError):
                pass

        conn.close()

        results = []
        on_track = 0
        at_risk = 0
        breached = 0
        total_active = len(claims)

        for row in claims:
            cid = row["claim_id"]
            status = row["status"]
            rule = SLA_RULES.get(status)
            if not rule:
                continue

            max_days = rule["max_days"]
            warn_pct = rule["warn_pct"]

            # Calculate days in current status
            # Use last status change timestamp if available, else filed_at
            entered_at_str = last_status_change.get(cid, row["filed_at"])
            try:
                entered_at = datetime.fromisoformat(entered_at_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except (ValueError, AttributeError):
                entered_at = datetime.fromisoformat(row["filed_at"].replace("Z", "+00:00")).replace(tzinfo=None)

            days_in_status = (now - entered_at).total_seconds() / 86400
            remaining_days = max_days - days_in_status
            usage_pct = min((days_in_status / max_days * 100), 100) if max_days > 0 else 100

            if days_in_status > max_days:
                sla_status = "breached"
                breached += 1
            elif days_in_status >= max_days * warn_pct:
                sla_status = "at_risk"
                at_risk += 1
            else:
                sla_status = "on_track"
                on_track += 1

            results.append({
                "claim_id": cid,
                "claimant": row["claimant_name"],
                "respondent": row["respondent_entity"],
                "amount": row["amount_claimed_usd"] or 0,
                "status": status,
                "sla_rule": rule["label"],
                "max_days": max_days,
                "days_in_status": round(days_in_status, 1),
                "remaining_days": round(remaining_days, 1),
                "usage_pct": round(usage_pct, 1),
                "sla_status": sla_status,
            })

        # Sort: breached first, then at_risk, then on_track; within each by usage_pct desc
        priority = {"breached": 0, "at_risk": 1, "on_track": 2}
        results.sort(key=lambda r: (priority.get(r["sla_status"], 3), -r["usage_pct"]))

        compliance_rate = round((on_track / total_active * 100), 1) if total_active > 0 else 100.0

        return {
            "total_active": total_active,
            "on_track": on_track,
            "at_risk": at_risk,
            "breached": breached,
            "compliance_rate": compliance_rate,
            "sla_rules": {s: {"max_days": r["max_days"], "label": r["label"]} for s, r in SLA_RULES.items()},
            "claims": results,
        }

    # ── Recovery Tracking ──

    def record_recovery(self, claim_id: str, amount: float, method: str = "direct_refund",
                        recovered_by: str = "operator", notes: str = "") -> Dict[str, Any]:
        """Record a recovery event against a claim."""
        conn = _get_db()
        claim = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            return None

        recovery_id = f"rec_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO recoveries (recovery_id, claim_id, amount_recovered, recovery_method, recovered_by, notes, recorded_at) VALUES (?,?,?,?,?,?,?)",
            (recovery_id, claim_id, round(amount, 2), method, recovered_by, notes, now),
        )
        conn.commit()
        conn.close()
        return {
            "recovery_id": recovery_id,
            "claim_id": claim_id,
            "amount_recovered": round(amount, 2),
            "recovery_method": method,
            "recovered_by": recovered_by,
            "notes": notes,
            "recorded_at": now,
        }

    def get_claim_recoveries(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get all recovery records for a claim."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM recoveries WHERE claim_id = ? ORDER BY recorded_at DESC", (claim_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_recovery_stats(self) -> Dict[str, Any]:
        """Aggregate recovery metrics across all claims."""
        conn = _get_db()

        # Total recovered
        total_recovered = conn.execute(
            "SELECT COALESCE(SUM(amount_recovered), 0) FROM recoveries"
        ).fetchone()[0]

        # Total claimed
        total_claimed = conn.execute(
            "SELECT COALESCE(SUM(amount_claimed_usd), 0) FROM claims"
        ).fetchone()[0]

        # Claims with at least one recovery
        claims_with_recovery = conn.execute(
            "SELECT COUNT(DISTINCT claim_id) FROM recoveries"
        ).fetchone()[0]

        total_claims = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]

        # Recovery count
        recovery_count = conn.execute("SELECT COUNT(*) FROM recoveries").fetchone()[0]

        # Per-claim recovery breakdown (claims that have recoveries)
        per_claim = conn.execute("""
            SELECT c.claim_id, c.claimant_name, c.respondent_entity, c.amount_claimed_usd, c.status,
                   COALESCE(SUM(r.amount_recovered), 0) as total_recovered,
                   COUNT(r.recovery_id) as recovery_events
            FROM claims c
            LEFT JOIN recoveries r ON c.claim_id = r.claim_id
            GROUP BY c.claim_id
            HAVING total_recovered > 0
            ORDER BY total_recovered DESC
        """).fetchall()

        claim_recoveries = []
        for row in per_claim:
            claimed = row["amount_claimed_usd"] or 0
            recovered = row["total_recovered"] or 0
            claim_recoveries.append({
                "claim_id": row["claim_id"],
                "claimant": row["claimant_name"],
                "respondent": row["respondent_entity"],
                "amount_claimed": round(claimed, 2),
                "amount_recovered": round(recovered, 2),
                "recovery_pct": round((recovered / claimed * 100), 1) if claimed > 0 else 0.0,
                "recovery_events": row["recovery_events"],
                "status": row["status"],
            })

        # By method
        by_method = {}
        for row in conn.execute(
            "SELECT recovery_method, COUNT(*) as cnt, SUM(amount_recovered) as total FROM recoveries GROUP BY recovery_method ORDER BY total DESC"
        ).fetchall():
            by_method[row["recovery_method"]] = {
                "count": row["cnt"],
                "total_usd": round(row["total"], 2),
            }

        # By respondent (top 10 by recovery)
        by_respondent = []
        for row in conn.execute("""
            SELECT c.respondent_entity, SUM(r.amount_recovered) as recovered, SUM(c.amount_claimed_usd) as claimed
            FROM recoveries r
            JOIN claims c ON r.claim_id = c.claim_id
            GROUP BY c.respondent_entity
            ORDER BY recovered DESC
            LIMIT 10
        """).fetchall():
            claimed_amt = row["claimed"] or 0
            recovered_amt = row["recovered"] or 0
            by_respondent.append({
                "respondent": row["respondent_entity"],
                "recovered": round(recovered_amt, 2),
                "claimed": round(claimed_amt, 2),
                "recovery_pct": round((recovered_amt / claimed_amt * 100), 1) if claimed_amt > 0 else 0,
            })

        # Recovery timeline (last 30 days)
        thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
        timeline = []
        for row in conn.execute("""
            SELECT DATE(recorded_at) as day, SUM(amount_recovered) as daily_total, COUNT(*) as cnt
            FROM recoveries
            WHERE recorded_at >= ?
            GROUP BY day ORDER BY day
        """, (thirty_days_ago,)).fetchall():
            timeline.append({
                "date": row["day"],
                "amount": round(row["daily_total"], 2),
                "count": row["cnt"],
            })

        conn.close()

        overall_rate = round((total_recovered / total_claimed * 100), 1) if total_claimed > 0 else 0.0
        claim_rate = round((claims_with_recovery / total_claims * 100), 1) if total_claims > 0 else 0.0

        return {
            "total_recovered_usd": round(total_recovered, 2),
            "total_claimed_usd": round(total_claimed, 2),
            "recovery_rate_usd": overall_rate,
            "claims_with_recovery": claims_with_recovery,
            "total_claims": total_claims,
            "claim_recovery_rate": claim_rate,
            "recovery_count": recovery_count,
            "by_method": by_method,
            "by_respondent": by_respondent,
            "claim_recoveries": claim_recoveries,
            "timeline_30d": timeline,
        }

    # ── System Health & Data Integrity ──

    def check_integrity(self) -> Dict[str, Any]:
        """
        Comprehensive data integrity and compliance health check.
        Returns per-check pass/warn/fail status with details.
        """
        conn = _get_db()
        now = datetime.utcnow()
        checks = []

        # 1. Audit Coverage: every claim should have a claim.intake audit entry
        claims = conn.execute("SELECT claim_id, respondent_entity FROM claims").fetchall()
        claim_ids = {r["claim_id"] for r in claims}
        audit_intakes = set()
        for row in conn.execute("SELECT detail FROM audit_log WHERE action = 'claim.intake'").fetchall():
            try:
                d = json.loads(row["detail"])
                cid = d.get("claim_id", "")
                if cid:
                    audit_intakes.add(cid)
            except Exception:
                pass
        missing_audit = claim_ids - audit_intakes
        checks.append({
            "id": "audit_coverage",
            "name": "Audit Trail Coverage",
            "description": "Every claim has a corresponding intake audit entry",
            "status": "pass" if not missing_audit else ("warn" if len(missing_audit) <= 2 else "fail"),
            "detail": f"{len(claim_ids) - len(missing_audit)}/{len(claim_ids)} claims have intake audit records",
            "missing": list(missing_audit)[:5] if missing_audit else [],
        })

        # 2. Classification Coverage: every claim should be classified
        classified = set()
        for row in conn.execute("SELECT detail FROM audit_log WHERE action = 'claim.classified'").fetchall():
            try:
                d = json.loads(row["detail"])
                cid = d.get("claim_id", "")
                if cid:
                    classified.add(cid)
            except Exception:
                pass
        # Also check JSON data for classification
        for row in conn.execute("SELECT claim_id, data FROM claims").fetchall():
            try:
                d = json.loads(row["data"])
                if d.get("classification", {}).get("value_band"):
                    classified.add(row["claim_id"])
            except Exception:
                pass
        unclassified = claim_ids - classified
        checks.append({
            "id": "classification_coverage",
            "name": "Classification Coverage",
            "description": "Every claim has been processed by CCE classification engine",
            "status": "pass" if not unclassified else ("warn" if len(unclassified) <= 2 else "fail"),
            "detail": f"{len(classified)}/{len(claim_ids)} claims classified",
            "missing": list(unclassified)[:5] if unclassified else [],
        })

        # 3. Required Field Completeness
        incomplete = []
        required_fields = ["claimant_name", "respondent_entity", "amount_claimed_usd", "harm_type"]
        for row in conn.execute("SELECT claim_id, data FROM claims").fetchall():
            try:
                d = json.loads(row["data"])
                missing = [f for f in required_fields if not d.get(f)]
                if missing:
                    incomplete.append({"claim_id": row["claim_id"], "missing": missing})
            except Exception:
                incomplete.append({"claim_id": row["claim_id"], "missing": ["data_parse_error"]})
        checks.append({
            "id": "field_completeness",
            "name": "Required Field Completeness",
            "description": "All claims have required fields populated (name, respondent, amount, harm type)",
            "status": "pass" if not incomplete else ("warn" if len(incomplete) <= 2 else "fail"),
            "detail": f"{len(claim_ids) - len(incomplete)}/{len(claim_ids)} claims fully populated",
            "issues": incomplete[:5] if incomplete else [],
        })

        # 4. Orphan Detection: referrals pointing to nonexistent claims or lawyers
        orphan_referrals = []
        lawyer_ids = {r["lawyer_id"] for r in conn.execute("SELECT lawyer_id FROM ilf_lawyers").fetchall()}
        for row in conn.execute("SELECT referral_id, claim_id, lawyer_id FROM ilf_referrals").fetchall():
            issues = []
            if row["claim_id"] not in claim_ids:
                issues.append("claim_missing")
            if row["lawyer_id"] not in lawyer_ids:
                issues.append("lawyer_missing")
            if issues:
                orphan_referrals.append({"referral_id": row["referral_id"], "issues": issues})
        checks.append({
            "id": "orphan_detection",
            "name": "Referential Integrity",
            "description": "All referrals point to valid claims and professionals",
            "status": "pass" if not orphan_referrals else "fail",
            "detail": f"{'No' if not orphan_referrals else len(orphan_referrals)} orphaned referrals detected",
            "issues": orphan_referrals[:5] if orphan_referrals else [],
        })

        # 5. SLA Adherence: no active claim older than 30 days without recent activity
        sla_breaches = []
        for row in conn.execute("SELECT claim_id, data, filed_at, status FROM claims WHERE status NOT IN ('resolved','closed')").fetchall():
            try:
                filed = datetime.fromisoformat(row["filed_at"].replace("Z", "").replace("+00:00", ""))
                age = (now - filed).days
                if age > 30:
                    # Check for recent audit activity
                    recent = conn.execute(
                        "SELECT COUNT(*) FROM audit_log WHERE detail LIKE ? AND timestamp > ?",
                        (f'%{row["claim_id"]}%', (now - timedelta(days=14)).isoformat()),
                    ).fetchone()[0]
                    if recent == 0:
                        sla_breaches.append({
                            "claim_id": row["claim_id"],
                            "age_days": age,
                            "status": row["status"],
                            "last_activity": "none in 14 days",
                        })
            except (ValueError, TypeError):
                pass
        checks.append({
            "id": "sla_adherence",
            "name": "SLA Adherence",
            "description": "No active claim older than 30 days without activity in last 14 days",
            "status": "pass" if not sla_breaches else ("warn" if len(sla_breaches) <= 2 else "fail"),
            "detail": f"{'No' if not sla_breaches else len(sla_breaches)} SLA breaches detected",
            "issues": sla_breaches[:5] if sla_breaches else [],
        })

        # 6. ILF Consent Compliance: all referrals should have consent timestamp
        consent_issues = []
        for row in conn.execute("SELECT referral_id, claim_id, claimant_consent_at FROM ilf_referrals").fetchall():
            if not row["claimant_consent_at"]:
                consent_issues.append({"referral_id": row["referral_id"], "claim_id": row["claim_id"]})
        total_referrals = conn.execute("SELECT COUNT(*) FROM ilf_referrals").fetchone()[0]
        checks.append({
            "id": "consent_compliance",
            "name": "ILF Consent Tracking",
            "description": "All referrals have documented claimant consent with timestamp",
            "status": "pass" if not consent_issues else ("warn" if total_referrals == 0 else "fail"),
            "detail": f"{total_referrals - len(consent_issues)}/{total_referrals} referrals with documented consent" if total_referrals > 0 else "No referrals to check",
            "issues": consent_issues[:5] if consent_issues else [],
        })

        # 7. Audit Log Monotonicity: rowid should be strictly increasing with timestamp
        audit_rows = conn.execute("SELECT rowid, timestamp FROM audit_log ORDER BY rowid ASC LIMIT 200").fetchall()
        out_of_order = 0
        prev_ts = ""
        for r in audit_rows:
            if r["timestamp"] < prev_ts:
                out_of_order += 1
            prev_ts = r["timestamp"]
        checks.append({
            "id": "audit_ordering",
            "name": "Audit Log Ordering",
            "description": "Audit log entries are in monotonically increasing timestamp order",
            "status": "pass" if out_of_order == 0 else "warn",
            "detail": f"{'All' if out_of_order == 0 else str(out_of_order)} entries {'in order' if out_of_order == 0 else 'out of order'} (checked {len(audit_rows)})",
        })

        # 8. Database Size Check
        import os as _os
        db_size = _os.path.getsize(DB_PATH) if _os.path.exists(DB_PATH) else 0
        db_mb = round(db_size / 1048576, 2)
        checks.append({
            "id": "db_size",
            "name": "Database Size",
            "description": "Database file size within operational limits (<500MB)",
            "status": "pass" if db_mb < 100 else ("warn" if db_mb < 500 else "fail"),
            "detail": f"{db_mb} MB",
        })

        conn.close()

        # Compute overall score
        pass_count = sum(1 for c in checks if c["status"] == "pass")
        warn_count = sum(1 for c in checks if c["status"] == "warn")
        fail_count = sum(1 for c in checks if c["status"] == "fail")
        total_checks = len(checks)
        score = round((pass_count / total_checks * 100) if total_checks > 0 else 0)

        overall = "healthy"
        if fail_count > 0:
            overall = "degraded"
        elif warn_count > 2:
            overall = "warning"
        elif warn_count > 0:
            overall = "good"

        return {
            "overall": overall,
            "score": score,
            "checks": checks,
            "summary": {
                "total": total_checks,
                "pass": pass_count,
                "warn": warn_count,
                "fail": fail_count,
            },
            "checked_at": now.isoformat(),
            "total_claims": len(claim_ids),
            "total_referrals": total_referrals if 'total_referrals' in dir() else 0,
            "total_audit_entries": len(audit_rows),
        }

    # ── ILF Lawyer Management ──

    def register_lawyer(self, name: str, email: str, bar_number: str = "",
                        jurisdiction: str = "US-General", specializations: List[str] = None,
                        max_caseload: int = 10) -> str:
        """Register a new lawyer in the ILF network."""
        lid = f"law_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        conn = _get_db()
        conn.execute(
            "INSERT INTO ilf_lawyers (lawyer_id, full_name, email, bar_number, jurisdiction, specializations, status, max_caseload, registered_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
            (lid, name, email, bar_number, jurisdiction, json.dumps(specializations or []), max_caseload, now, now),
        )
        conn.commit()
        conn.close()
        return lid

    def list_lawyers(self, status_filter: str = None) -> List[Dict[str, Any]]:
        """List all lawyers, optionally filtered by status."""
        conn = _get_db()
        if status_filter:
            rows = conn.execute("SELECT * FROM ilf_lawyers WHERE status = ? ORDER BY registered_at DESC", (status_filter,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ilf_lawyers ORDER BY registered_at DESC").fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["specializations"] = json.loads(d.get("specializations", "[]"))
            result.append(d)
        return result

    def get_lawyer(self, lawyer_id: str) -> Optional[Dict[str, Any]]:
        """Get a single lawyer by ID."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM ilf_lawyers WHERE lawyer_id = ?", (lawyer_id,)).fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["specializations"] = json.loads(d.get("specializations", "[]"))
        return d

    def update_lawyer_status(self, lawyer_id: str, new_status: str):
        """Update a lawyer's availability status."""
        conn = _get_db()
        now = datetime.utcnow().isoformat()
        conn.execute("UPDATE ilf_lawyers SET status = ?, updated_at = ? WHERE lawyer_id = ?", (new_status, now, lawyer_id))
        conn.commit()
        conn.close()

    def get_lawyer_caseload(self, lawyer_id: str) -> int:
        """Count active referrals for a lawyer."""
        conn = _get_db()
        row = conn.execute(
            "SELECT COUNT(*) FROM ilf_referrals WHERE lawyer_id = ? AND status IN ('pending', 'accepted')",
            (lawyer_id,),
        ).fetchone()
        conn.close()
        return row[0]

    def create_referral(self, claim_id: str, lawyer_id: str) -> str:
        """Create a case referral to a lawyer."""
        rid = f"ref_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        conn = _get_db()
        conn.execute(
            "INSERT INTO ilf_referrals (referral_id, claim_id, lawyer_id, status, referred_at) VALUES (?, ?, ?, 'pending', ?)",
            (rid, claim_id, lawyer_id, now),
        )
        conn.commit()
        conn.close()
        return rid

    def update_referral_status(self, referral_id: str, new_status: str, notes: str = ""):
        """Accept, decline, or complete a referral."""
        conn = _get_db()
        now = datetime.utcnow().isoformat()
        conn.execute(
            "UPDATE ilf_referrals SET status = ?, responded_at = ?, notes = ? WHERE referral_id = ?",
            (new_status, now, notes, referral_id),
        )
        conn.commit()
        conn.close()

    def list_referrals(self, lawyer_id: str = None, claim_id: str = None, status_filter: str = None) -> List[Dict[str, Any]]:
        """List referrals with optional filters."""
        conn = _get_db()
        query = "SELECT * FROM ilf_referrals WHERE 1=1"
        params: List[Any] = []
        if lawyer_id:
            query += " AND lawyer_id = ?"
            params.append(lawyer_id)
        if claim_id:
            query += " AND claim_id = ?"
            params.append(claim_id)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        query += " ORDER BY referred_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_referral(self, referral_id: str) -> Optional[Dict[str, Any]]:
        """Get a single referral by ID."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM ilf_referrals WHERE referral_id = ?", (referral_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_ilf_stats(self) -> Dict[str, Any]:
        """Aggregate ILF network statistics."""
        conn = _get_db()
        lawyers_total = conn.execute("SELECT COUNT(*) FROM ilf_lawyers").fetchone()[0]
        lawyers_active = conn.execute("SELECT COUNT(*) FROM ilf_lawyers WHERE status = 'active'").fetchone()[0]
        referrals_total = conn.execute("SELECT COUNT(*) FROM ilf_referrals").fetchone()[0]
        referrals_pending = conn.execute("SELECT COUNT(*) FROM ilf_referrals WHERE status = 'pending'").fetchone()[0]
        referrals_accepted = conn.execute("SELECT COUNT(*) FROM ilf_referrals WHERE status = 'accepted'").fetchone()[0]
        referrals_declined = conn.execute("SELECT COUNT(*) FROM ilf_referrals WHERE status = 'declined'").fetchone()[0]
        referrals_completed = conn.execute("SELECT COUNT(*) FROM ilf_referrals WHERE status = 'completed'").fetchone()[0]
        conn.close()
        return {
            "lawyers_total": lawyers_total,
            "lawyers_active": lawyers_active,
            "referrals_total": referrals_total,
            "referrals_pending": referrals_pending,
            "referrals_accepted": referrals_accepted,
            "referrals_declined": referrals_declined,
            "referrals_completed": referrals_completed,
        }


    def transition_claim(self, claim_id, new_status, actor="system", reason=""):
        claim=self.get_claim(claim_id)
        if not claim: return None
        old=claim.get("status","filed"); allowed=VALID_STATUS_TRANSITIONS.get(old,set())
        if new_status not in allowed: return {"error":f"Cannot transition {old} to {new_status}"}
        conn=_get_db(); now=datetime.utcnow().isoformat()
        conn.execute("UPDATE claims SET status=? WHERE claim_id=?",(new_status,claim_id))
        conn.execute("INSERT INTO transitions (claim_id,from_status,to_status,changed_by,reason,changed_at) VALUES (?,?,?,?,?,?)",(claim_id,old,new_status,actor,reason,now))
        conn.commit(); conn.close()
        self.audit("claim.status_changed",{"claim_id":claim_id,"from":old,"to":new_status},actor=actor)
        return {"claim_id":claim_id,"old_status":old,"new_status":new_status}

    def score_litmus(self, claim_id, scores=None):
        claim=self.get_claim(claim_id)
        if not claim: return None
        import uuid as _u
        sid=f"lms_{_u.uuid4().hex[:12]}"; now=datetime.utcnow().isoformat()
        if scores is None: scores=self._auto_litmus(claim)
        composite=round(sum([scores.get(k,0)*0.167 for k in ["l_score","i_score","t_score","m_score","u_score","s_score"]]),3)
        passes=composite>=0.6
        action="auto_escalate" if composite>=0.8 else "flag_review" if composite>=0.6 else "human_review" if composite>=0.4 else "monitor"
        conn=_get_db()
        conn.execute("INSERT INTO litmus_scores (score_id,claim_id,l_score,l_reasoning,l_flags,i_score,i_reasoning,i_flags,t_score,t_reasoning,t_flags,m_score,m_reasoning,m_flags,u_score,u_reasoning,u_flags,s_score,s_reasoning,s_flags,composite_score,pass_threshold,action_level,scored_at,scored_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(sid,claim_id,scores.get("l_score",0),scores.get("l_reasoning",""),json.dumps(scores.get("l_flags",[])),scores.get("i_score",0),scores.get("i_reasoning",""),json.dumps(scores.get("i_flags",[])),scores.get("t_score",0),scores.get("t_reasoning",""),json.dumps(scores.get("t_flags",[])),scores.get("m_score",0),scores.get("m_reasoning",""),json.dumps(scores.get("m_flags",[])),scores.get("u_score",0),scores.get("u_reasoning",""),json.dumps(scores.get("u_flags",[])),scores.get("s_score",0),scores.get("s_reasoning",""),json.dumps(scores.get("s_flags",[])),composite,1 if passes else 0,action,now,scores.get("scored_by","system")))
        conn.commit(); conn.close()
        self.audit("litmus.scored",{"score_id":sid,"claim_id":claim_id,"composite":composite,"action_level":action})
        return {"score_id":sid,"claim_id":claim_id,"composite_score":composite,"passes":passes,"action_level":action,"scored_at":now}

    def _auto_litmus(self, claim):
        harm=claim.get("harm_type","other"); amt=claim.get("amount_claimed_usd",0); ev=claim.get("evidence",[]); sup=claim.get("contacted_support","")
        s={}; real={"payout_withholding","wage_theft","contract_breach","account_freeze"}
        s["l_score"],s["l_reasoning"],s["l_flags"]=(0.9,f"Real obligation: {harm}",["real_obligation"]) if harm in real else (0.6,f"Moderate: {harm}",[])
        s["i_score"],s["i_reasoning"],s["i_flags"]=0.8,"Independent of speculation",["stable_settlement"]
        he=sup and "no_resolution" in str(sup).lower().replace(" ","_")
        s["t_score"],s["t_reasoning"],s["t_flags"]=(0.85,"Prior attempts made",["adversarial_ready"]) if he else (0.65,"Escalation available",["escalation_available"])
        ec=len(ev) if isinstance(ev,list) else 0
        s["m_score"],s["m_reasoning"],s["m_flags"]=(0.9,f"{ec} evidence items",["execution_verified"]) if ec>=3 else (0.6,f"{ec} items",["partial_records"]) if ec>=1 else (0.3,"No evidence",["promises_only"])
        s["u_score"],s["u_reasoning"],s["u_flags"]=0.75,"Persistent DB with audit trail",["audit_trail"]
        s["s_score"],s["s_reasoning"],s["s_flags"]=(0.85,f"${amt:,.0f} significant",["manual_required"]) if amt>=5000 else (0.7,f"${amt:,.0f} moderate",["manual_required"]) if amt>=500 else (0.5,f"${amt:,.0f} micro",["partial_recovery"])
        return s

    def get_litmus_score(self, claim_id):
        conn=_get_db(); row=conn.execute("SELECT * FROM litmus_scores WHERE claim_id=? ORDER BY scored_at DESC LIMIT 1",(claim_id,)).fetchone(); conn.close()
        if not row: return None
        d=dict(row)
        for k in ["l_flags","i_flags","t_flags","m_flags","u_flags","s_flags"]: d[k]=json.loads(d.get(k,"[]"))
        return d

    def get_litmus_stats(self):
        conn=_get_db(); t=conn.execute("SELECT COUNT(*) FROM litmus_scores").fetchone()[0]; a=conn.execute("SELECT AVG(composite_score) FROM litmus_scores").fetchone()[0] or 0; p=conn.execute("SELECT COUNT(*) FROM litmus_scores WHERE pass_threshold=1").fetchone()[0]
        ba={r[0]:r[1] for r in conn.execute("SELECT action_level,COUNT(*) FROM litmus_scores GROUP BY action_level").fetchall()}; conn.close()
        return {"total_scored":t,"avg_composite":round(a,3),"passing_claims":p,"pass_rate_pct":round(p/t*100,1) if t else 0,"by_action_level":ba}

    def auto_route_claim(self, claim_id):
        claim=self.get_claim(claim_id)
        if not claim: return {"error":"Claim not found","matches":[]}
        cl=claim.get("classification",{}); vb=cl.get("value_band","unknown"); dt=cl.get("dispute_type","other"); jur=cl.get("jurisdictional_scope","US-General"); amt=claim.get("amount_claimed_usd",0); ht=cl.get("requires_human_triage",False)
        lawyers=self.list_lawyers(status_filter="active")
        if not lawyers: return {"claim_id":claim_id,"matches":[],"reason":"No active lawyers"}
        cands=[]
        for law in lawyers:
            sc=0; reasons=[]
            lj=law.get("jurisdiction","US-General")
            if lj==jur: sc+=30; reasons.append("exact_jurisdiction")
            elif "General" in lj or "General" in jur: sc+=15; reasons.append("general_jurisdiction")
            specs=law.get("specializations",[]); specs=json.loads(specs) if isinstance(specs,str) else specs
            sl=[s.lower() for s in specs]
            if dt.lower().replace("_"," ") in " ".join(sl): sc+=30; reasons.append("specialty_match")
            elif any(s in sl for s in ["general","payment recovery"]): sc+=10; reasons.append("general_practice")
            cur=self.get_lawyer_caseload(law["lawyer_id"]); mx=law.get("max_caseload",10)
            if mx>0:
                u=cur/mx
                if u<0.5: sc+=20; reasons.append("low_caseload")
                elif u<0.8: sc+=10; reasons.append("moderate_caseload")
            sc+=10
            if law.get("verification_status")=="verified": sc+=10; reasons.append("verified")
            cands.append({"lawyer_id":law["lawyer_id"],"name":law["full_name"],"jurisdiction":lj,"match_score":sc,"match_reasons":reasons})
        cands.sort(key=lambda x:x["match_score"],reverse=True); top=cands[:5]
        return {"claim_id":claim_id,"respondent":claim.get("respondent_entity","Unknown"),"amount":amt,"value_band":vb,"matches":top,"total_candidates":len(cands),"recommendation":top[0]["lawyer_id"] if top and top[0]["match_score"]>=40 else None}

    @staticmethod
    def mask_pii(claim, level="standard"):
        m=dict(claim)
        if level=="full": return m
        email=m.get("claimant_email","")
        if email and "@" in email:
            lo,do=email.split("@",1); m["claimant_email"]=f"{lo[:2]}***@{do}" if len(lo)>2 else f"***@{do}"
        name=m.get("claimant_name","")
        if name and " " in name: parts=name.split(); m["claimant_name"]=f"{parts[0]} {parts[-1][0]}."
        elif name: m["claimant_name"]=f"{name[0]}."
        if level=="redacted": m.pop("claimant_email",None); m.pop("claimant_phone",None)
        return m

    # ── Outreach Templates & Communication Log ──

    def list_templates(self) -> List[Dict[str, Any]]:
        conn = _get_db()
        rows = conn.execute("SELECT * FROM outreach_templates ORDER BY category, name").fetchall()
        conn.close()
        return [
            {
                "template_id": r["template_id"],
                "name": r["name"],
                "category": r["category"],
                "subject": r["subject"],
                "body": r["body"],
                "variables": json.loads(r["variables"]) if r["variables"] else [],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        conn = _get_db()
        r = conn.execute("SELECT * FROM outreach_templates WHERE template_id = ?", (template_id,)).fetchone()
        conn.close()
        if not r:
            return None
        return {
            "template_id": r["template_id"],
            "name": r["name"],
            "category": r["category"],
            "subject": r["subject"],
            "body": r["body"],
            "variables": json.loads(r["variables"]) if r["variables"] else [],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def save_template(self, template_id: str, name: str, category: str, subject: str, body: str, variables: List[str]) -> Dict[str, Any]:
        conn = _get_db()
        now_str = datetime.utcnow().isoformat() + "Z"
        existing = conn.execute("SELECT template_id FROM outreach_templates WHERE template_id = ?", (template_id,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE outreach_templates SET name=?, category=?, subject=?, body=?, variables=?, updated_at=? WHERE template_id=?",
                (name, category, subject, body, json.dumps(variables), now_str, template_id),
            )
        else:
            conn.execute(
                "INSERT INTO outreach_templates (template_id, name, category, subject, body, variables, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (template_id, name, category, subject, body, json.dumps(variables), now_str, now_str),
            )
        conn.commit()
        conn.close()
        return self.get_template(template_id)

    def delete_template(self, template_id: str) -> bool:
        conn = _get_db()
        r = conn.execute("DELETE FROM outreach_templates WHERE template_id = ?", (template_id,))
        conn.commit()
        conn.close()
        return r.rowcount > 0

    def render_template(self, template_id: str, claim_id: str) -> Optional[Dict[str, str]]:
        """Render a template with claim data, returning filled subject + body."""
        tpl = self.get_template(template_id)
        if not tpl:
            return None
        claim = self.get_claim(claim_id)
        if not claim:
            return None

        # Gather outreach history for this claim
        conn = _get_db()
        outreach_rows = conn.execute(
            "SELECT * FROM outreach_log WHERE claim_id = ? ORDER BY created_at DESC", (claim_id,)
        ).fetchall()
        conn.close()

        now = datetime.utcnow()
        filed_str = claim.get("filed_at", "")
        days_active = 0
        if filed_str:
            try:
                filed_dt = datetime.fromisoformat(filed_str.replace("Z", "").replace("+00:00", ""))
                days_active = (now - filed_dt).days
            except (ValueError, TypeError):
                pass

        last_outreach_date = "N/A"
        if outreach_rows:
            last_outreach_date = (outreach_rows[0]["sent_at"] or outreach_rows[0]["created_at"] or "N/A")[:10]

        # Recovery data
        recoveries = self.get_claim_recoveries(claim_id)
        total_recovered = sum(r.get("amount_recovered", 0) for r in recoveries)

        # Build variable context
        ctx = {
            "claim_id": claim_id[:16],
            "claimant_name": claim.get("claimant_name", "Claimant"),
            "claimant_email": claim.get("claimant_email", ""),
            "respondent": claim.get("respondent_entity", "Unknown"),
            "amount": f"{claim.get('amount_claimed_usd', 0):,.2f}",
            "filed_date": filed_str[:10] if filed_str else "N/A",
            "harm_type": (claim.get("harm_type", "dispute")).replace("_", " ").title(),
            "status": (claim.get("status", "filed")).replace("_", " ").title(),
            "days_active": str(days_active),
            "outreach_count": str(len(outreach_rows)),
            "last_outreach_date": last_outreach_date,
            "amount_recovered": f"{total_recovered:,.2f}",
            "recovery_method": "Direct Resolution",
            "resolution_date": now.strftime("%Y-%m-%d"),
            "status_message": "Your claim is being actively processed by our team.",
        }

        subject = tpl["subject"]
        body = tpl["body"]
        for key, val in ctx.items():
            subject = subject.replace("{" + key + "}", val)
            body = body.replace("{" + key + "}", val)

        return {"subject": subject, "body": body, "template_id": template_id, "claim_id": claim_id}

    def log_outreach(self, claim_id: str, template_id: Optional[str], channel: str, recipient: str, subject: str, body: str, status: str = "drafted") -> str:
        conn = _get_db()
        outreach_id = f"out_{uuid.uuid4().hex[:12]}"
        now_str = datetime.utcnow().isoformat() + "Z"
        sent_at = now_str if status == "sent" else None
        conn.execute(
            "INSERT INTO outreach_log (outreach_id, claim_id, template_id, channel, recipient, subject, body, status, sent_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (outreach_id, claim_id, template_id, channel, recipient, subject, body, status, sent_at, now_str),
        )
        conn.commit()
        conn.close()
        return outreach_id

    def get_claim_outreach(self, claim_id: str) -> List[Dict[str, Any]]:
        conn = _get_db()
        rows = conn.execute("SELECT * FROM outreach_log WHERE claim_id = ? ORDER BY created_at DESC", (claim_id,)).fetchall()
        conn.close()
        return [
            {
                "outreach_id": r["outreach_id"],
                "claim_id": r["claim_id"],
                "template_id": r["template_id"],
                "channel": r["channel"],
                "recipient": r["recipient"],
                "subject": r["subject"],
                "body": r["body"],
                "status": r["status"],
                "sent_at": r["sent_at"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def update_outreach_status(self, outreach_id: str, new_status: str) -> bool:
        conn = _get_db()
        now_str = datetime.utcnow().isoformat() + "Z"
        sent_at_update = now_str if new_status == "sent" else None
        if sent_at_update:
            r = conn.execute(
                "UPDATE outreach_log SET status=?, sent_at=? WHERE outreach_id=?",
                (new_status, sent_at_update, outreach_id),
            )
        else:
            r = conn.execute(
                "UPDATE outreach_log SET status=? WHERE outreach_id=?",
                (new_status, outreach_id),
            )
        conn.commit()
        conn.close()
        return r.rowcount > 0

    def get_outreach_stats(self) -> Dict[str, Any]:
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM outreach_log").fetchone()[0]
        sent = conn.execute("SELECT COUNT(*) FROM outreach_log WHERE status = 'sent'").fetchone()[0]
        drafted = conn.execute("SELECT COUNT(*) FROM outreach_log WHERE status = 'drafted'").fetchone()[0]
        by_channel = {}
        for row in conn.execute("SELECT channel, COUNT(*) as cnt FROM outreach_log GROUP BY channel").fetchall():
            by_channel[row["channel"]] = row["cnt"]
        by_template = {}
        for row in conn.execute("SELECT template_id, COUNT(*) as cnt FROM outreach_log WHERE template_id IS NOT NULL GROUP BY template_id").fetchall():
            by_template[row["template_id"]] = row["cnt"]
        # Recent outreach
        recent = conn.execute("SELECT * FROM outreach_log ORDER BY created_at DESC LIMIT 10").fetchall()
        conn.close()
        return {
            "total": total,
            "sent": sent,
            "drafted": drafted,
            "by_channel": by_channel,
            "by_template": by_template,
            "recent": [
                {
                    "outreach_id": r["outreach_id"],
                    "claim_id": r["claim_id"],
                    "channel": r["channel"],
                    "subject": r["subject"],
                    "status": r["status"],
                    "created_at": r["created_at"],
                }
                for r in recent
            ],
        }

    # ── Operators & Case Assignment ──

    def list_operators(self) -> List[Dict[str, Any]]:
        conn = _get_db()
        rows = conn.execute("SELECT * FROM operators ORDER BY role, name").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_operator(self, operator_id: str) -> Optional[Dict[str, Any]]:
        conn = _get_db()
        r = conn.execute("SELECT * FROM operators WHERE operator_id = ?", (operator_id,)).fetchone()
        conn.close()
        return dict(r) if r else None

    def save_operator(self, operator_id: str, name: str, email: str, role: str, max_caseload: int) -> Dict[str, Any]:
        conn = _get_db()
        now_str = datetime.utcnow().isoformat() + "Z"
        existing = conn.execute("SELECT operator_id FROM operators WHERE operator_id = ?", (operator_id,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE operators SET name=?, email=?, role=?, max_caseload=? WHERE operator_id=?",
                (name, email, role, max_caseload, operator_id),
            )
        else:
            conn.execute(
                "INSERT INTO operators (operator_id, name, email, role, status, max_caseload, created_at) VALUES (?,?,?,?,?,?,?)",
                (operator_id, name, email, role, "active", max_caseload, now_str),
            )
        conn.commit()
        conn.close()
        return self.get_operator(operator_id)

    def delete_operator(self, operator_id: str) -> bool:
        conn = _get_db()
        # Unassign all their claims first
        conn.execute("DELETE FROM assignments WHERE operator_id = ?", (operator_id,))
        r = conn.execute("DELETE FROM operators WHERE operator_id = ?", (operator_id,))
        conn.commit()
        conn.close()
        return r.rowcount > 0

    def assign_claim(self, claim_id: str, operator_id: str, assigned_by: str = "operator") -> Dict[str, Any]:
        conn = _get_db()
        now_str = datetime.utcnow().isoformat() + "Z"
        # Upsert assignment
        conn.execute("DELETE FROM assignments WHERE claim_id = ?", (claim_id,))
        conn.execute(
            "INSERT INTO assignments (claim_id, operator_id, assigned_at, assigned_by) VALUES (?,?,?,?)",
            (claim_id, operator_id, now_str, assigned_by),
        )
        conn.commit()
        conn.close()
        return {"claim_id": claim_id, "operator_id": operator_id, "assigned_at": now_str}

    def unassign_claim(self, claim_id: str) -> bool:
        conn = _get_db()
        r = conn.execute("DELETE FROM assignments WHERE claim_id = ?", (claim_id,))
        conn.commit()
        conn.close()
        return r.rowcount > 0

    def bulk_assign(self, claim_ids: List[str], operator_id: str, assigned_by: str = "operator") -> Dict[str, Any]:
        conn = _get_db()
        now_str = datetime.utcnow().isoformat() + "Z"
        assigned = 0
        for cid in claim_ids:
            conn.execute("DELETE FROM assignments WHERE claim_id = ?", (cid,))
            conn.execute(
                "INSERT INTO assignments (claim_id, operator_id, assigned_at, assigned_by) VALUES (?,?,?,?)",
                (cid, operator_id, now_str, assigned_by),
            )
            assigned += 1
        conn.commit()
        conn.close()
        return {"assigned": assigned, "operator_id": operator_id}

    def get_assignment(self, claim_id: str) -> Optional[Dict[str, Any]]:
        conn = _get_db()
        r = conn.execute(
            "SELECT a.*, o.name as operator_name FROM assignments a JOIN operators o ON a.operator_id = o.operator_id WHERE a.claim_id = ?",
            (claim_id,),
        ).fetchone()
        conn.close()
        return dict(r) if r else None

    def get_workload_stats(self) -> Dict[str, Any]:
        conn = _get_db()
        operators = conn.execute("SELECT * FROM operators WHERE status = 'active' ORDER BY name").fetchall()
        assignments = conn.execute(
            "SELECT a.operator_id, COUNT(*) as cnt FROM assignments a GROUP BY a.operator_id"
        ).fetchall()
        assignment_map = {r["operator_id"]: r["cnt"] for r in assignments}
        total_assigned = sum(assignment_map.values())
        total_claims = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        unassigned = total_claims - total_assigned
        conn.close()

        workloads = []
        for op in operators:
            oid = op["operator_id"]
            current = assignment_map.get(oid, 0)
            capacity = op["max_caseload"]
            utilization = round((current / capacity * 100), 1) if capacity > 0 else 0
            workloads.append({
                "operator_id": oid,
                "name": op["name"],
                "role": op["role"],
                "current_cases": current,
                "max_caseload": capacity,
                "utilization_pct": utilization,
                "available_capacity": max(0, capacity - current),
                "status": "overloaded" if current > capacity else ("high" if utilization >= 80 else ("moderate" if utilization >= 50 else "available")),
            })

        # Auto-assign recommendation: find operator with most capacity
        workloads.sort(key=lambda w: w["available_capacity"], reverse=True)
        recommended = workloads[0]["operator_id"] if workloads else None

        return {
            "total_claims": total_claims,
            "total_assigned": total_assigned,
            "unassigned": unassigned,
            "assignment_rate": round((total_assigned / total_claims * 100), 1) if total_claims > 0 else 0,
            "workloads": workloads,
            "recommended_assignee": recommended,
        }

    def auto_assign(self, claim_id: str) -> Optional[Dict[str, Any]]:
        """Auto-assign a claim to the operator with most available capacity."""
        stats = self.get_workload_stats()
        workloads = stats.get("workloads", [])
        # Find operator with most available capacity
        available = [w for w in workloads if w["available_capacity"] > 0]
        if not available:
            return None
        best = max(available, key=lambda w: w["available_capacity"])
        return self.assign_claim(claim_id, best["operator_id"], assigned_by="auto")

    # ── Settlement & Resolution Methods ──

    def create_settlement_offer(self, claim_id: str, offer_type: str, offered_by: str,
                                 amount_offered: float, terms: str = "",
                                 response_deadline: str = None) -> Dict[str, Any]:
        """Create a settlement offer or counteroffer for a claim."""
        sid = f"stl_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        conn.execute(
            """INSERT INTO settlements
               (settlement_id, claim_id, offer_type, offered_by, amount_offered, terms, status, response_deadline, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (sid, claim_id, offer_type, offered_by, amount_offered, terms, "pending", response_deadline, now, now),
        )
        conn.commit()
        conn.close()
        return {
            "settlement_id": sid, "claim_id": claim_id, "offer_type": offer_type,
            "offered_by": offered_by, "amount_offered": amount_offered, "terms": terms,
            "status": "pending", "response_deadline": response_deadline,
            "created_at": now, "updated_at": now,
        }

    def get_claim_settlements(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get all settlement offers/counteroffers for a claim, newest first."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM settlements WHERE claim_id = ? ORDER BY created_at DESC", (claim_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_settlement(self, settlement_id: str) -> Optional[Dict[str, Any]]:
        """Get a single settlement by ID."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM settlements WHERE settlement_id = ?", (settlement_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def update_settlement_status(self, settlement_id: str, new_status: str, resolved_at: str = None) -> Optional[Dict[str, Any]]:
        """Update a settlement's status (pending → accepted/rejected/expired/withdrawn)."""
        conn = _get_db()
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "UPDATE settlements SET status = ?, updated_at = ?, resolved_at = COALESCE(?, resolved_at) WHERE settlement_id = ?",
            (new_status, now, resolved_at or (now if new_status in ("accepted", "rejected") else None), settlement_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM settlements WHERE settlement_id = ?", (settlement_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def create_resolution(self, claim_id: str, settlement_id: str = None,
                          resolution_type: str = "full_settlement",
                          amount_settled: float = 0, amount_claimed: float = 0,
                          terms_summary: str = "", resolution_notes: str = "") -> Dict[str, Any]:
        """Record a final resolution for a claim."""
        rid = f"res_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        ratio = round(amount_settled / amount_claimed, 4) if amount_claimed > 0 else 0
        conn = _get_db()
        conn.execute(
            """INSERT OR REPLACE INTO resolutions
               (resolution_id, claim_id, settlement_id, resolution_type, amount_settled,
                amount_claimed, settlement_ratio, terms_summary, resolution_notes, resolved_at, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, claim_id, settlement_id, resolution_type, amount_settled,
             amount_claimed, ratio, terms_summary, resolution_notes, now, now),
        )
        conn.commit()
        conn.close()
        return {
            "resolution_id": rid, "claim_id": claim_id, "settlement_id": settlement_id,
            "resolution_type": resolution_type, "amount_settled": amount_settled,
            "amount_claimed": amount_claimed, "settlement_ratio": ratio,
            "terms_summary": terms_summary, "resolution_notes": resolution_notes,
            "resolved_at": now, "created_at": now,
        }

    def get_resolution(self, claim_id: str) -> Optional[Dict[str, Any]]:
        """Get the resolution record for a claim."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM resolutions WHERE claim_id = ?", (claim_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_resolution_dashboard(self) -> Dict[str, Any]:
        """Aggregate resolution statistics across all claims."""
        conn = _get_db()
        # Total resolved
        total = conn.execute("SELECT COUNT(*) as c FROM resolutions").fetchone()["c"]
        # By type
        by_type = {}
        for row in conn.execute("SELECT resolution_type, COUNT(*) as c, SUM(amount_settled) as total_settled, AVG(settlement_ratio) as avg_ratio FROM resolutions GROUP BY resolution_type").fetchall():
            by_type[row["resolution_type"]] = {
                "count": row["c"],
                "total_settled": round(row["total_settled"] or 0, 2),
                "avg_ratio": round(row["avg_ratio"] or 0, 4),
            }
        # Overall stats
        agg = conn.execute("SELECT SUM(amount_settled) as ts, SUM(amount_claimed) as tc, AVG(settlement_ratio) as ar FROM resolutions").fetchone()
        total_settled = round(agg["ts"] or 0, 2)
        total_claimed = round(agg["tc"] or 0, 2)
        avg_ratio = round(agg["ar"] or 0, 4)
        # Recent resolutions
        recent = []
        for row in conn.execute("SELECT r.*, c.data FROM resolutions r LEFT JOIN claims c ON r.claim_id = c.claim_id ORDER BY r.resolved_at DESC LIMIT 10").fetchall():
            entry = dict(row)
            if entry.get("data"):
                claim_data = json.loads(entry["data"]) if isinstance(entry["data"], str) else entry["data"]
                entry["respondent"] = claim_data.get("respondent_entity", "Unknown")
                entry["claimant_name"] = claim_data.get("claimant_name", "Unknown")
            del entry["data"]
            recent.append(entry)
        # Pending settlements count
        pending = conn.execute("SELECT COUNT(*) as c FROM settlements WHERE status = 'pending'").fetchone()["c"]
        conn.close()
        return {
            "total_resolved": total,
            "total_settled_usd": total_settled,
            "total_claimed_usd": total_claimed,
            "overall_ratio": avg_ratio,
            "pending_offers": pending,
            "by_type": by_type,
            "recent": recent,
        }

    # ── Workflow Rules Engine Methods ──

    def list_workflow_rules(self) -> List[Dict[str, Any]]:
        conn = _get_db()
        rows = conn.execute("SELECT * FROM workflow_rules ORDER BY priority ASC").fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["conditions"] = json.loads(d["conditions"]) if isinstance(d["conditions"], str) else d["conditions"]
            d["actions"] = json.loads(d["actions"]) if isinstance(d["actions"], str) else d["actions"]
            d["enabled"] = bool(d["enabled"])
            result.append(d)
        return result

    def get_workflow_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        conn = _get_db()
        row = conn.execute("SELECT * FROM workflow_rules WHERE rule_id = ?", (rule_id,)).fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["conditions"] = json.loads(d["conditions"]) if isinstance(d["conditions"], str) else d["conditions"]
        d["actions"] = json.loads(d["actions"]) if isinstance(d["actions"], str) else d["actions"]
        d["enabled"] = bool(d["enabled"])
        return d

    def save_workflow_rule(self, rule_id: str = None, name: str = "", description: str = "",
                           trigger_event: str = "claim.filed", conditions: Dict = None,
                           actions: List = None, enabled: bool = True, priority: int = 50) -> Dict[str, Any]:
        rid = rule_id or f"wfr_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        conn.execute(
            """INSERT OR REPLACE INTO workflow_rules
               (rule_id, name, description, trigger_event, conditions, actions, enabled, priority, execution_count, last_executed, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT execution_count FROM workflow_rules WHERE rule_id = ?), 0),
                       (SELECT last_executed FROM workflow_rules WHERE rule_id = ?), COALESCE((SELECT created_at FROM workflow_rules WHERE rule_id = ?), ?))""",
            (rid, name, description, trigger_event, json.dumps(conditions or {}), json.dumps(actions or []),
             1 if enabled else 0, priority, rid, rid, rid, now),
        )
        conn.commit()
        conn.close()
        return self.get_workflow_rule(rid)

    def toggle_workflow_rule(self, rule_id: str, enabled: bool) -> Optional[Dict[str, Any]]:
        conn = _get_db()
        conn.execute("UPDATE workflow_rules SET enabled = ? WHERE rule_id = ?", (1 if enabled else 0, rule_id))
        conn.commit()
        conn.close()
        return self.get_workflow_rule(rule_id)

    def delete_workflow_rule(self, rule_id: str) -> bool:
        conn = _get_db()
        cur = conn.execute("DELETE FROM workflow_rules WHERE rule_id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def log_workflow_execution(self, rule_id: str, claim_id: str, trigger_event: str,
                                actions_taken: List[Dict], status: str = "success") -> Dict[str, Any]:
        eid = f"wfx_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        conn.execute(
            "INSERT INTO workflow_executions (execution_id, rule_id, claim_id, trigger_event, actions_taken, status, executed_at) VALUES (?,?,?,?,?,?,?)",
            (eid, rule_id, claim_id, trigger_event, json.dumps(actions_taken), status, now),
        )
        conn.execute("UPDATE workflow_rules SET execution_count = execution_count + 1, last_executed = ? WHERE rule_id = ?", (now, rule_id))
        conn.commit()
        conn.close()
        return {"execution_id": eid, "rule_id": rule_id, "claim_id": claim_id, "status": status, "executed_at": now}

    def get_workflow_executions(self, rule_id: str = None, claim_id: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        conn = _get_db()
        q = "SELECT e.*, r.name as rule_name FROM workflow_executions e LEFT JOIN workflow_rules r ON e.rule_id = r.rule_id WHERE 1=1"
        params = []
        if rule_id:
            q += " AND e.rule_id = ?"
            params.append(rule_id)
        if claim_id:
            q += " AND e.claim_id = ?"
            params.append(claim_id)
        q += " ORDER BY e.executed_at DESC LIMIT ?"
        params.append(min(limit, 200))
        rows = conn.execute(q, params).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["actions_taken"] = json.loads(d["actions_taken"]) if isinstance(d["actions_taken"], str) else d["actions_taken"]
            result.append(d)
        return result

    def evaluate_workflow_rules(self, trigger_event: str, claim_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate all enabled rules for a given trigger event against claim data. Returns list of actions to execute."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM workflow_rules WHERE trigger_event = ? AND enabled = 1 ORDER BY priority ASC",
            (trigger_event,)
        ).fetchall()
        conn.close()

        claim_id = claim_data.get("claim_id", "")
        results = []

        for row in rows:
            rule = dict(row)
            rule["conditions"] = json.loads(rule["conditions"]) if isinstance(rule["conditions"], str) else rule["conditions"]
            rule["actions"] = json.loads(rule["actions"]) if isinstance(rule["actions"], str) else rule["actions"]
            conditions = rule["conditions"]

            # Evaluate conditions
            match = True

            # Amount threshold
            if "min_amount" in conditions:
                amount = claim_data.get("amount_claimed_usd", 0) or 0
                if amount < conditions["min_amount"]:
                    match = False

            # Status match
            if "status" in conditions and match:
                if claim_data.get("status") != conditions["status"]:
                    match = False

            # Days in current status
            if "min_days_in_status" in conditions and match:
                filed_at = claim_data.get("filed_at") or claim_data.get("timestamp")
                if filed_at:
                    try:
                        filed_dt = datetime.fromisoformat(filed_at.replace("Z", "+00:00").replace("+00:00", ""))
                        days = (datetime.utcnow() - filed_dt).days
                        if days < conditions["min_days_in_status"]:
                            match = False
                    except Exception:
                        match = False
                else:
                    match = False

            # Respondent claim count
            if "min_respondent_claims" in conditions and match:
                resp = claim_data.get("respondent_normalized_id") or claim_data.get("respondent_entity", "")
                conn2 = _get_db()
                count = conn2.execute(
                    "SELECT COUNT(*) as c FROM claims WHERE data LIKE ?", (f'%{resp}%',)
                ).fetchone()["c"]
                conn2.close()
                if count < conditions["min_respondent_claims"]:
                    match = False

            # Pending settlement days
            if "pending_settlement_days" in conditions and match:
                conn2 = _get_db()
                pending = conn2.execute(
                    "SELECT MIN(created_at) as oldest FROM settlements WHERE claim_id = ? AND status = 'pending'",
                    (claim_id,)
                ).fetchone()
                conn2.close()
                if pending and pending["oldest"]:
                    try:
                        oldest_dt = datetime.fromisoformat(pending["oldest"].replace("Z", ""))
                        days = (datetime.utcnow() - oldest_dt).days
                        if days < conditions["pending_settlement_days"]:
                            match = False
                    except Exception:
                        match = False
                else:
                    match = False

            if match:
                results.append({
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "actions": rule["actions"],
                    "priority": rule["priority"],
                })

        return results

    def execute_workflow_actions(self, rule_id: str, rule_name: str, claim_id: str,
                                  claim_data: Dict[str, Any], actions: List[Dict],
                                  trigger_event: str) -> Dict[str, Any]:
        """Execute the actions defined in a workflow rule for a specific claim."""
        actions_taken = []
        for action in actions:
            atype = action.get("type", "")
            try:
                if atype == "change_status":
                    target = action.get("target", "")
                    reason = action.get("reason", f"Automated by rule: {rule_name}")
                    if target and target != claim_data.get("status"):
                        self.update_claim_status(claim_id, target)
                        actions_taken.append({"type": "change_status", "target": target, "success": True})
                        self.audit("workflow.status_changed", {
                            "claim_id": claim_id, "rule_id": rule_id, "rule_name": rule_name,
                            "new_status": target, "reason": reason,
                        }, actor="system")

                elif atype == "auto_assign":
                    result = self.auto_assign(claim_id)
                    if result:
                        op = self.get_operator(result["operator_id"])
                        actions_taken.append({"type": "auto_assign", "operator_id": result["operator_id"],
                                              "operator_name": op["name"] if op else "?", "success": True})
                        self.audit("workflow.auto_assigned", {
                            "claim_id": claim_id, "rule_id": rule_id,
                            "operator_id": result["operator_id"],
                        }, actor="system")
                    else:
                        actions_taken.append({"type": "auto_assign", "success": False, "reason": "No available capacity"})

                elif atype == "add_note":
                    note_text = action.get("text", f"Automated note from rule: {rule_name}")
                    nid = f"note_{uuid.uuid4().hex[:12]}"
                    now = datetime.utcnow().isoformat() + "Z"
                    conn = _get_db()
                    conn.execute(
                        "INSERT INTO notes (note_id, claim_id, author, content, created_at) VALUES (?,?,?,?,?)",
                        (nid, claim_id, "System (Workflow)", note_text, now),
                    )
                    conn.commit()
                    conn.close()
                    actions_taken.append({"type": "add_note", "note_id": nid, "success": True})
                    self.audit("workflow.note_added", {
                        "claim_id": claim_id, "rule_id": rule_id, "note_id": nid,
                    }, actor="system")

                else:
                    actions_taken.append({"type": atype, "success": False, "reason": "Unknown action type"})

            except Exception as e:
                actions_taken.append({"type": atype, "success": False, "reason": str(e)})

        # Log execution
        self.log_workflow_execution(rule_id, claim_id, trigger_event, actions_taken)
        return {"rule_id": rule_id, "rule_name": rule_name, "claim_id": claim_id, "actions_taken": actions_taken}

    # ── Document / Evidence Management ──

    VALID_DOC_CATEGORIES = [
        "evidence", "correspondence", "screenshot", "receipt", "contract",
        "identification", "legal", "financial", "communication_log", "other",
    ]
    VALID_FILE_TYPES = [
        "pdf", "image", "document", "spreadsheet", "text", "email", "archive", "other",
    ]
    MIME_TO_FILE_TYPE = {
        "application/pdf": "pdf",
        "image/png": "image", "image/jpeg": "image", "image/gif": "image",
        "image/webp": "image", "image/svg+xml": "image", "image/bmp": "image",
        "application/msword": "document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document",
        "application/vnd.ms-excel": "spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "spreadsheet",
        "text/plain": "text", "text/csv": "text", "text/html": "text",
        "message/rfc822": "email", "application/zip": "archive",
    }

    def add_document(self, claim_id: str, filename: str, category: str = "evidence",
                     description: str = "", file_size_bytes: int = 0,
                     mime_type: str = "application/octet-stream",
                     content_b64: str = None, uploaded_by: str = "operator",
                     tags: List[str] = None, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Add a document/evidence record to a claim."""
        doc_id = f"doc_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"

        # Auto-detect file_type from mime
        file_type = self.MIME_TO_FILE_TYPE.get(mime_type, "other")
        # Fallback detection from filename extension
        if file_type == "other" and "." in filename:
            ext = filename.rsplit(".", 1)[-1].lower()
            ext_map = {"pdf": "pdf", "png": "image", "jpg": "image", "jpeg": "image",
                       "gif": "image", "webp": "image", "doc": "document", "docx": "document",
                       "xls": "spreadsheet", "xlsx": "spreadsheet", "csv": "text",
                       "txt": "text", "eml": "email", "zip": "archive", "rar": "archive"}
            file_type = ext_map.get(ext, "other")

        # Validate category
        if category not in self.VALID_DOC_CATEGORIES:
            category = "other"

        # Compute hash if content provided
        hash_sha256 = ""
        if content_b64:
            import base64
            try:
                raw = base64.b64decode(content_b64)
                hash_sha256 = hashlib.sha256(raw).hexdigest()
                if file_size_bytes == 0:
                    file_size_bytes = len(raw)
            except Exception:
                hash_sha256 = hashlib.sha256(content_b64.encode()).hexdigest()

        tags_json = json.dumps(tags or [])
        meta_json = json.dumps(metadata or {})

        conn = _get_db()
        conn.execute(
            """INSERT INTO documents
               (document_id, claim_id, filename, file_type, category, description,
                file_size_bytes, mime_type, storage_path, content_b64, hash_sha256,
                uploaded_by, tags, metadata, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (doc_id, claim_id, filename, file_type, category, description,
             file_size_bytes, mime_type, "", content_b64, hash_sha256,
             uploaded_by, tags_json, meta_json, now),
        )
        conn.commit()
        conn.close()

        self.audit("document.uploaded", {
            "document_id": doc_id, "claim_id": claim_id,
            "filename": filename, "file_type": file_type,
            "category": category, "file_size_bytes": file_size_bytes,
        }, actor=uploaded_by)

        return {
            "document_id": doc_id, "claim_id": claim_id, "filename": filename,
            "file_type": file_type, "category": category, "description": description,
            "file_size_bytes": file_size_bytes, "mime_type": mime_type,
            "hash_sha256": hash_sha256, "uploaded_by": uploaded_by,
            "tags": tags or [], "metadata": metadata or {},
            "created_at": now,
        }

    def get_claim_documents(self, claim_id: str, category: str = None,
                            file_type: str = None) -> List[Dict[str, Any]]:
        """Get all documents for a claim, optionally filtered by category or file type."""
        conn = _get_db()
        query = "SELECT * FROM documents WHERE claim_id = ?"
        params: List[Any] = [claim_id]
        if category:
            query += " AND category = ?"
            params.append(category)
        if file_type:
            query += " AND file_type = ?"
            params.append(file_type)
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            d["metadata"] = json.loads(d.get("metadata", "{}"))
            # Don't include content_b64 in list view (can be large)
            d.pop("content_b64", None)
            results.append(d)
        return results

    def get_document(self, document_id: str, include_content: bool = False) -> Optional[Dict[str, Any]]:
        """Get a single document by ID. Set include_content=True to include base64 data."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM documents WHERE document_id = ?", (document_id,)).fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["tags"] = json.loads(d.get("tags", "[]"))
        d["metadata"] = json.loads(d.get("metadata", "{}"))
        if not include_content:
            d.pop("content_b64", None)
        return d

    def update_document(self, document_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update document metadata (description, category, tags)."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM documents WHERE document_id = ?", (document_id,)).fetchone()
        if not row:
            conn.close()
            return None

        allowed_fields = {"description", "category", "tags", "metadata"}
        set_parts = []
        params = []
        for k, v in updates.items():
            if k in allowed_fields:
                if k == "tags":
                    v = json.dumps(v) if isinstance(v, list) else v
                elif k == "metadata":
                    v = json.dumps(v) if isinstance(v, dict) else v
                elif k == "category" and v not in self.VALID_DOC_CATEGORIES:
                    continue
                set_parts.append(f"{k} = ?")
                params.append(v)

        if not set_parts:
            conn.close()
            return dict(row)

        params.append(document_id)
        conn.execute(f"UPDATE documents SET {', '.join(set_parts)} WHERE document_id = ?", params)
        conn.commit()
        updated = conn.execute("SELECT * FROM documents WHERE document_id = ?", (document_id,)).fetchone()
        conn.close()
        d = dict(updated)
        d["tags"] = json.loads(d.get("tags", "[]"))
        d["metadata"] = json.loads(d.get("metadata", "{}"))
        d.pop("content_b64", None)
        return d

    def delete_document(self, document_id: str) -> bool:
        """Delete a document record."""
        conn = _get_db()
        row = conn.execute("SELECT claim_id, filename FROM documents WHERE document_id = ?", (document_id,)).fetchone()
        if not row:
            conn.close()
            return False
        conn.execute("DELETE FROM documents WHERE document_id = ?", (document_id,))
        conn.commit()
        conn.close()
        self.audit("document.deleted", {
            "document_id": document_id, "claim_id": row["claim_id"],
            "filename": row["filename"],
        }, actor="operator")
        return True

    def get_document_stats(self) -> Dict[str, Any]:
        """Get aggregate document statistics across all claims."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) as c FROM documents").fetchone()["c"]
        total_size = conn.execute("SELECT COALESCE(SUM(file_size_bytes), 0) as s FROM documents").fetchone()["s"]
        by_category = {}
        for row in conn.execute("SELECT category, COUNT(*) as c, SUM(file_size_bytes) as s FROM documents GROUP BY category").fetchall():
            by_category[row["category"]] = {"count": row["c"], "total_bytes": row["s"] or 0}
        by_type = {}
        for row in conn.execute("SELECT file_type, COUNT(*) as c FROM documents GROUP BY file_type").fetchall():
            by_type[row["file_type"]] = row["c"]
        claims_with_docs = conn.execute("SELECT COUNT(DISTINCT claim_id) as c FROM documents").fetchone()["c"]
        total_claims = conn.execute("SELECT COUNT(*) as c FROM claims").fetchone()["c"]
        recent = []
        for row in conn.execute("SELECT document_id, claim_id, filename, file_type, category, file_size_bytes, uploaded_by, created_at FROM documents ORDER BY created_at DESC LIMIT 10").fetchall():
            recent.append(dict(row))
        conn.close()
        return {
            "total_documents": total,
            "total_size_bytes": total_size,
            "total_size_human": _human_size(total_size),
            "claims_with_documents": claims_with_docs,
            "total_claims": total_claims,
            "coverage_pct": round(claims_with_docs / max(total_claims, 1) * 100, 1),
            "by_category": by_category,
            "by_file_type": by_type,
            "recent_uploads": recent,
        }

    def search_documents(self, query: str = "", claim_id: str = None,
                         category: str = None, file_type: str = None,
                         uploaded_by: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Search documents by filename, description, tags, or filters."""
        conn = _get_db()
        sql = "SELECT * FROM documents WHERE 1=1"
        params: List[Any] = []
        if claim_id:
            sql += " AND claim_id = ?"
            params.append(claim_id)
        if category:
            sql += " AND category = ?"
            params.append(category)
        if file_type:
            sql += " AND file_type = ?"
            params.append(file_type)
        if uploaded_by:
            sql += " AND uploaded_by = ?"
            params.append(uploaded_by)
        if query:
            sql += " AND (filename LIKE ? OR description LIKE ? OR tags LIKE ?)"
            q = f"%{query}%"
            params.extend([q, q, q])
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            d["metadata"] = json.loads(d.get("metadata", "{}"))
            d.pop("content_b64", None)
            results.append(d)
        return results

    # ── Notification Center ──

    NOTIF_TYPES = [
        "sla_breach", "sla_warning", "escalation", "settlement_deadline",
        "settlement_response", "workflow_triggered", "claim_filed",
        "status_changed", "document_uploaded", "assignment", "system",
    ]
    NOTIF_SEVERITIES = ["info", "warning", "critical"]

    def create_notification(self, ntype: str, severity: str, title: str,
                            message: str = "", claim_id: str = None,
                            source: str = "system", action_url: str = "",
                            action_label: str = "") -> Dict[str, Any]:
        """Create a notification entry."""
        nid = f"ntf_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        if severity not in self.NOTIF_SEVERITIES:
            severity = "info"
        conn = _get_db()
        conn.execute(
            """INSERT INTO notifications
               (notification_id, type, severity, title, message, claim_id,
                source, action_url, action_label, read, dismissed, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,0,0,?)""",
            (nid, ntype, severity, title, message, claim_id,
             source, action_url, action_label, now),
        )
        conn.commit()
        conn.close()
        return {
            "notification_id": nid, "type": ntype, "severity": severity,
            "title": title, "message": message, "claim_id": claim_id,
            "source": source, "action_url": action_url, "action_label": action_label,
            "read": False, "dismissed": False, "created_at": now,
        }

    def get_notifications(self, unread_only: bool = False, severity: str = None,
                          ntype: str = None, claim_id: str = None,
                          limit: int = 50) -> List[Dict[str, Any]]:
        """Get notifications with optional filters."""
        conn = _get_db()
        sql = "SELECT * FROM notifications WHERE dismissed = 0"
        params: List[Any] = []
        if unread_only:
            sql += " AND read = 0"
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if ntype:
            sql += " AND type = ?"
            params.append(ntype)
        if claim_id:
            sql += " AND claim_id = ?"
            params.append(claim_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [
            {**dict(r), "read": bool(r["read"]), "dismissed": bool(r["dismissed"])}
            for r in rows
        ]

    def get_notification_summary(self) -> Dict[str, Any]:
        """Get notification counts by severity and read status."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) as c FROM notifications WHERE dismissed = 0").fetchone()["c"]
        unread = conn.execute("SELECT COUNT(*) as c FROM notifications WHERE dismissed = 0 AND read = 0").fetchone()["c"]
        by_severity = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as c FROM notifications WHERE dismissed = 0 AND read = 0 GROUP BY severity"
        ).fetchall():
            by_severity[row["severity"]] = row["c"]
        by_type = {}
        for row in conn.execute(
            "SELECT type, COUNT(*) as c FROM notifications WHERE dismissed = 0 AND read = 0 GROUP BY type"
        ).fetchall():
            by_type[row["type"]] = row["c"]
        conn.close()
        return {
            "total": total,
            "unread": unread,
            "by_severity": by_severity,
            "by_type": by_type,
        }

    def mark_notification_read(self, notification_id: str) -> bool:
        """Mark a notification as read."""
        conn = _get_db()
        now = datetime.utcnow().isoformat() + "Z"
        cur = conn.execute(
            "UPDATE notifications SET read = 1, read_at = ? WHERE notification_id = ? AND read = 0",
            (now, notification_id),
        )
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def mark_all_notifications_read(self) -> int:
        """Mark all unread notifications as read. Returns count."""
        conn = _get_db()
        now = datetime.utcnow().isoformat() + "Z"
        cur = conn.execute("UPDATE notifications SET read = 1, read_at = ? WHERE read = 0", (now,))
        conn.commit()
        count = cur.rowcount
        conn.close()
        return count

    def dismiss_notification(self, notification_id: str) -> bool:
        """Dismiss a notification (soft delete)."""
        conn = _get_db()
        cur = conn.execute(
            "UPDATE notifications SET dismissed = 1 WHERE notification_id = ?",
            (notification_id,),
        )
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def dismiss_all_notifications(self) -> int:
        """Dismiss all notifications. Returns count."""
        conn = _get_db()
        cur = conn.execute("UPDATE notifications SET dismissed = 1 WHERE dismissed = 0")
        conn.commit()
        count = cur.rowcount
        conn.close()
        return count

    def generate_sla_notifications(self) -> List[Dict[str, Any]]:
        """Scan claims for SLA breaches/warnings and generate notifications."""
        generated = []
        conn = _get_db()
        claims = []
        for row in conn.execute("SELECT claim_id, data FROM claims").fetchall():
            d = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
            d["claim_id"] = row["claim_id"]
            claims.append(d)
        conn.close()

        for claim in claims:
            cid = claim.get("claim_id", "")
            status = claim.get("status", "")
            if status in ("resolved", "closed"):
                continue
            try:
                sla = self.check_sla_status(cid)
                if not sla or sla.get("sla_status") == "n/a":
                    continue
                days_rem = sla.get("days_remaining", 99)
                respondent = claim.get("respondent_entity", "Unknown")

                # Check for existing recent notification to avoid duplicates
                conn2 = _get_db()
                existing = conn2.execute(
                    "SELECT notification_id FROM notifications WHERE claim_id = ? AND type IN ('sla_breach','sla_warning') AND dismissed = 0 AND created_at > datetime('now', '-1 day')",
                    (cid,)
                ).fetchone()
                conn2.close()
                if existing:
                    continue

                if days_rem <= 0:
                    n = self.create_notification(
                        "sla_breach", "critical",
                        f"SLA Breached: {cid[:16]}",
                        f"Claim against {respondent} has exceeded its SLA deadline by {abs(round(days_rem,1))} days.",
                        claim_id=cid, source="sla_monitor",
                        action_label="View Claim",
                    )
                    generated.append(n)
                elif days_rem <= 2:
                    n = self.create_notification(
                        "sla_warning", "warning",
                        f"SLA At Risk: {cid[:16]}",
                        f"Claim against {respondent} has {round(days_rem,1)} days remaining before SLA breach.",
                        claim_id=cid, source="sla_monitor",
                        action_label="View Claim",
                    )
                    generated.append(n)
            except Exception:
                pass

        return generated

    def generate_settlement_deadline_notifications(self) -> List[Dict[str, Any]]:
        """Check for settlement offers approaching or past response deadline."""
        generated = []
        conn = _get_db()
        pending = conn.execute(
            "SELECT settlement_id, claim_id, offer_type, amount_offered, response_deadline, created_at FROM settlements WHERE status = 'pending'"
        ).fetchall()
        conn.close()

        now = datetime.utcnow()
        for s in pending:
            sid = s["settlement_id"]
            cid = s["claim_id"]
            deadline = s["response_deadline"]
            if not deadline:
                # Check age — if pending > 14 days with no deadline
                created = datetime.fromisoformat(s["created_at"].replace("Z", ""))
                age_days = (now - created).days
                if age_days >= 14:
                    conn2 = _get_db()
                    existing = conn2.execute(
                        "SELECT notification_id FROM notifications WHERE claim_id = ? AND type = 'settlement_deadline' AND dismissed = 0 AND created_at > datetime('now', '-3 day')",
                        (cid,)
                    ).fetchone()
                    conn2.close()
                    if not existing:
                        n = self.create_notification(
                            "settlement_deadline", "warning",
                            f"Settlement Pending {age_days}d: {cid[:16]}",
                            f"A ${s['amount_offered']:,.2f} {s['offer_type'].replace('_',' ')} has been pending for {age_days} days with no response.",
                            claim_id=cid, source="settlement_monitor",
                            action_label="Review Settlement",
                        )
                        generated.append(n)
                continue

            try:
                dl = datetime.fromisoformat(deadline.replace("Z", ""))
                days_left = (dl - now).total_seconds() / 86400

                conn2 = _get_db()
                existing = conn2.execute(
                    "SELECT notification_id FROM notifications WHERE claim_id = ? AND type = 'settlement_deadline' AND dismissed = 0 AND created_at > datetime('now', '-1 day')",
                    (cid,)
                ).fetchone()
                conn2.close()
                if existing:
                    continue

                if days_left <= 0:
                    n = self.create_notification(
                        "settlement_deadline", "critical",
                        f"Settlement Expired: {cid[:16]}",
                        f"${s['amount_offered']:,.2f} {s['offer_type'].replace('_',' ')} deadline has passed.",
                        claim_id=cid, source="settlement_monitor",
                        action_label="Review Settlement",
                    )
                    generated.append(n)
                elif days_left <= 3:
                    n = self.create_notification(
                        "settlement_deadline", "warning",
                        f"Settlement Deadline Soon: {cid[:16]}",
                        f"${s['amount_offered']:,.2f} offer expires in {round(days_left,1)} days.",
                        claim_id=cid, source="settlement_monitor",
                        action_label="Review Settlement",
                    )
                    generated.append(n)
            except Exception:
                pass

        return generated

    # ── Case Groups & Multi-Claim Linking ──

    VALID_GROUP_TYPES = ["respondent", "incident", "pattern", "class_action", "geographic", "custom"]
    VALID_GROUP_STATUSES = ["active", "monitoring", "coordinating", "resolved", "archived"]
    VALID_LINK_ROLES = ["lead", "member", "supporting", "related"]

    def create_case_group(self, name: str, group_type: str = "respondent",
                          description: str = "", respondent_key: str = None,
                          tags: List[str] = None, strategy_notes: str = "",
                          created_by: str = "operator") -> Dict[str, Any]:
        """Create a case group for linking related claims."""
        gid = f"grp_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        if group_type not in self.VALID_GROUP_TYPES:
            group_type = "custom"
        tags_json = json.dumps(tags or [])

        conn = _get_db()
        conn.execute(
            """INSERT INTO case_groups
               (group_id, name, description, group_type, status, respondent_key,
                tags, strategy_notes, created_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (gid, name, description, group_type, "active", respondent_key,
             tags_json, strategy_notes, created_by, now, now),
        )
        conn.commit()
        conn.close()

        self.audit("case_group.created", {
            "group_id": gid, "name": name, "group_type": group_type,
            "respondent_key": respondent_key,
        }, actor=created_by)

        return {
            "group_id": gid, "name": name, "description": description,
            "group_type": group_type, "status": "active",
            "respondent_key": respondent_key, "tags": tags or [],
            "strategy_notes": strategy_notes, "created_by": created_by,
            "created_at": now, "updated_at": now, "claim_count": 0,
        }

    def get_case_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        """Get a case group with member claims."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM case_groups WHERE group_id = ?", (group_id,)).fetchone()
        if not row:
            conn.close()
            return None
        g = dict(row)
        g["tags"] = json.loads(g.get("tags", "[]"))

        # Get linked claims
        links = conn.execute(
            "SELECT cl.*, c.data FROM claim_links cl LEFT JOIN claims c ON cl.claim_id = c.claim_id WHERE cl.group_id = ? ORDER BY cl.linked_at ASC",
            (group_id,)
        ).fetchall()
        conn.close()

        members = []
        total_claimed = 0
        total_recovered = 0
        statuses = {}
        for link in links:
            claim_data = {}
            if link["data"]:
                claim_data = json.loads(link["data"]) if isinstance(link["data"], str) else link["data"]
            amt = claim_data.get("amount_claimed_usd", 0)
            total_claimed += amt
            total_recovered += claim_data.get("amount_recovered_usd", 0)
            st = claim_data.get("status", "unknown")
            statuses[st] = statuses.get(st, 0) + 1
            members.append({
                "link_id": link["link_id"],
                "claim_id": link["claim_id"],
                "role": link["role"],
                "linked_at": link["linked_at"],
                "linked_by": link["linked_by"],
                "notes": link["notes"],
                "claimant_name": claim_data.get("claimant_name", "?"),
                "respondent": claim_data.get("respondent_entity", "?"),
                "amount_claimed_usd": amt,
                "status": st,
                "harm_type": claim_data.get("harm_type", "?"),
            })

        g["members"] = members
        g["claim_count"] = len(members)
        g["total_claimed_usd"] = round(total_claimed, 2)
        g["total_recovered_usd"] = round(total_recovered, 2)
        g["status_breakdown"] = statuses
        return g

    def list_case_groups(self, status: str = None, group_type: str = None,
                         respondent_key: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """List case groups with summary stats."""
        conn = _get_db()
        sql = "SELECT g.*, COUNT(cl.link_id) as claim_count FROM case_groups g LEFT JOIN claim_links cl ON g.group_id = cl.group_id WHERE 1=1"
        params: List[Any] = []
        if status:
            sql += " AND g.status = ?"
            params.append(status)
        if group_type:
            sql += " AND g.group_type = ?"
            params.append(group_type)
        if respondent_key:
            sql += " AND g.respondent_key = ?"
            params.append(respondent_key)
        sql += " GROUP BY g.group_id ORDER BY g.created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            results.append(d)
        return results

    def update_case_group(self, group_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update case group metadata."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM case_groups WHERE group_id = ?", (group_id,)).fetchone()
        if not row:
            conn.close()
            return None
        now = datetime.utcnow().isoformat() + "Z"
        allowed = {"name", "description", "status", "tags", "strategy_notes", "group_type"}
        set_parts = []
        params = []
        for k, v in updates.items():
            if k in allowed:
                if k == "tags":
                    v = json.dumps(v) if isinstance(v, list) else v
                elif k == "status" and v not in self.VALID_GROUP_STATUSES:
                    continue
                elif k == "group_type" and v not in self.VALID_GROUP_TYPES:
                    continue
                set_parts.append(f"{k} = ?")
                params.append(v)
        set_parts.append("updated_at = ?")
        params.append(now)
        params.append(group_id)
        conn.execute(f"UPDATE case_groups SET {', '.join(set_parts)} WHERE group_id = ?", params)
        conn.commit()
        updated = conn.execute("SELECT * FROM case_groups WHERE group_id = ?", (group_id,)).fetchone()
        conn.close()
        d = dict(updated)
        d["tags"] = json.loads(d.get("tags", "[]"))
        return d

    def delete_case_group(self, group_id: str) -> bool:
        """Delete a case group and all its links."""
        conn = _get_db()
        row = conn.execute("SELECT name FROM case_groups WHERE group_id = ?", (group_id,)).fetchone()
        if not row:
            conn.close()
            return False
        conn.execute("DELETE FROM claim_links WHERE group_id = ?", (group_id,))
        conn.execute("DELETE FROM case_groups WHERE group_id = ?", (group_id,))
        conn.commit()
        conn.close()
        self.audit("case_group.deleted", {"group_id": group_id, "name": row["name"]}, actor="operator")
        return True

    def link_claim_to_group(self, group_id: str, claim_id: str, role: str = "member",
                            notes: str = "", linked_by: str = "operator") -> Optional[Dict[str, Any]]:
        """Link a claim to a case group."""
        conn = _get_db()
        # Verify group and claim exist
        group = conn.execute("SELECT group_id FROM case_groups WHERE group_id = ?", (group_id,)).fetchone()
        if not group:
            conn.close()
            return None
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            return None
        # Check for duplicate
        existing = conn.execute(
            "SELECT link_id FROM claim_links WHERE group_id = ? AND claim_id = ?", (group_id, claim_id)
        ).fetchone()
        if existing:
            conn.close()
            return {"link_id": existing["link_id"], "already_linked": True}

        if role not in self.VALID_LINK_ROLES:
            role = "member"
        lid = f"lnk_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO claim_links (link_id, group_id, claim_id, role, linked_at, linked_by, notes) VALUES (?,?,?,?,?,?,?)",
            (lid, group_id, claim_id, role, now, linked_by, notes),
        )
        # Update group timestamp
        conn.execute("UPDATE case_groups SET updated_at = ? WHERE group_id = ?", (now, group_id))
        conn.commit()
        conn.close()
        self.audit("claim.linked", {
            "link_id": lid, "group_id": group_id, "claim_id": claim_id, "role": role,
        }, actor=linked_by)
        return {"link_id": lid, "group_id": group_id, "claim_id": claim_id,
                "role": role, "linked_at": now, "linked_by": linked_by, "notes": notes}

    def unlink_claim_from_group(self, group_id: str, claim_id: str) -> bool:
        """Remove a claim from a case group."""
        conn = _get_db()
        cur = conn.execute(
            "DELETE FROM claim_links WHERE group_id = ? AND claim_id = ?", (group_id, claim_id)
        )
        if cur.rowcount > 0:
            now = datetime.utcnow().isoformat() + "Z"
            conn.execute("UPDATE case_groups SET updated_at = ? WHERE group_id = ?", (now, group_id))
        conn.commit()
        conn.close()
        if cur.rowcount > 0:
            self.audit("claim.unlinked", {"group_id": group_id, "claim_id": claim_id}, actor="operator")
        return cur.rowcount > 0

    def get_claim_groups(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get all case groups a claim belongs to."""
        conn = _get_db()
        rows = conn.execute(
            """SELECT g.*, cl.role, cl.linked_at, cl.link_id,
                      (SELECT COUNT(*) FROM claim_links WHERE group_id = g.group_id) as claim_count
               FROM claim_links cl
               JOIN case_groups g ON cl.group_id = g.group_id
               WHERE cl.claim_id = ?
               ORDER BY cl.linked_at DESC""",
            (claim_id,)
        ).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            results.append(d)
        return results

    def auto_detect_groups(self) -> List[Dict[str, Any]]:
        """Auto-detect potential case groups based on respondent clustering."""
        conn = _get_db()
        # Find respondents with 2+ claims not already grouped
        rows = conn.execute("""
            SELECT respondent_entity, COUNT(*) as claim_count,
                   SUM(amount_claimed_usd) as total_amount,
                   GROUP_CONCAT(claim_id) as claim_ids
            FROM claims
            WHERE claim_id NOT IN (SELECT claim_id FROM claim_links)
            GROUP BY respondent_entity
            HAVING COUNT(*) >= 2
            ORDER BY COUNT(*) DESC
        """).fetchall()
        conn.close()
        suggestions = []
        for r in rows:
            suggestions.append({
                "respondent": r["respondent_entity"],
                "claim_count": r["claim_count"],
                "total_amount": round(r["total_amount"] or 0, 2),
                "claim_ids": r["claim_ids"].split(",") if r["claim_ids"] else [],
                "suggested_name": f"Coordinated: {r['respondent_entity']} ({r['claim_count']} claims)",
                "suggested_type": "respondent",
            })
        return suggestions

    def get_group_analytics(self) -> Dict[str, Any]:
        """Get analytics across all case groups."""
        conn = _get_db()
        total_groups = conn.execute("SELECT COUNT(*) as c FROM case_groups").fetchone()["c"]
        active = conn.execute("SELECT COUNT(*) as c FROM case_groups WHERE status = 'active'").fetchone()["c"]
        total_linked = conn.execute("SELECT COUNT(DISTINCT claim_id) as c FROM claim_links").fetchone()["c"]
        total_claims = conn.execute("SELECT COUNT(*) as c FROM claims").fetchone()["c"]
        by_type = {}
        for row in conn.execute("SELECT group_type, COUNT(*) as c FROM case_groups GROUP BY group_type").fetchall():
            by_type[row["group_type"]] = row["c"]
        by_status = {}
        for row in conn.execute("SELECT status, COUNT(*) as c FROM case_groups GROUP BY status").fetchall():
            by_status[row["status"]] = row["c"]
        # Largest groups
        largest = []
        for row in conn.execute("""
            SELECT g.group_id, g.name, g.group_type, COUNT(cl.claim_id) as members
            FROM case_groups g LEFT JOIN claim_links cl ON g.group_id = cl.group_id
            GROUP BY g.group_id ORDER BY members DESC LIMIT 5
        """).fetchall():
            largest.append(dict(row))
        conn.close()
        return {
            "total_groups": total_groups,
            "active_groups": active,
            "total_linked_claims": total_linked,
            "total_claims": total_claims,
            "linking_coverage_pct": round(total_linked / max(total_claims, 1) * 100, 1),
            "by_type": by_type,
            "by_status": by_status,
            "largest_groups": largest,
        }


    # ── Advanced Analytics & Performance Methods ──

    def get_operator_performance(self, operator_id: str = None, days: int = 90) -> Dict[str, Any]:
        """Operator performance KPIs: resolution rate, avg handle time, recovery effectiveness."""
        conn = _get_db()
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        operators = conn.execute("SELECT * FROM operators WHERE status = 'active' ORDER BY name").fetchall()

        perf_list = []
        for op in operators:
            oid = op["operator_id"]
            if operator_id and oid != operator_id:
                continue

            # Claims assigned
            assigned = conn.execute(
                "SELECT COUNT(*) FROM assignments WHERE operator_id = ?", (oid,)
            ).fetchone()[0]

            # Claims assigned in period
            assigned_period = conn.execute(
                "SELECT COUNT(*) FROM assignments WHERE operator_id = ? AND assigned_at >= ?",
                (oid, cutoff)
            ).fetchone()[0]

            # Get assigned claim IDs
            claim_ids = [r["claim_id"] for r in conn.execute(
                "SELECT claim_id FROM assignments WHERE operator_id = ?", (oid,)
            ).fetchall()]

            resolved_count = 0
            total_handle_hours = 0
            total_recovered = 0.0
            total_claimed = 0.0
            notes_written = 0
            outreach_sent = 0
            escalations = 0

            for cid in claim_ids:
                claim = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (cid,)).fetchone()
                if not claim:
                    continue

                total_claimed += claim["amount_claimed_usd"] or 0

                if claim["status"] in ("resolved", "closed"):
                    resolved_count += 1
                    # Handle time: filed_at to updated_at
                    try:
                        filed = datetime.fromisoformat(claim["filed_at"].replace("Z", "+00:00").replace("+00:00", ""))
                        updated = datetime.fromisoformat(claim["updated_at"].replace("Z", "+00:00").replace("+00:00", ""))
                        hours = (updated - filed).total_seconds() / 3600
                        total_handle_hours += hours
                    except Exception:
                        pass

                if claim["status"] == "escalated":
                    escalations += 1

                # Recovery amount for this claim
                rec = conn.execute(
                    "SELECT COALESCE(SUM(amount_recovered), 0) FROM recoveries WHERE claim_id = ?",
                    (cid,)
                ).fetchone()[0]
                total_recovered += rec

                # Notes by this operator
                nc = conn.execute(
                    "SELECT COUNT(*) FROM notes WHERE claim_id = ? AND author = ?",
                    (cid, op["name"])
                ).fetchone()[0]
                notes_written += nc

            # Outreach for assigned claims
            if claim_ids:
                placeholders = ",".join("?" for _ in claim_ids)
                outreach_sent = conn.execute(
                    f"SELECT COUNT(*) FROM outreach_log WHERE claim_id IN ({placeholders}) AND status = 'sent'",
                    claim_ids
                ).fetchone()[0]
            else:
                outreach_sent = 0

            resolution_rate = round(resolved_count / max(assigned, 1) * 100, 1)
            avg_handle_hours = round(total_handle_hours / max(resolved_count, 1), 1)
            recovery_rate = round(total_recovered / max(total_claimed, 1) * 100, 1)

            perf = {
                "operator_id": oid,
                "name": op["name"],
                "role": op["role"],
                "total_assigned": assigned,
                "assigned_in_period": assigned_period,
                "resolved": resolved_count,
                "resolution_rate_pct": resolution_rate,
                "avg_handle_hours": avg_handle_hours,
                "total_recovered_usd": round(total_recovered, 2),
                "total_claimed_usd": round(total_claimed, 2),
                "recovery_rate_pct": recovery_rate,
                "notes_written": notes_written,
                "outreach_sent": outreach_sent,
                "escalations": escalations,
                "efficiency_score": round(
                    (resolution_rate * 0.4) + (recovery_rate * 0.4) + (min(notes_written, 50) / 50 * 20), 1
                ),
            }
            perf_list.append(perf)

        conn.close()

        # Rankings
        perf_list.sort(key=lambda p: p["efficiency_score"], reverse=True)
        for i, p in enumerate(perf_list):
            p["rank"] = i + 1

        return {
            "period_days": days,
            "operator_count": len(perf_list),
            "operators": perf_list,
            "team_avg_resolution_rate": round(
                sum(p["resolution_rate_pct"] for p in perf_list) / max(len(perf_list), 1), 1
            ),
            "team_avg_recovery_rate": round(
                sum(p["recovery_rate_pct"] for p in perf_list) / max(len(perf_list), 1), 1
            ),
        }

    def get_respondent_scorecards(self, limit: int = 20) -> Dict[str, Any]:
        """Respondent behavior scorecards: claims count, settlement rate, avg response time, cooperation score."""
        conn = _get_db()
        respondents = conn.execute(
            "SELECT respondent_entity, COUNT(*) as cnt, "
            "COALESCE(SUM(amount_claimed_usd), 0) as total_claimed "
            "FROM claims GROUP BY respondent_entity ORDER BY cnt DESC LIMIT ?",
            (limit,)
        ).fetchall()

        scorecards = []
        for r in respondents:
            entity = r["respondent_entity"] or "Unknown"
            claim_count = r["cnt"]
            total_claimed = r["total_claimed"]

            # Recovery stats for this respondent
            rec = conn.execute(
                "SELECT COALESCE(SUM(rv.amount_recovered), 0) as recovered "
                "FROM recoveries rv JOIN claims c ON rv.claim_id = c.claim_id "
                "WHERE c.respondent_entity = ?", (entity,)
            ).fetchone()
            total_recovered = rec["recovered"] if rec else 0

            # Settlement stats
            settlements_total = conn.execute(
                "SELECT COUNT(*) FROM settlements s JOIN claims c ON s.claim_id = c.claim_id "
                "WHERE c.respondent_entity = ?", (entity,)
            ).fetchone()[0]
            settlements_accepted = conn.execute(
                "SELECT COUNT(*) FROM settlements s JOIN claims c ON s.claim_id = c.claim_id "
                "WHERE c.respondent_entity = ? AND s.status = 'accepted'", (entity,)
            ).fetchone()[0]

            # Resolution stats
            resolved = conn.execute(
                "SELECT COUNT(*) FROM claims WHERE respondent_entity = ? AND status IN ('resolved', 'closed')",
                (entity,)
            ).fetchone()[0]
            escalated = conn.execute(
                "SELECT COUNT(*) FROM claims WHERE respondent_entity = ? AND status = 'escalated'",
                (entity,)
            ).fetchone()[0]

            # Compute cooperation score (0-100)
            settlement_rate = settlements_accepted / max(settlements_total, 1)
            resolution_rate = resolved / max(claim_count, 1)
            escalation_rate = escalated / max(claim_count, 1)
            recovery_ratio = total_recovered / max(total_claimed, 1)

            cooperation_score = round(
                (settlement_rate * 30) + (resolution_rate * 30) +
                ((1 - escalation_rate) * 20) + (recovery_ratio * 20), 1
            ) * 100 / 100

            # Rating label
            if cooperation_score >= 70:
                rating = "cooperative"
            elif cooperation_score >= 40:
                rating = "mixed"
            else:
                rating = "uncooperative"

            scorecards.append({
                "respondent": entity,
                "claim_count": claim_count,
                "total_claimed_usd": round(total_claimed, 2),
                "total_recovered_usd": round(total_recovered, 2),
                "recovery_rate_pct": round(recovery_ratio * 100, 1),
                "settlements_offered": settlements_total,
                "settlements_accepted": settlements_accepted,
                "settlement_acceptance_rate_pct": round(settlement_rate * 100, 1),
                "resolved_count": resolved,
                "resolution_rate_pct": round(resolution_rate * 100, 1),
                "escalated_count": escalated,
                "cooperation_score": round(cooperation_score, 1),
                "rating": rating,
            })

        conn.close()
        scorecards.sort(key=lambda s: s["claim_count"], reverse=True)

        return {
            "total_respondents": len(scorecards),
            "scorecards": scorecards,
            "avg_cooperation": round(
                sum(s["cooperation_score"] for s in scorecards) / max(len(scorecards), 1), 1
            ),
        }

    def get_pipeline_funnel(self) -> Dict[str, Any]:
        """Pipeline funnel: claims flowing through each status stage."""
        conn = _get_db()
        stages = [
            ("filed", "Filed"),
            ("under_review", "Under Review"),
            ("in_resolution", "In Resolution"),
            ("escalated", "Escalated"),
            ("resolved", "Resolved"),
            ("closed", "Closed"),
            ("withdrawn", "Withdrawn"),
            ("rejected", "Rejected"),
        ]

        funnel = []
        total = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        for status_key, label in stages:
            count = conn.execute(
                "SELECT COUNT(*) FROM claims WHERE status = ?", (status_key,)
            ).fetchone()[0]
            amount = conn.execute(
                "SELECT COALESCE(SUM(amount_claimed_usd), 0) FROM claims WHERE status = ?",
                (status_key,)
            ).fetchone()[0]
            funnel.append({
                "stage": status_key,
                "label": label,
                "count": count,
                "pct_of_total": round(count / max(total, 1) * 100, 1),
                "total_amount_usd": round(amount, 2),
            })

        # Conversion rates between stages
        filed = sum(f["count"] for f in funnel)
        reviewed = sum(f["count"] for f in funnel if f["stage"] not in ("filed",))
        in_resolution = sum(f["count"] for f in funnel if f["stage"] in ("in_resolution", "escalated", "resolved", "closed"))
        resolved_closed = sum(f["count"] for f in funnel if f["stage"] in ("resolved", "closed"))

        conversions = {
            "filed_to_review_pct": round(reviewed / max(filed, 1) * 100, 1),
            "review_to_resolution_pct": round(in_resolution / max(reviewed, 1) * 100, 1),
            "resolution_to_closed_pct": round(resolved_closed / max(in_resolution, 1) * 100, 1),
            "overall_resolution_pct": round(resolved_closed / max(filed, 1) * 100, 1),
        }

        # Average time in each stage (estimated from timestamps)
        conn.close()

        return {
            "total_claims": total,
            "funnel": funnel,
            "conversions": conversions,
        }

    def get_trend_analytics(self, days: int = 30, granularity: str = "day") -> Dict[str, Any]:
        """Time-series trends for claims filed, resolved, recovered amounts."""
        conn = _get_db()
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        if granularity == "week":
            date_fmt = "%Y-W%W"
        elif granularity == "month":
            date_fmt = "%Y-%m"
        else:
            date_fmt = "%Y-%m-%d"

        # Claims filed per period
        filed_trend = {}
        for row in conn.execute(
            "SELECT filed_at, amount_claimed_usd FROM claims WHERE filed_at >= ?", (cutoff,)
        ).fetchall():
            try:
                dt = datetime.fromisoformat(row["filed_at"].replace("Z", "+00:00").replace("+00:00", ""))
                key = dt.strftime(date_fmt)
                if key not in filed_trend:
                    filed_trend[key] = {"count": 0, "amount": 0.0}
                filed_trend[key]["count"] += 1
                filed_trend[key]["amount"] += row["amount_claimed_usd"] or 0
            except Exception:
                pass

        # Recoveries per period
        recovery_trend = {}
        for row in conn.execute(
            "SELECT recorded_at, amount_recovered FROM recoveries WHERE recorded_at >= ?", (cutoff,)
        ).fetchall():
            try:
                dt = datetime.fromisoformat(row["recorded_at"].replace("Z", "+00:00").replace("+00:00", ""))
                key = dt.strftime(date_fmt)
                if key not in recovery_trend:
                    recovery_trend[key] = {"count": 0, "amount": 0.0}
                recovery_trend[key]["count"] += 1
                recovery_trend[key]["amount"] += row["amount_recovered"] or 0
            except Exception:
                pass

        # Resolutions per period
        resolution_trend = {}
        for row in conn.execute(
            "SELECT resolved_at FROM resolutions WHERE resolved_at >= ?", (cutoff,)
        ).fetchall():
            try:
                dt = datetime.fromisoformat(row["resolved_at"].replace("Z", "+00:00").replace("+00:00", ""))
                key = dt.strftime(date_fmt)
                resolution_trend[key] = resolution_trend.get(key, 0) + 1
            except Exception:
                pass

        # Build unified timeline
        all_keys = sorted(set(list(filed_trend.keys()) + list(recovery_trend.keys()) + list(resolution_trend.keys())))
        timeline = []
        for key in all_keys:
            ft = filed_trend.get(key, {"count": 0, "amount": 0.0})
            rt = recovery_trend.get(key, {"count": 0, "amount": 0.0})
            rsl = resolution_trend.get(key, 0)
            timeline.append({
                "period": key,
                "claims_filed": ft["count"],
                "amount_claimed": round(ft["amount"], 2),
                "recoveries": rt["count"],
                "amount_recovered": round(rt["amount"], 2),
                "resolutions": rsl,
            })

        # Cumulative totals
        cum_claimed = 0
        cum_recovered = 0
        for t in timeline:
            cum_claimed += t["amount_claimed"]
            cum_recovered += t["amount_recovered"]
            t["cumulative_claimed"] = round(cum_claimed, 2)
            t["cumulative_recovered"] = round(cum_recovered, 2)

        conn.close()

        return {
            "period_days": days,
            "granularity": granularity,
            "data_points": len(timeline),
            "timeline": timeline,
            "summary": {
                "total_filed": sum(t["claims_filed"] for t in timeline),
                "total_claimed_usd": round(cum_claimed, 2),
                "total_recovered_usd": round(cum_recovered, 2),
                "total_resolutions": sum(t["resolutions"] for t in timeline),
                "avg_daily_filings": round(sum(t["claims_filed"] for t in timeline) / max(days, 1), 1),
            },
        }

    def get_financial_summary(self) -> Dict[str, Any]:
        """Financial overview: claimed vs recovered, by method, by respondent, projected."""
        conn = _get_db()

        total_claimed = conn.execute(
            "SELECT COALESCE(SUM(amount_claimed_usd), 0) FROM claims"
        ).fetchone()[0]
        total_recovered = conn.execute(
            "SELECT COALESCE(SUM(amount_recovered), 0) FROM recoveries"
        ).fetchone()[0]
        total_settled = conn.execute(
            "SELECT COALESCE(SUM(amount_offered), 0) FROM settlements WHERE status = 'accepted'"
        ).fetchone()[0]
        pending_settlements = conn.execute(
            "SELECT COALESCE(SUM(amount_offered), 0) FROM settlements WHERE status = 'pending'"
        ).fetchone()[0]

        # Recovery by method
        by_method = {}
        for row in conn.execute(
            "SELECT recovery_method, COUNT(*) as cnt, COALESCE(SUM(amount_recovered), 0) as total "
            "FROM recoveries GROUP BY recovery_method ORDER BY total DESC"
        ).fetchall():
            by_method[row["recovery_method"]] = {
                "count": row["cnt"],
                "amount": round(row["total"], 2),
            }

        # Top respondents by exposure
        top_exposure = []
        for row in conn.execute(
            "SELECT respondent_entity, COALESCE(SUM(amount_claimed_usd), 0) as claimed, COUNT(*) as cnt "
            "FROM claims GROUP BY respondent_entity ORDER BY claimed DESC LIMIT 10"
        ).fetchall():
            entity = row["respondent_entity"] or "Unknown"
            recovered = conn.execute(
                "SELECT COALESCE(SUM(rv.amount_recovered), 0) FROM recoveries rv "
                "JOIN claims c ON rv.claim_id = c.claim_id WHERE c.respondent_entity = ?",
                (entity,)
            ).fetchone()[0]
            top_exposure.append({
                "respondent": entity,
                "claims": row["cnt"],
                "claimed_usd": round(row["claimed"], 2),
                "recovered_usd": round(recovered, 2),
                "gap_usd": round(row["claimed"] - recovered, 2),
            })

        # Active claims (potential future recovery)
        active_claimed = conn.execute(
            "SELECT COALESCE(SUM(amount_claimed_usd), 0) FROM claims "
            "WHERE status NOT IN ('resolved', 'closed', 'withdrawn', 'rejected')"
        ).fetchone()[0]

        conn.close()

        overall_recovery_rate = round(total_recovered / max(total_claimed, 1) * 100, 1)

        return {
            "total_claimed_usd": round(total_claimed, 2),
            "total_recovered_usd": round(total_recovered, 2),
            "total_settled_usd": round(total_settled, 2),
            "pending_settlements_usd": round(pending_settlements, 2),
            "recovery_gap_usd": round(total_claimed - total_recovered, 2),
            "overall_recovery_rate_pct": overall_recovery_rate,
            "active_exposure_usd": round(active_claimed, 2),
            "projected_recovery_usd": round(active_claimed * (overall_recovery_rate / 100), 2),
            "by_recovery_method": by_method,
            "top_exposure": top_exposure,
        }

    def get_platform_health_score(self) -> Dict[str, Any]:
        """Composite platform health score based on multiple performance indicators."""
        conn = _get_db()

        total = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        if total == 0:
            conn.close()
            return {"health_score": 0, "grade": "N/A", "factors": {}, "total_claims": 0}

        # Factor 1: Resolution rate (weight 25%)
        resolved = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status IN ('resolved', 'closed')"
        ).fetchone()[0]
        resolution_rate = resolved / total

        # Factor 2: Recovery effectiveness (weight 25%)
        claimed = conn.execute(
            "SELECT COALESCE(SUM(amount_claimed_usd), 0) FROM claims"
        ).fetchone()[0]
        recovered = conn.execute(
            "SELECT COALESCE(SUM(amount_recovered), 0) FROM recoveries"
        ).fetchone()[0]
        recovery_rate = recovered / max(claimed, 1)

        # Factor 3: SLA compliance (weight 20%)
        sla_ok = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status NOT IN ('resolved', 'closed', 'withdrawn', 'rejected')"
        ).fetchone()[0]
        active_total = max(sla_ok, 1)
        overdue = 0
        now = datetime.utcnow()
        for row in conn.execute(
            "SELECT filed_at FROM claims WHERE status NOT IN ('resolved', 'closed', 'withdrawn', 'rejected')"
        ).fetchall():
            try:
                filed = datetime.fromisoformat(row["filed_at"].replace("Z", "+00:00").replace("+00:00", ""))
                age_days = (now - filed).days
                if age_days > 30:
                    overdue += 1
            except Exception:
                pass
        sla_compliance = 1 - (overdue / active_total)

        # Factor 4: Assignment coverage (weight 15%)
        assigned = conn.execute("SELECT COUNT(DISTINCT claim_id) FROM assignments").fetchone()[0]
        assignment_rate = assigned / total

        # Factor 5: Documentation rate (weight 15%)
        documented = conn.execute("SELECT COUNT(DISTINCT claim_id) FROM documents").fetchone()[0]
        doc_rate = documented / total

        # Weighted score
        score = round(
            (resolution_rate * 25) +
            (recovery_rate * 25) +
            (sla_compliance * 20) +
            (assignment_rate * 15) +
            (doc_rate * 15), 1
        )

        if score >= 80:
            grade = "A"
        elif score >= 65:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 35:
            grade = "D"
        else:
            grade = "F"

        conn.close()

        return {
            "health_score": score,
            "grade": grade,
            "total_claims": total,
            "factors": {
                "resolution_rate": {"value": round(resolution_rate * 100, 1), "weight": 25, "contribution": round(resolution_rate * 25, 1)},
                "recovery_effectiveness": {"value": round(recovery_rate * 100, 1), "weight": 25, "contribution": round(recovery_rate * 25, 1)},
                "sla_compliance": {"value": round(sla_compliance * 100, 1), "weight": 20, "contribution": round(sla_compliance * 20, 1)},
                "assignment_coverage": {"value": round(assignment_rate * 100, 1), "weight": 15, "contribution": round(assignment_rate * 15, 1)},
                "documentation_rate": {"value": round(doc_rate * 100, 1), "weight": 15, "contribution": round(doc_rate * 15, 1)},
            },
        }


    # ── Priority Queue & Smart Triage Methods ──

    TRIAGE_LABELS = {
        (90, 100): ("critical", "Immediate action required"),
        (70, 89):  ("high", "Urgent — address within 24h"),
        (50, 69):  ("medium", "Standard priority"),
        (25, 49):  ("low", "Monitor — low urgency"),
        (0, 24):   ("minimal", "No immediate action needed"),
    }

    def compute_priority_score(self, claim_id: str) -> Dict[str, Any]:
        """
        Compute a composite priority score (0-100) for a claim based on:
          - Amount factor (20%): higher claim = higher priority
          - Age/urgency factor (20%): older unfiled claims are more urgent
          - SLA factor (20%): how close to or past SLA deadline
          - Evidence factor (10%): claims with more evidence are more actionable
          - Respondent factor (15%): uncooperative respondents get priority
          - Settlement factor (15%): pending settlements with deadlines
        """
        conn = _get_db()
        claim = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            return None

        now = datetime.utcnow()
        factors = {}

        # 1. Amount factor (0-100, weight 20%)
        amount = claim["amount_claimed_usd"] or 0
        if amount >= 50000:
            amt_score = 100
        elif amount >= 10000:
            amt_score = 80
        elif amount >= 5000:
            amt_score = 60
        elif amount >= 1000:
            amt_score = 40
        elif amount >= 100:
            amt_score = 20
        else:
            amt_score = 10
        factors["amount"] = {"score": amt_score, "weight": 20, "detail": f"${amount:,.0f}"}

        # 2. Age/urgency factor (0-100, weight 20%)
        try:
            filed = datetime.fromisoformat(claim["filed_at"].replace("Z", "+00:00").replace("+00:00", ""))
            age_days = (now - filed).days
        except Exception:
            age_days = 0

        if claim["status"] in ("resolved", "closed", "withdrawn", "rejected"):
            age_score = 0  # Terminal states don't need urgency
        elif age_days >= 60:
            age_score = 100
        elif age_days >= 30:
            age_score = 80
        elif age_days >= 14:
            age_score = 60
        elif age_days >= 7:
            age_score = 40
        else:
            age_score = 20
        factors["age"] = {"score": age_score, "weight": 20, "detail": f"{age_days} days old"}

        # 3. SLA factor (0-100, weight 20%)
        sla_deadlines = {"filed": 3, "under_review": 7, "in_resolution": 14, "escalated": 5}
        sla_target = sla_deadlines.get(claim["status"], 30)
        sla_remaining = sla_target - age_days
        if claim["status"] in ("resolved", "closed", "withdrawn", "rejected"):
            sla_score = 0
        elif sla_remaining <= 0:
            sla_score = 100  # Overdue
        elif sla_remaining <= 1:
            sla_score = 90
        elif sla_remaining <= 3:
            sla_score = 70
        elif sla_remaining <= 7:
            sla_score = 40
        else:
            sla_score = 15
        factors["sla"] = {"score": sla_score, "weight": 20, "detail": f"{sla_remaining}d remaining" if sla_remaining > 0 else "OVERDUE"}

        # 4. Evidence factor (0-100, weight 10%)
        doc_count = conn.execute(
            "SELECT COUNT(*) FROM documents WHERE claim_id = ?", (claim_id,)
        ).fetchone()[0]
        if doc_count == 0:
            ev_score = 80  # No evidence = needs attention
        elif doc_count >= 5:
            ev_score = 30  # Well-documented
        elif doc_count >= 2:
            ev_score = 50
        else:
            ev_score = 65
        factors["evidence"] = {"score": ev_score, "weight": 10, "detail": f"{doc_count} documents"}

        # 5. Respondent factor (0-100, weight 15%)
        entity = claim["respondent_entity"] or "Unknown"
        resp_claims = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE respondent_entity = ?", (entity,)
        ).fetchone()[0]
        resp_escalated = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE respondent_entity = ? AND status = 'escalated'",
            (entity,)
        ).fetchone()[0]
        resp_resolved = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE respondent_entity = ? AND status IN ('resolved','closed')",
            (entity,)
        ).fetchone()[0]
        escalation_rate = resp_escalated / max(resp_claims, 1)
        resolution_rate = resp_resolved / max(resp_claims, 1)
        resp_score = round(min(100, (escalation_rate * 60) + ((1 - resolution_rate) * 40)))
        factors["respondent"] = {"score": resp_score, "weight": 15, "detail": f"{entity} ({resp_claims} claims)"}

        # 6. Settlement factor (0-100, weight 15%)
        pending_settlements = conn.execute(
            "SELECT COUNT(*) FROM settlements WHERE claim_id = ? AND status = 'pending'",
            (claim_id,)
        ).fetchone()[0]
        nearest_deadline = conn.execute(
            "SELECT MIN(response_deadline) FROM settlements WHERE claim_id = ? AND status = 'pending' AND response_deadline IS NOT NULL",
            (claim_id,)
        ).fetchone()[0]

        if pending_settlements > 0 and nearest_deadline:
            try:
                deadline = datetime.fromisoformat(nearest_deadline.replace("Z", "+00:00").replace("+00:00", ""))
                days_to_deadline = (deadline - now).days
                if days_to_deadline <= 0:
                    settle_score = 100
                elif days_to_deadline <= 3:
                    settle_score = 85
                elif days_to_deadline <= 7:
                    settle_score = 60
                else:
                    settle_score = 35
            except Exception:
                settle_score = 50
        elif pending_settlements > 0:
            settle_score = 50
        else:
            settle_score = 15  # No pending settlements
        factors["settlement"] = {"score": settle_score, "weight": 15, "detail": f"{pending_settlements} pending"}

        # Check for manual override
        override = conn.execute(
            "SELECT new_value FROM triage_actions WHERE claim_id = ? AND action_type = 'priority_override' ORDER BY created_at DESC LIMIT 1",
            (claim_id,)
        ).fetchone()

        conn.close()

        # Weighted composite
        composite = sum(f["score"] * f["weight"] / 100 for f in factors.values())
        composite = round(min(100, max(0, composite)), 1)

        # Apply override if exists
        override_active = False
        if override:
            try:
                composite = float(override["new_value"])
                override_active = True
            except Exception:
                pass

        # Determine triage label
        triage_level = "minimal"
        triage_desc = ""
        for (lo, hi), (level, desc) in self.TRIAGE_LABELS.items():
            if lo <= composite <= hi:
                triage_level = level
                triage_desc = desc
                break

        return {
            "claim_id": claim_id,
            "priority_score": composite,
            "triage_level": triage_level,
            "triage_description": triage_desc,
            "override_active": override_active,
            "factors": factors,
            "status": claim["status"],
            "claimant_name": claim["claimant_name"],
            "respondent": entity,
            "amount_claimed_usd": amount,
            "filed_at": claim["filed_at"],
        }

    def get_priority_queue(self, limit: int = 50, triage_level: str = None,
                            status: str = None, operator_id: str = None) -> Dict[str, Any]:
        """Build the smart priority queue — all active claims ranked by priority score."""
        conn = _get_db()
        # Get active claims
        query = "SELECT claim_id FROM claims WHERE status NOT IN ('resolved','closed','withdrawn','rejected')"
        params = []
        if status:
            query = "SELECT claim_id FROM claims WHERE status = ?"
            params = [status]

        # Filter by operator assignment if specified
        if operator_id:
            query += " AND claim_id IN (SELECT claim_id FROM assignments WHERE operator_id = ?)"
            params.append(operator_id)

        claim_ids = [r["claim_id"] for r in conn.execute(query, params).fetchall()]
        conn.close()

        # Compute scores for all
        scored = []
        for cid in claim_ids:
            result = self.compute_priority_score(cid)
            if result:
                scored.append(result)

        # Sort by priority score descending
        scored.sort(key=lambda x: x["priority_score"], reverse=True)

        # Filter by triage level if specified
        if triage_level:
            scored = [s for s in scored if s["triage_level"] == triage_level]

        # Summary stats
        total = len(scored)
        by_level = {}
        for s in scored:
            lv = s["triage_level"]
            by_level[lv] = by_level.get(lv, 0) + 1

        return {
            "total_in_queue": total,
            "queue": scored[:limit],
            "by_triage_level": by_level,
            "avg_priority": round(sum(s["priority_score"] for s in scored) / max(total, 1), 1),
        }

    def triage_action(self, claim_id: str, action_type: str, new_value: str,
                       reason: str = "", performed_by: str = "operator") -> Dict[str, Any]:
        """Record a triage action (priority override, manual escalation, etc.)."""
        conn = _get_db()
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            return None

        # Get previous value
        prev = self.compute_priority_score(claim_id)
        previous_value = str(prev["priority_score"]) if prev else "0"

        action_id = f"tri_{uuid.uuid4().hex[:12]}"
        now_str = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO triage_actions (action_id, claim_id, action_type, previous_value, new_value, reason, performed_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (action_id, claim_id, action_type, previous_value, new_value, reason, performed_by, now_str)
        )
        conn.commit()
        conn.close()

        return {
            "action_id": action_id,
            "claim_id": claim_id,
            "action_type": action_type,
            "previous_value": previous_value,
            "new_value": new_value,
            "reason": reason,
            "performed_by": performed_by,
            "created_at": now_str,
        }

    def get_triage_history(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get triage action history for a claim."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM triage_actions WHERE claim_id = ? ORDER BY created_at DESC",
            (claim_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_triage_summary(self) -> Dict[str, Any]:
        """Overall triage summary across all active claims."""
        conn = _get_db()
        total_active = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status NOT IN ('resolved','closed','withdrawn','rejected')"
        ).fetchone()[0]
        total_overrides = conn.execute(
            "SELECT COUNT(DISTINCT claim_id) FROM triage_actions WHERE action_type = 'priority_override'"
        ).fetchone()[0]
        recent_actions = conn.execute(
            "SELECT * FROM triage_actions ORDER BY created_at DESC LIMIT 10"
        ).fetchall()
        conn.close()

        return {
            "total_active_claims": total_active,
            "claims_with_overrides": total_overrides,
            "recent_actions": [dict(r) for r in recent_actions],
        }

    # ── Tags & Custom Fields Methods ──

    TAG_COLORS = ["#58a6ff", "#f85149", "#4ade80", "#f0883e", "#d2a8ff", "#79c0ff",
                  "#ff7b72", "#7ee787", "#ffa657", "#d2a8ff", "#a5d6ff", "#ffd33d"]
    TAG_CATEGORIES = ["general", "status", "priority", "source", "region", "type", "team", "custom"]
    FIELD_TYPES = ["text", "number", "date", "select", "boolean", "url", "email"]

    def create_tag(self, name: str, color: str = "#58a6ff", category: str = "general",
                   description: str = "", created_by: str = "operator") -> Dict[str, Any]:
        """Create a new tag."""
        conn = _get_db()
        # Check uniqueness
        existing = conn.execute("SELECT tag_id FROM tags WHERE LOWER(name) = LOWER(?)", (name.strip(),)).fetchone()
        if existing:
            conn.close()
            return {"error": "Tag already exists", "tag_id": existing["tag_id"]}

        tag_id = f"tag_{uuid.uuid4().hex[:12]}"
        now_str = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO tags (tag_id, name, color, category, description, created_by, created_at) VALUES (?,?,?,?,?,?,?)",
            (tag_id, name.strip(), color, category, description, created_by, now_str)
        )
        conn.commit()
        conn.close()
        return {"tag_id": tag_id, "name": name.strip(), "color": color, "category": category,
                "description": description, "usage_count": 0, "created_by": created_by, "created_at": now_str}

    def list_tags(self, category: str = None, search: str = None) -> List[Dict[str, Any]]:
        """List all tags with optional filtering."""
        conn = _get_db()
        query = "SELECT * FROM tags"
        params = []
        conditions = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        if search:
            conditions.append("LOWER(name) LIKE ?")
            params.append(f"%{search.lower()}%")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY usage_count DESC, name ASC"

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_tag(self, tag_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update a tag's color, category, or description."""
        conn = _get_db()
        tag = conn.execute("SELECT * FROM tags WHERE tag_id = ?", (tag_id,)).fetchone()
        if not tag:
            conn.close()
            return None
        allowed = {"color", "category", "description", "name"}
        sets = []
        params = []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                params.append(v)
        if sets:
            params.append(tag_id)
            conn.execute(f"UPDATE tags SET {', '.join(sets)} WHERE tag_id = ?", params)
            conn.commit()
        result = conn.execute("SELECT * FROM tags WHERE tag_id = ?", (tag_id,)).fetchone()
        conn.close()
        return dict(result) if result else None

    def delete_tag(self, tag_id: str) -> bool:
        """Delete a tag and remove all claim associations."""
        conn = _get_db()
        tag = conn.execute("SELECT tag_id FROM tags WHERE tag_id = ?", (tag_id,)).fetchone()
        if not tag:
            conn.close()
            return False
        conn.execute("DELETE FROM claim_tags WHERE tag_id = ?", (tag_id,))
        conn.execute("DELETE FROM tags WHERE tag_id = ?", (tag_id,))
        conn.commit()
        conn.close()
        return True

    def tag_claim(self, claim_id: str, tag_id: str, tagged_by: str = "operator") -> Dict[str, Any]:
        """Add a tag to a claim."""
        conn = _get_db()
        # Verify both exist
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        tag = conn.execute("SELECT * FROM tags WHERE tag_id = ?", (tag_id,)).fetchone()
        if not claim or not tag:
            conn.close()
            return {"error": "Claim or tag not found"}

        # Check if already tagged
        existing = conn.execute(
            "SELECT * FROM claim_tags WHERE claim_id = ? AND tag_id = ?", (claim_id, tag_id)
        ).fetchone()
        if existing:
            conn.close()
            return {"status": "already_tagged", "claim_id": claim_id, "tag_id": tag_id}

        now_str = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO claim_tags (claim_id, tag_id, tagged_by, tagged_at) VALUES (?,?,?,?)",
            (claim_id, tag_id, tagged_by, now_str)
        )
        conn.execute("UPDATE tags SET usage_count = usage_count + 1 WHERE tag_id = ?", (tag_id,))
        conn.commit()
        conn.close()
        return {"status": "tagged", "claim_id": claim_id, "tag_id": tag_id, "tag_name": tag["name"],
                "color": tag["color"], "tagged_at": now_str}

    def untag_claim(self, claim_id: str, tag_id: str) -> bool:
        """Remove a tag from a claim."""
        conn = _get_db()
        existing = conn.execute(
            "SELECT * FROM claim_tags WHERE claim_id = ? AND tag_id = ?", (claim_id, tag_id)
        ).fetchone()
        if not existing:
            conn.close()
            return False
        conn.execute("DELETE FROM claim_tags WHERE claim_id = ? AND tag_id = ?", (claim_id, tag_id))
        conn.execute("UPDATE tags SET usage_count = MAX(0, usage_count - 1) WHERE tag_id = ?", (tag_id,))
        conn.commit()
        conn.close()
        return True

    def get_claim_tags(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get all tags for a claim."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT t.*, ct.tagged_by, ct.tagged_at FROM tags t "
            "JOIN claim_tags ct ON t.tag_id = ct.tag_id WHERE ct.claim_id = ? ORDER BY t.name",
            (claim_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_claims_by_tag(self, tag_id: str) -> List[str]:
        """Get all claim IDs with a specific tag."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT claim_id FROM claim_tags WHERE tag_id = ? ORDER BY tagged_at DESC", (tag_id,)
        ).fetchall()
        conn.close()
        return [r["claim_id"] for r in rows]

    def get_tag_stats(self) -> Dict[str, Any]:
        """Tag usage statistics."""
        conn = _get_db()
        total_tags = conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
        total_tagged = conn.execute("SELECT COUNT(DISTINCT claim_id) FROM claim_tags").fetchone()[0]
        total_claims = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        by_category = {}
        for row in conn.execute(
            "SELECT category, COUNT(*) as cnt FROM tags GROUP BY category ORDER BY cnt DESC"
        ).fetchall():
            by_category[row["category"]] = row["cnt"]
        top_tags = conn.execute(
            "SELECT tag_id, name, color, category, usage_count FROM tags ORDER BY usage_count DESC LIMIT 10"
        ).fetchall()
        conn.close()
        return {
            "total_tags": total_tags,
            "total_tagged_claims": total_tagged,
            "total_claims": total_claims,
            "coverage_pct": round(total_tagged / max(total_claims, 1) * 100, 1),
            "by_category": by_category,
            "top_tags": [dict(r) for r in top_tags],
        }

    # Custom Fields
    def create_custom_field(self, name: str, field_type: str = "text", description: str = "",
                             options: list = None, required: bool = False,
                             created_by: str = "operator") -> Dict[str, Any]:
        """Create a custom field definition."""
        conn = _get_db()
        existing = conn.execute("SELECT field_id FROM custom_fields WHERE LOWER(name) = LOWER(?)", (name.strip(),)).fetchone()
        if existing:
            conn.close()
            return {"error": "Field already exists", "field_id": existing["field_id"]}

        if field_type not in self.FIELD_TYPES:
            field_type = "text"
        field_id = f"fld_{uuid.uuid4().hex[:12]}"
        now_str = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO custom_fields (field_id, name, field_type, description, options, required, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (field_id, name.strip(), field_type, description, json.dumps(options or []), 1 if required else 0, created_by, now_str)
        )
        conn.commit()
        conn.close()
        return {"field_id": field_id, "name": name.strip(), "field_type": field_type,
                "description": description, "options": options or [], "required": required,
                "created_by": created_by, "created_at": now_str}

    def list_custom_fields(self) -> List[Dict[str, Any]]:
        """List all custom field definitions."""
        conn = _get_db()
        rows = conn.execute("SELECT * FROM custom_fields ORDER BY name").fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["options"] = json.loads(d["options"]) if d["options"] else []
            d["required"] = bool(d["required"])
            result.append(d)
        return result

    def delete_custom_field(self, field_id: str) -> bool:
        """Delete a custom field and all its values."""
        conn = _get_db()
        field = conn.execute("SELECT field_id FROM custom_fields WHERE field_id = ?", (field_id,)).fetchone()
        if not field:
            conn.close()
            return False
        conn.execute("DELETE FROM claim_custom_values WHERE field_id = ?", (field_id,))
        conn.execute("DELETE FROM custom_fields WHERE field_id = ?", (field_id,))
        conn.commit()
        conn.close()
        return True

    def set_claim_custom_value(self, claim_id: str, field_id: str, value: str,
                                updated_by: str = "operator") -> Dict[str, Any]:
        """Set a custom field value for a claim."""
        conn = _get_db()
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        field = conn.execute("SELECT * FROM custom_fields WHERE field_id = ?", (field_id,)).fetchone()
        if not claim or not field:
            conn.close()
            return {"error": "Claim or field not found"}

        now_str = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT OR REPLACE INTO claim_custom_values (claim_id, field_id, value, updated_by, updated_at) VALUES (?,?,?,?,?)",
            (claim_id, field_id, str(value), updated_by, now_str)
        )
        conn.commit()
        conn.close()
        return {"claim_id": claim_id, "field_id": field_id, "field_name": field["name"],
                "value": str(value), "updated_at": now_str}

    def get_claim_custom_values(self, claim_id: str) -> List[Dict[str, Any]]:
        """Get all custom field values for a claim."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT cf.field_id, cf.name, cf.field_type, ccv.value, ccv.updated_by, ccv.updated_at "
            "FROM custom_fields cf LEFT JOIN claim_custom_values ccv "
            "ON cf.field_id = ccv.field_id AND ccv.claim_id = ? ORDER BY cf.name",
            (claim_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ── Data Quality & Deduplication Methods ──

    @staticmethod
    def _normalize(s: str) -> str:
        """Normalize a string for fuzzy comparison."""
        if not s:
            return ""
        return s.strip().lower().replace("-", " ").replace("_", " ").replace(".", " ")

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        """Simple similarity ratio between two strings (0-1)."""
        a, b = a.lower().strip(), b.lower().strip()
        if not a or not b:
            return 0.0
        if a == b:
            return 1.0
        # Longest common subsequence ratio
        shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
        matches = sum(1 for c in shorter if c in longer)
        # Combine with prefix match
        prefix = 0
        for i in range(min(len(a), len(b))):
            if a[i] == b[i]:
                prefix += 1
            else:
                break
        prefix_ratio = prefix / max(len(a), len(b))
        char_ratio = matches / max(len(longer), 1)
        return round((prefix_ratio * 0.5) + (char_ratio * 0.5), 3)

    def scan_duplicates(self, threshold: float = 0.7) -> Dict[str, Any]:
        """Scan all claims for potential duplicates based on multiple fields."""
        conn = _get_db()
        claims = conn.execute(
            "SELECT claim_id, claimant_name, claimant_email, respondent_entity, "
            "amount_claimed_usd, harm_type, filed_at FROM claims ORDER BY filed_at"
        ).fetchall()

        # Clear old pending pairs
        conn.execute("DELETE FROM duplicate_pairs WHERE status = 'pending'")
        conn.commit()

        found = []
        seen = set()
        for i, a in enumerate(claims):
            for j in range(i + 1, len(claims)):
                b = claims[j]
                if a["claim_id"] == b["claim_id"]:
                    continue
                pair_key = tuple(sorted([a["claim_id"], b["claim_id"]]))
                if pair_key in seen:
                    continue

                # Score each field
                match_fields = []
                total_score = 0
                weights = 0

                # Name similarity (weight 30)
                name_sim = self._similarity(
                    self._normalize(a["claimant_name"] or ""),
                    self._normalize(b["claimant_name"] or "")
                )
                if name_sim >= 0.7:
                    match_fields.append({"field": "name", "score": name_sim})
                total_score += name_sim * 30
                weights += 30

                # Email exact match (weight 30)
                email_a = (a["claimant_email"] or "").strip().lower()
                email_b = (b["claimant_email"] or "").strip().lower()
                email_sim = 1.0 if email_a and email_b and email_a == email_b else 0.0
                if email_sim > 0:
                    match_fields.append({"field": "email", "score": 1.0})
                total_score += email_sim * 30
                weights += 30

                # Respondent similarity (weight 20)
                resp_sim = self._similarity(
                    self._normalize(a["respondent_entity"] or ""),
                    self._normalize(b["respondent_entity"] or "")
                )
                if resp_sim >= 0.8:
                    match_fields.append({"field": "respondent", "score": resp_sim})
                total_score += resp_sim * 20
                weights += 20

                # Amount proximity (weight 20)
                amt_a = a["amount_claimed_usd"] or 0
                amt_b = b["amount_claimed_usd"] or 0
                if amt_a > 0 and amt_b > 0:
                    amt_ratio = min(amt_a, amt_b) / max(amt_a, amt_b)
                else:
                    amt_ratio = 0
                if amt_ratio >= 0.9:
                    match_fields.append({"field": "amount", "score": amt_ratio})
                total_score += amt_ratio * 20
                weights += 20

                overall = total_score / max(weights, 1)

                if overall >= threshold and len(match_fields) >= 2:
                    seen.add(pair_key)
                    pair_id = f"dup_{uuid.uuid4().hex[:12]}"
                    now_str = datetime.utcnow().isoformat() + "Z"
                    conn.execute(
                        "INSERT OR IGNORE INTO duplicate_pairs (pair_id, claim_id_a, claim_id_b, similarity, match_fields, status, created_at) VALUES (?,?,?,?,?,?,?)",
                        (pair_id, a["claim_id"], b["claim_id"], round(overall, 3),
                         json.dumps(match_fields), "pending", now_str)
                    )
                    found.append({
                        "pair_id": pair_id,
                        "claim_a": {"claim_id": a["claim_id"], "name": a["claimant_name"],
                                     "respondent": a["respondent_entity"], "amount": amt_a},
                        "claim_b": {"claim_id": b["claim_id"], "name": b["claimant_name"],
                                     "respondent": b["respondent_entity"], "amount": amt_b},
                        "similarity": round(overall, 3),
                        "match_fields": match_fields,
                    })

        conn.commit()
        conn.close()

        found.sort(key=lambda x: x["similarity"], reverse=True)
        return {
            "duplicates_found": len(found),
            "threshold": threshold,
            "total_claims_scanned": len(claims),
            "pairs": found[:50],
        }

    def get_duplicate_pairs(self, status: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get duplicate pairs with optional status filter."""
        conn = _get_db()
        query = "SELECT * FROM duplicate_pairs"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY similarity DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["match_fields"] = json.loads(d["match_fields"]) if d["match_fields"] else []
            # Enrich with claim names
            ca = conn.execute("SELECT claimant_name, respondent_entity, amount_claimed_usd FROM claims WHERE claim_id = ?", (d["claim_id_a"],)).fetchone()
            cb = conn.execute("SELECT claimant_name, respondent_entity, amount_claimed_usd FROM claims WHERE claim_id = ?", (d["claim_id_b"],)).fetchone()
            d["claim_a_name"] = ca["claimant_name"] if ca else "Unknown"
            d["claim_b_name"] = cb["claimant_name"] if cb else "Unknown"
            d["claim_a_respondent"] = ca["respondent_entity"] if ca else ""
            d["claim_b_respondent"] = cb["respondent_entity"] if cb else ""
            result.append(d)
        conn.close()
        return result

    def resolve_duplicate(self, pair_id: str, action: str, resolved_by: str = "operator") -> Optional[Dict[str, Any]]:
        """Resolve a duplicate pair: 'dismiss' (not duplicate) or 'confirm' (is duplicate)."""
        conn = _get_db()
        pair = conn.execute("SELECT * FROM duplicate_pairs WHERE pair_id = ?", (pair_id,)).fetchone()
        if not pair:
            conn.close()
            return None
        now_str = datetime.utcnow().isoformat() + "Z"
        new_status = "dismissed" if action == "dismiss" else "confirmed"
        conn.execute(
            "UPDATE duplicate_pairs SET status = ?, resolved_by = ?, resolved_at = ? WHERE pair_id = ?",
            (new_status, resolved_by, now_str, pair_id)
        )
        conn.commit()
        conn.close()
        return {"pair_id": pair_id, "status": new_status, "resolved_by": resolved_by, "resolved_at": now_str}

    def merge_claims(self, source_id: str, target_id: str, merged_by: str = "operator") -> Optional[Dict[str, Any]]:
        """Merge source claim into target claim. Moves notes, docs, tags, recoveries to target. Closes source."""
        conn = _get_db()
        source = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (source_id,)).fetchone()
        target = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (target_id,)).fetchone()
        if not source or not target:
            conn.close()
            return None

        now_str = datetime.utcnow().isoformat() + "Z"
        merged_fields = []

        # Move notes
        notes_moved = conn.execute("UPDATE notes SET claim_id = ? WHERE claim_id = ?", (target_id, source_id)).rowcount
        if notes_moved:
            merged_fields.append(f"notes:{notes_moved}")

        # Move documents
        docs_moved = conn.execute("UPDATE documents SET claim_id = ? WHERE claim_id = ?", (target_id, source_id)).rowcount
        if docs_moved:
            merged_fields.append(f"documents:{docs_moved}")

        # Move recoveries
        rec_moved = conn.execute("UPDATE recoveries SET claim_id = ? WHERE claim_id = ?", (target_id, source_id)).rowcount
        if rec_moved:
            merged_fields.append(f"recoveries:{rec_moved}")

        # Move tags (ignore conflicts)
        for tag_row in conn.execute("SELECT tag_id FROM claim_tags WHERE claim_id = ?", (source_id,)).fetchall():
            try:
                conn.execute("INSERT OR IGNORE INTO claim_tags (claim_id, tag_id, tagged_by, tagged_at) VALUES (?,?,?,?)",
                             (target_id, tag_row["tag_id"], "merge", now_str))
            except Exception:
                pass
        tags_moved = conn.execute("DELETE FROM claim_tags WHERE claim_id = ?", (source_id,)).rowcount
        if tags_moved:
            merged_fields.append(f"tags:{tags_moved}")

        # Add merge amount if source has uncaptured amount
        source_amt = source["amount_claimed_usd"] or 0
        target_amt = target["amount_claimed_usd"] or 0
        if source_amt > 0 and source_amt != target_amt:
            new_amt = max(source_amt, target_amt)
            conn.execute("UPDATE claims SET amount_claimed_usd = ? WHERE claim_id = ?", (new_amt, target_id))
            merged_fields.append(f"amount_adjusted:{new_amt}")

        # Close source claim
        conn.execute("UPDATE claims SET status = 'closed', updated_at = ? WHERE claim_id = ?", (now_str, source_id))

        # Add a note to target about the merge
        note_id = f"note_{uuid.uuid4().hex[:12]}"
        conn.execute(
            "INSERT INTO notes (note_id, claim_id, author, content, created_at) VALUES (?,?,?,?,?)",
            (note_id, target_id, merged_by,
             f"Merged claim {source_id} into this claim. Fields merged: {', '.join(merged_fields)}",
             now_str)
        )

        # Record merge history
        merge_id = f"mrg_{uuid.uuid4().hex[:12]}"
        conn.execute(
            "INSERT INTO merge_history (merge_id, source_claim_id, target_claim_id, fields_merged, merged_by, merged_at) VALUES (?,?,?,?,?,?)",
            (merge_id, source_id, target_id, json.dumps(merged_fields), merged_by, now_str)
        )

        conn.commit()
        conn.close()

        return {
            "merge_id": merge_id,
            "source_claim_id": source_id,
            "target_claim_id": target_id,
            "fields_merged": merged_fields,
            "merged_by": merged_by,
            "merged_at": now_str,
        }

    def get_data_quality_report(self) -> Dict[str, Any]:
        """Overall data quality report: missing fields, completeness scores, issues."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        if total == 0:
            conn.close()
            return {"total_claims": 0, "quality_score": 100, "issues": []}

        # Check key fields for completeness
        missing_email = conn.execute("SELECT COUNT(*) FROM claims WHERE claimant_email IS NULL OR claimant_email = ''").fetchone()[0]
        missing_respondent = conn.execute("SELECT COUNT(*) FROM claims WHERE respondent_entity IS NULL OR respondent_entity = ''").fetchone()[0]
        missing_amount = conn.execute("SELECT COUNT(*) FROM claims WHERE amount_claimed_usd IS NULL OR amount_claimed_usd = 0").fetchone()[0]
        missing_harm = conn.execute("SELECT COUNT(*) FROM claims WHERE harm_type IS NULL OR harm_type = ''").fetchone()[0]
        missing_desc = conn.execute("SELECT COUNT(*) FROM claims WHERE description IS NULL OR description = ''").fetchone()[0]

        # Duplicate stats
        pending_dups = conn.execute("SELECT COUNT(*) FROM duplicate_pairs WHERE status = 'pending'").fetchone()[0]
        confirmed_dups = conn.execute("SELECT COUNT(*) FROM duplicate_pairs WHERE status = 'confirmed'").fetchone()[0]
        total_merges = conn.execute("SELECT COUNT(*) FROM merge_history").fetchone()[0]

        # Unassigned claims
        unassigned = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE claim_id NOT IN (SELECT claim_id FROM assignments) AND status NOT IN ('closed','resolved','withdrawn','rejected')"
        ).fetchone()[0]

        # Untagged claims
        untagged = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE claim_id NOT IN (SELECT DISTINCT claim_id FROM claim_tags)"
        ).fetchone()[0]

        # No documents
        undocumented = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE claim_id NOT IN (SELECT DISTINCT claim_id FROM documents)"
        ).fetchone()[0]

        conn.close()

        issues = []
        if missing_email > 0:
            issues.append({"field": "email", "missing": missing_email, "severity": "warning"})
        if missing_respondent > 0:
            issues.append({"field": "respondent", "missing": missing_respondent, "severity": "critical"})
        if missing_amount > 0:
            issues.append({"field": "amount", "missing": missing_amount, "severity": "critical"})
        if missing_harm > 0:
            issues.append({"field": "harm_type", "missing": missing_harm, "severity": "warning"})
        if pending_dups > 0:
            issues.append({"field": "duplicates", "missing": pending_dups, "severity": "warning"})

        # Quality score (0-100)
        completeness = 1 - (
            (missing_email + missing_respondent + missing_amount + missing_harm + missing_desc) /
            (total * 5)
        )
        dup_penalty = min(pending_dups * 2, 15) / 100
        quality_score = round(max(0, min(100, completeness * 100 - dup_penalty * 100)), 1)

        return {
            "total_claims": total,
            "quality_score": quality_score,
            "completeness": {
                "email": round((total - missing_email) / total * 100, 1),
                "respondent": round((total - missing_respondent) / total * 100, 1),
                "amount": round((total - missing_amount) / total * 100, 1),
                "harm_type": round((total - missing_harm) / total * 100, 1),
                "description": round((total - missing_desc) / total * 100, 1),
            },
            "duplicates": {
                "pending": pending_dups,
                "confirmed": confirmed_dups,
                "total_merges": total_merges,
            },
            "coverage": {
                "assigned": total - unassigned,
                "unassigned": unassigned,
                "tagged": total - untagged,
                "untagged": untagged,
                "documented": total - undocumented,
                "undocumented": undocumented,
            },
            "issues": issues,
        }

    # ── Claim Timeline & Activity Stream Methods ──

    def get_claim_timeline(self, claim_id: str, limit: int = 100, event_type: str = None) -> Dict[str, Any]:
        """Build a unified chronological timeline for a single claim."""
        conn = _get_db()

        # Verify claim exists
        claim = conn.execute("SELECT claim_id, claimant_name, status FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            return {"error": "claim_not_found"}

        events = []

        # 1. Notes
        for r in conn.execute(
            "SELECT note_id, content, author, created_at FROM notes WHERE claim_id = ? ORDER BY created_at",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "note",
                "event_id": r["note_id"],
                "timestamp": r["created_at"],
                "actor": r["author"] or "system",
                "summary": (r["content"] or "")[:120],
                "detail": r["content"],
                "icon": "note",
            })

        # 2. Audit log entries (detail is JSON blob, may contain claim_id)
        for r in conn.execute(
            "SELECT audit_id, action, actor, detail, timestamp FROM audit_log ORDER BY timestamp"
        ).fetchall():
            try:
                detail_data = json.loads(r["detail"]) if r["detail"] else {}
            except (json.JSONDecodeError, TypeError):
                detail_data = {}
            # Filter: only include if detail contains this claim_id
            detail_str = json.dumps(detail_data)
            if claim_id not in detail_str:
                continue
            summary = f"{r['action']}"
            if isinstance(detail_data, dict):
                for k in ("field", "status", "claim_id"):
                    if k in detail_data and k != "claim_id":
                        summary += f" {detail_data[k]}"
            events.append({
                "event_type": "audit",
                "event_id": r["audit_id"],
                "timestamp": r["timestamp"],
                "actor": r["actor"] or "system",
                "summary": summary[:150],
                "detail": detail_data,
                "icon": "audit",
            })

        # 3. Recoveries
        for r in conn.execute(
            "SELECT recovery_id, amount_recovered, recovery_method, recovered_by, recorded_at FROM recoveries WHERE claim_id = ? ORDER BY recorded_at",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "recovery",
                "event_id": r["recovery_id"],
                "timestamp": r["recorded_at"],
                "actor": r["recovered_by"] or "system",
                "summary": f"${r['amount_recovered']:,.2f} recovered via {r['recovery_method']}",
                "detail": {"amount": r["amount_recovered"], "method": r["recovery_method"]},
                "icon": "recovery",
            })

        # 4. Settlements
        for r in conn.execute(
            "SELECT settlement_id, offered_by, amount_offered, status, created_at FROM settlements WHERE claim_id = ? ORDER BY created_at",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "settlement",
                "event_id": r["settlement_id"],
                "timestamp": r["created_at"],
                "actor": r["offered_by"] or "system",
                "summary": f"Settlement {r['status']}: ${r['amount_offered']:,.2f}",
                "detail": dict(r),
                "icon": "settlement",
            })

        # 5. Outreach
        for r in conn.execute(
            "SELECT outreach_id, channel, recipient, status, sent_at FROM outreach_log WHERE claim_id = ? ORDER BY sent_at",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "outreach",
                "event_id": r["outreach_id"],
                "timestamp": r["sent_at"],
                "actor": "system",
                "summary": f"{r['channel']} to {r['recipient']}: {r['status']}",
                "detail": dict(r),
                "icon": "outreach",
            })

        # 6. Triage actions
        for r in conn.execute(
            "SELECT action_id, action_type, previous_value, new_value, reason, performed_by, created_at FROM triage_actions WHERE claim_id = ? ORDER BY created_at",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "triage",
                "event_id": r["action_id"],
                "timestamp": r["created_at"],
                "actor": r["performed_by"] or "system",
                "summary": f"Triage {r['action_type']}: {r['previous_value'] or ''} → {r['new_value'] or ''}",
                "detail": {"reason": r["reason"]},
                "icon": "triage",
            })

        # 7. Tag events
        for r in conn.execute(
            "SELECT ct.tag_id, t.name, ct.tagged_by, ct.tagged_at FROM claim_tags ct JOIN tags t ON ct.tag_id = t.tag_id WHERE ct.claim_id = ?",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "tag_added",
                "event_id": f"tag_{r['tag_id']}",
                "timestamp": r["tagged_at"],
                "actor": r["tagged_by"] or "system",
                "summary": f"Tagged: {r['name']}",
                "detail": {"tag": r["name"]},
                "icon": "tag",
            })

        # 8. Documents
        for r in conn.execute(
            "SELECT document_id, filename, file_type, uploaded_by, created_at FROM documents WHERE claim_id = ? ORDER BY created_at",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "document",
                "event_id": r["document_id"],
                "timestamp": r["created_at"],
                "actor": r["uploaded_by"] or "system",
                "summary": f"Document uploaded: {r['filename']} ({r['file_type']})",
                "detail": {"filename": r["filename"], "type": r["file_type"]},
                "icon": "document",
            })

        # 9. Case group membership
        for r in conn.execute(
            "SELECT cg.group_id, cg.name, cl.linked_at, cl.linked_by FROM claim_links cl JOIN case_groups cg ON cl.group_id = cg.group_id WHERE cl.claim_id = ?",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "group_added",
                "event_id": f"grp_{r['group_id']}",
                "timestamp": r["linked_at"],
                "actor": r["linked_by"] or "system",
                "summary": f"Added to group: {r['name']}",
                "detail": {"group": r["name"]},
                "icon": "group",
            })

        # 10. Merge history (as target)
        for r in conn.execute(
            "SELECT merge_id, source_claim_id, fields_merged, merged_by, merged_at FROM merge_history WHERE target_claim_id = ?",
            (claim_id,)
        ).fetchall():
            events.append({
                "event_type": "merge_received",
                "event_id": r["merge_id"],
                "timestamp": r["merged_at"],
                "actor": r["merged_by"] or "system",
                "summary": f"Merged from {r['source_claim_id'][:12]}",
                "detail": {"source": r["source_claim_id"], "fields": r["fields_merged"]},
                "icon": "merge",
            })

        conn.close()

        # Filter by type if requested
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]

        # Sort chronologically (newest first)
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

        # Apply limit
        events = events[:limit]

        # Compute timeline stats
        type_counts = {}
        for e in events:
            t = e["event_type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "claim_id": claim_id,
            "claim_name": claim["claimant_name"],
            "total_events": len(events),
            "event_types": type_counts,
            "events": events,
        }

    def get_global_activity_feed(self, limit: int = 50, event_type: str = None, hours: int = 72) -> Dict[str, Any]:
        """Global activity feed across all claims for the dashboard."""
        conn = _get_db()
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
        events = []

        # Recent notes
        for r in conn.execute(
            "SELECT cn.note_id, cn.claim_id, cn.content, cn.author, cn.created_at, c.claimant_name "
            "FROM notes cn JOIN claims c ON cn.claim_id = c.claim_id "
            "WHERE cn.created_at >= ? ORDER BY cn.created_at DESC LIMIT ?",
            (cutoff, limit)
        ).fetchall():
            events.append({
                "event_type": "note", "event_id": r["note_id"],
                "claim_id": r["claim_id"], "claim_name": r["claimant_name"],
                "timestamp": r["created_at"], "actor": r["author"] or "system",
                "summary": (r["content"] or "")[:100], "icon": "note",
            })

        # Recent audit events (detail is JSON blob, may contain claim_id)
        for r in conn.execute(
            "SELECT audit_id, action, actor, detail, timestamp FROM audit_log "
            "WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
            (cutoff, limit)
        ).fetchall():
            try:
                detail_data = json.loads(r["detail"]) if r["detail"] else {}
            except (json.JSONDecodeError, TypeError):
                detail_data = {}
            # Try to extract claim_id from detail
            a_claim_id = detail_data.get("claim_id", "") if isinstance(detail_data, dict) else ""
            claim_name = ""
            if a_claim_id:
                cr = conn.execute("SELECT claimant_name FROM claims WHERE claim_id = ?", (a_claim_id,)).fetchone()
                claim_name = cr["claimant_name"] if cr else ""
            events.append({
                "event_type": "audit", "event_id": r["audit_id"],
                "claim_id": a_claim_id, "claim_name": claim_name,
                "timestamp": r["timestamp"], "actor": r["actor"] or "system",
                "summary": f"{r['action']}"[:100], "icon": "audit",
            })

        # Recent recoveries
        for r in conn.execute(
            "SELECT rv.recovery_id, rv.claim_id, rv.amount_recovered, rv.recovery_method, rv.recovered_by, rv.recorded_at, c.claimant_name "
            "FROM recoveries rv JOIN claims c ON rv.claim_id = c.claim_id "
            "WHERE rv.recorded_at >= ? ORDER BY rv.recorded_at DESC LIMIT ?",
            (cutoff, limit)
        ).fetchall():
            events.append({
                "event_type": "recovery", "event_id": r["recovery_id"],
                "claim_id": r["claim_id"], "claim_name": r["claimant_name"],
                "timestamp": r["recorded_at"], "actor": r["recovered_by"] or "system",
                "summary": f"${r['amount_recovered']:,.2f} via {r['recovery_method']}", "icon": "recovery",
            })

        # Recent settlements
        for r in conn.execute(
            "SELECT s.settlement_id, s.claim_id, s.amount_offered, s.status, s.created_at, c.claimant_name "
            "FROM settlements s JOIN claims c ON s.claim_id = c.claim_id "
            "WHERE s.created_at >= ? ORDER BY s.created_at DESC LIMIT ?",
            (cutoff, limit)
        ).fetchall():
            events.append({
                "event_type": "settlement", "event_id": r["settlement_id"],
                "claim_id": r["claim_id"], "claim_name": r["claimant_name"],
                "timestamp": r["created_at"], "actor": "system",
                "summary": f"Settlement {r['status']}: ${r['amount_offered']:,.2f}", "icon": "settlement",
            })

        conn.close()

        # Filter
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]

        # Sort & limit
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        events = events[:limit]

        type_counts = {}
        for e in events:
            t = e["event_type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_events": len(events),
            "event_types": type_counts,
            "hours_window": hours,
            "events": events,
        }

    # ── Financial Reconciliation Methods ──

    def get_financial_summary(self) -> Dict[str, Any]:
        """Comprehensive financial reconciliation summary."""
        conn = _get_db()
        claimed_row = conn.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(amount_claimed_usd), 0) as total FROM claims").fetchone()
        total_claims = claimed_row[0]
        total_claimed = round(claimed_row[1], 2)

        rec_row = conn.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(amount_recovered), 0) as total FROM recoveries").fetchone()
        total_recoveries = rec_row[0]
        total_recovered = round(rec_row[1], 2)

        settled_row = conn.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(amount_offered), 0) as total FROM settlements WHERE status = 'accepted'").fetchone()
        total_settled_count = settled_row[0]
        total_settled = round(settled_row[1], 2)

        pending_row = conn.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(amount_offered), 0) as total FROM settlements WHERE status = 'pending'").fetchone()
        pending_count = pending_row[0]
        pending_amount = round(pending_row[1], 2)

        by_method = {}
        for row in conn.execute("SELECT recovery_method, COUNT(*) as cnt, SUM(amount_recovered) as total FROM recoveries GROUP BY recovery_method").fetchall():
            by_method[row[0]] = {"count": row[1], "amount": round(row[2], 2)}

        gap = round(total_claimed - total_recovered - total_settled, 2)
        recovery_rate = round((total_recovered + total_settled) / total_claimed * 100, 1) if total_claimed > 0 else 0

        by_status = {}
        for row in conn.execute("SELECT status, COUNT(*) as cnt, SUM(amount_claimed_usd) as total FROM claims GROUP BY status").fetchall():
            by_status[row[0]] = {"count": row[1], "amount": round(row[2] or 0, 2)}

        conn.close()
        return {
            "total_claims": total_claims,
            "total_claimed_usd": total_claimed,
            "total_recovered_usd": total_recovered,
            "total_recoveries": total_recoveries,
            "total_settled_usd": total_settled,
            "total_settled_count": total_settled_count,
            "pending_settlements_usd": pending_amount,
            "pending_settlements_count": pending_count,
            "outstanding_gap_usd": gap,
            "overall_recovery_rate_pct": recovery_rate,
            "recovery_by_method": by_method,
            "claims_by_status": by_status,
        }

    def get_financial_by_respondent(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Financial breakdown by respondent entity."""
        conn = _get_db()
        respondents = conn.execute("""
            SELECT respondent_entity, COUNT(*) as claim_count, SUM(amount_claimed_usd) as total_claimed
            FROM claims WHERE respondent_entity IS NOT NULL AND respondent_entity != ''
            GROUP BY respondent_entity ORDER BY total_claimed DESC LIMIT ?
        """, (limit,)).fetchall()

        results = []
        for r in respondents:
            entity = r[0]
            claimed = round(r[2] or 0, 2)
            rec = conn.execute("""
                SELECT COALESCE(SUM(rv.amount_recovered), 0)
                FROM recoveries rv JOIN claims c ON rv.claim_id = c.claim_id
                WHERE c.respondent_entity = ?
            """, (entity,)).fetchone()
            recovered = round(rec[0], 2)
            stl = conn.execute("""
                SELECT COALESCE(SUM(s.amount_offered), 0)
                FROM settlements s JOIN claims c ON s.claim_id = c.claim_id
                WHERE c.respondent_entity = ? AND s.status = 'accepted'
            """, (entity,)).fetchone()
            settled = round(stl[0], 2)
            gap = round(claimed - recovered - settled, 2)
            rate = round((recovered + settled) / claimed * 100, 1) if claimed > 0 else 0
            results.append({
                "respondent_entity": entity, "claim_count": r[1],
                "total_claimed_usd": claimed, "total_recovered_usd": recovered,
                "total_settled_usd": settled, "outstanding_gap_usd": gap,
                "recovery_rate_pct": rate,
            })
        conn.close()
        return results

    def get_financial_trends(self, days: int = 90) -> Dict[str, Any]:
        """Financial trends over time — claimed, recovered, settled per day."""
        conn = _get_db()
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"

        claims_by_day = {}
        for row in conn.execute("""
            SELECT substr(filed_at, 1, 10) as day, COUNT(*) as cnt, SUM(amount_claimed_usd) as total
            FROM claims WHERE filed_at >= ? GROUP BY day ORDER BY day
        """, (cutoff,)).fetchall():
            claims_by_day[row[0]] = {"count": row[1], "amount": round(row[2] or 0, 2)}

        recoveries_by_day = {}
        for row in conn.execute("""
            SELECT substr(recorded_at, 1, 10) as day, COUNT(*) as cnt, SUM(amount_recovered) as total
            FROM recoveries WHERE recorded_at >= ? GROUP BY day ORDER BY day
        """, (cutoff,)).fetchall():
            recoveries_by_day[row[0]] = {"count": row[1], "amount": round(row[2] or 0, 2)}

        settlements_by_day = {}
        for row in conn.execute("""
            SELECT substr(created_at, 1, 10) as day, COUNT(*) as cnt, SUM(amount_offered) as total
            FROM settlements WHERE status = 'accepted' AND created_at >= ? GROUP BY day ORDER BY day
        """, (cutoff,)).fetchall():
            settlements_by_day[row[0]] = {"count": row[1], "amount": round(row[2] or 0, 2)}

        all_days = sorted(set(list(claims_by_day.keys()) + list(recoveries_by_day.keys()) + list(settlements_by_day.keys())))
        timeline = []
        for d in all_days:
            c = claims_by_day.get(d, {"count": 0, "amount": 0})
            r = recoveries_by_day.get(d, {"count": 0, "amount": 0})
            s = settlements_by_day.get(d, {"count": 0, "amount": 0})
            timeline.append({
                "date": d, "claimed": c["amount"], "claimed_count": c["count"],
                "recovered": r["amount"], "recovered_count": r["count"],
                "settled": s["amount"], "settled_count": s["count"],
            })
        conn.close()
        return {"days": days, "periods": len(timeline), "timeline": timeline}

    def get_financial_gaps(self, min_gap: float = 0) -> List[Dict[str, Any]]:
        """Claims with largest outstanding financial gaps."""
        conn = _get_db()
        claims = conn.execute("""
            SELECT c.claim_id, c.claimant_name, c.respondent_entity,
                   c.amount_claimed_usd, c.status, c.filed_at,
                   COALESCE((SELECT SUM(r.amount_recovered) FROM recoveries r WHERE r.claim_id = c.claim_id), 0) as recovered,
                   COALESCE((SELECT SUM(s.amount_offered) FROM settlements s WHERE s.claim_id = c.claim_id AND s.status = 'accepted'), 0) as settled
            FROM claims c WHERE c.status NOT IN ('dismissed', 'closed')
            ORDER BY c.amount_claimed_usd DESC
        """).fetchall()

        results = []
        for c in claims:
            claimed = round(c[3] or 0, 2)
            recovered = round(c[6], 2)
            settled = round(c[7], 2)
            gap = round(claimed - recovered - settled, 2)
            if gap >= min_gap:
                results.append({
                    "claim_id": c[0], "claimant_name": c[1], "respondent_entity": c[2],
                    "amount_claimed_usd": claimed, "amount_recovered_usd": recovered,
                    "amount_settled_usd": settled, "outstanding_gap_usd": gap,
                    "recovery_pct": round((recovered + settled) / claimed * 100, 1) if claimed > 0 else 0,
                    "status": c[4], "filed_at": c[5],
                })
        conn.close()
        results.sort(key=lambda x: x["outstanding_gap_usd"], reverse=True)
        return results[:50]

    # ── Claim Scoring & Risk Assessment Methods ──

    RISK_TIERS = {"critical": (80, 100), "high": (60, 79), "medium": (30, 59), "low": (0, 29)}
    RISK_TIER_COLORS = {"critical": "#f85149", "high": "#f0883e", "medium": "#d29922", "low": "#3fb950"}

    def _calculate_claim_risk(self, claim_id: str, conn=None) -> Dict[str, Any]:
        """Calculate risk score for a single claim (0-100). Higher = riskier."""
        close_conn = False
        if conn is None:
            conn = _get_db()
            close_conn = True

        claim = conn.execute("""
            SELECT claim_id, amount_claimed_usd, status, vertical, respondent_entity,
                   filed_at, harm_type
            FROM claims WHERE claim_id = ?
        """, (claim_id,)).fetchone()
        if not claim:
            if close_conn:
                conn.close()
            return {"claim_id": claim_id, "score": 0, "tier": "low", "factors": [], "error": "not_found"}

        factors = []
        score = 0

        # Factor 1: Financial exposure (0-25 points)
        amount = claim[1] or 0
        if amount >= 50000:
            score += 25; factors.append({"name": "financial_exposure", "points": 25, "detail": f"${amount:,.2f} (very high)"})
        elif amount >= 25000:
            score += 20; factors.append({"name": "financial_exposure", "points": 20, "detail": f"${amount:,.2f} (high)"})
        elif amount >= 10000:
            score += 15; factors.append({"name": "financial_exposure", "points": 15, "detail": f"${amount:,.2f} (significant)"})
        elif amount >= 5000:
            score += 10; factors.append({"name": "financial_exposure", "points": 10, "detail": f"${amount:,.2f} (moderate)"})
        elif amount >= 1000:
            score += 5; factors.append({"name": "financial_exposure", "points": 5, "detail": f"${amount:,.2f} (low)"})

        # Factor 2: Claim age — older claims are riskier (0-20 points)
        filed_at = claim[5] or ""
        if filed_at:
            try:
                filed_dt = datetime.fromisoformat(filed_at.replace("Z", "+00:00").replace("+00:00", ""))
                age_days = (datetime.utcnow() - filed_dt).days
                if age_days >= 90:
                    score += 20; factors.append({"name": "claim_age", "points": 20, "detail": f"{age_days} days (stale)"})
                elif age_days >= 60:
                    score += 15; factors.append({"name": "claim_age", "points": 15, "detail": f"{age_days} days (aging)"})
                elif age_days >= 30:
                    score += 10; factors.append({"name": "claim_age", "points": 10, "detail": f"{age_days} days (maturing)"})
                elif age_days >= 14:
                    score += 5; factors.append({"name": "claim_age", "points": 5, "detail": f"{age_days} days"})
            except Exception:
                pass

        # Factor 3: Status risk (0-15 points)
        status = claim[2] or ""
        status_scores = {"escalated": 15, "under_review": 10, "filed": 5, "resolved": 0, "closed": 0, "rejected": 0}
        s_pts = status_scores.get(status, 5)
        if s_pts > 0:
            score += s_pts
            factors.append({"name": "status_risk", "points": s_pts, "detail": f"Status: {status}"})

        # Factor 4: Respondent history (0-20 points)
        respondent = claim[4] or ""
        if respondent:
            resp_claims = conn.execute(
                "SELECT COUNT(*), AVG(amount_claimed_usd) FROM claims WHERE respondent_entity = ?",
                (respondent,)).fetchone()
            resp_count = resp_claims[0] or 0
            if resp_count >= 10:
                score += 20; factors.append({"name": "respondent_history", "points": 20, "detail": f"{respondent}: {resp_count} claims (repeat offender)"})
            elif resp_count >= 5:
                score += 15; factors.append({"name": "respondent_history", "points": 15, "detail": f"{respondent}: {resp_count} claims (frequent)"})
            elif resp_count >= 3:
                score += 10; factors.append({"name": "respondent_history", "points": 10, "detail": f"{respondent}: {resp_count} claims"})
            # Check recovery rate for respondent
            rec = conn.execute("""
                SELECT COALESCE(SUM(r.amount_recovered), 0)
                FROM recoveries r JOIN claims c ON r.claim_id = c.claim_id
                WHERE c.respondent_entity = ?
            """, (respondent,)).fetchone()
            total_claimed = conn.execute(
                "SELECT COALESCE(SUM(amount_claimed_usd), 0) FROM claims WHERE respondent_entity = ?",
                (respondent,)).fetchone()
            if total_claimed[0] > 0:
                recovery_rate = (rec[0] / total_claimed[0]) * 100
                if recovery_rate < 5:
                    score += 5
                    factors.append({"name": "low_recovery_entity", "points": 5, "detail": f"{respondent} recovery rate: {recovery_rate:.1f}%"})

        # Factor 5: Compliance failures (0-10 points)
        try:
            comp_failed = conn.execute(
                "SELECT COUNT(*) FROM compliance_checks WHERE claim_id = ? AND status = 'failed'",
                (claim_id,)).fetchone()[0]
            if comp_failed >= 3:
                score += 10; factors.append({"name": "compliance_failures", "points": 10, "detail": f"{comp_failed} failed checks"})
            elif comp_failed >= 1:
                score += 5; factors.append({"name": "compliance_failures", "points": 5, "detail": f"{comp_failed} failed check(s)"})
        except Exception:
            pass

        # Factor 6: No recovery progress (0-10 points)
        recoveries = conn.execute(
            "SELECT COALESCE(SUM(amount_recovered), 0) FROM recoveries WHERE claim_id = ?",
            (claim_id,)).fetchone()[0]
        if amount > 0 and recoveries == 0 and status not in ("resolved", "closed", "rejected"):
            score += 10
            factors.append({"name": "no_recovery", "points": 10, "detail": "Zero recovery on open claim"})

        score = min(score, 100)
        tier = "low"
        for t, (lo, hi) in self.RISK_TIERS.items():
            if lo <= score <= hi:
                tier = t
                break

        if close_conn:
            conn.close()

        return {
            "claim_id": claim_id, "score": score, "tier": tier,
            "amount_claimed_usd": amount, "status": status,
            "respondent_entity": respondent, "factors": factors,
        }

    def get_claim_risk(self, claim_id: str) -> Dict[str, Any]:
        """Get risk assessment for a single claim."""
        return self._calculate_claim_risk(claim_id)

    def get_risk_dashboard(self) -> Dict[str, Any]:
        """Calculate risk scores for all open claims and return summary + top risks."""
        conn = _get_db()
        claims = conn.execute("""
            SELECT claim_id FROM claims
            WHERE status NOT IN ('resolved', 'closed', 'rejected')
            ORDER BY amount_claimed_usd DESC
            LIMIT 200
        """).fetchall()

        all_risks = []
        tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_score = 0

        for c in claims:
            risk = self._calculate_claim_risk(c[0], conn=conn)
            all_risks.append(risk)
            tier_counts[risk["tier"]] = tier_counts.get(risk["tier"], 0) + 1
            total_score += risk["score"]

        conn.close()

        all_risks.sort(key=lambda x: x["score"], reverse=True)
        avg_score = round(total_score / len(all_risks)) if all_risks else 0
        avg_tier = "low"
        for t, (lo, hi) in self.RISK_TIERS.items():
            if lo <= avg_score <= hi:
                avg_tier = t
                break

        return {
            "total_assessed": len(all_risks),
            "avg_risk_score": avg_score,
            "avg_tier": avg_tier,
            "tier_distribution": tier_counts,
            "top_risks": all_risks[:15],
            "risk_tiers": self.RISK_TIERS,
        }

    def get_risk_by_respondent(self, limit: int = 15) -> Dict[str, Any]:
        """Average risk score per respondent entity."""
        conn = _get_db()
        respondents = conn.execute("""
            SELECT respondent_entity, COUNT(*) as cnt
            FROM claims WHERE status NOT IN ('resolved', 'closed', 'rejected')
            GROUP BY respondent_entity HAVING cnt >= 1
            ORDER BY cnt DESC LIMIT ?
        """, (limit,)).fetchall()

        results = []
        for r in respondents:
            entity = r[0]
            claim_ids = conn.execute(
                "SELECT claim_id FROM claims WHERE respondent_entity = ? AND status NOT IN ('resolved','closed','rejected')",
                (entity,)).fetchall()
            scores = []
            for cid in claim_ids:
                risk = self._calculate_claim_risk(cid[0], conn=conn)
                scores.append(risk["score"])
            avg = round(sum(scores) / len(scores)) if scores else 0
            tier = "low"
            for t, (lo, hi) in self.RISK_TIERS.items():
                if lo <= avg <= hi:
                    tier = t
                    break
            results.append({
                "respondent_entity": entity, "open_claims": len(claim_ids),
                "avg_risk_score": avg, "tier": tier,
                "max_score": max(scores) if scores else 0,
            })
        conn.close()
        results.sort(key=lambda x: x["avg_risk_score"], reverse=True)
        return {"respondents": results, "total": len(results)}

    # ── Settlement Negotiation Tracker Methods ──

    NEG_STATUSES = ["pending", "countered", "accepted", "rejected", "expired", "withdrawn"]
    NEG_INITIATORS = ["claimant", "respondent", "mediator", "platform"]

    def create_negotiation_round(self, claim_id: str, offer_amount: float,
                                  initiated_by: str = "claimant", terms: str = "",
                                  deadline: str = None,
                                  created_by: str = "operator") -> Dict[str, Any]:
        """Create a new negotiation round for a claim."""
        conn = _get_db()
        claim = conn.execute("SELECT claim_id, respondent_entity, amount_claimed_usd FROM claims WHERE claim_id = ?",
                             (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        # Get next round number
        last_round = conn.execute(
            "SELECT MAX(round_number) FROM negotiations WHERE claim_id = ?",
            (claim_id,)).fetchone()[0]
        round_num = (last_round or 0) + 1
        neg_id = f"NEG-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute("""
            INSERT INTO negotiations
            (negotiation_id, claim_id, round_number, initiated_by, offer_amount,
             terms, status, deadline, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
        """, (neg_id, claim_id, round_num, initiated_by, offer_amount,
              terms.strip(), deadline, created_by, now))
        conn.commit()
        conn.close()
        self.audit("negotiation_created", {"negotiation_id": neg_id, "claim_id": claim_id,
                                            "round": round_num, "offer": offer_amount}, created_by)
        return {"negotiation_id": neg_id, "claim_id": claim_id, "round_number": round_num,
                "initiated_by": initiated_by, "offer_amount": offer_amount,
                "status": "pending", "created_at": now}

    def get_claim_negotiations(self, claim_id: str) -> Dict[str, Any]:
        """Get all negotiation rounds for a claim."""
        conn = _get_db()
        rows = conn.execute("""
            SELECT * FROM negotiations WHERE claim_id = ?
            ORDER BY round_number ASC
        """, (claim_id,)).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM negotiations LIMIT 0").description]
        claim = conn.execute("SELECT respondent_entity, amount_claimed_usd FROM claims WHERE claim_id = ?",
                             (claim_id,)).fetchone()
        conn.close()
        rounds = [dict(zip(cols, r)) for r in rows]
        latest_offer = rounds[-1]["offer_amount"] if rounds else 0
        latest_counter = rounds[-1].get("counter_amount") if rounds else None
        claimed = claim[1] if claim else 0
        return {
            "claim_id": claim_id, "respondent": claim[0] if claim else "",
            "amount_claimed": claimed,
            "rounds": rounds, "total_rounds": len(rounds),
            "latest_offer": latest_offer, "latest_counter": latest_counter,
            "current_status": rounds[-1]["status"] if rounds else "none",
        }

    def counter_negotiation(self, negotiation_id: str, counter_amount: float,
                             response_note: str = "",
                             responded_by: str = "respondent") -> Dict[str, Any]:
        """Counter an existing negotiation offer."""
        conn = _get_db()
        neg = conn.execute("SELECT * FROM negotiations WHERE negotiation_id = ?",
                           (negotiation_id,)).fetchone()
        if not neg:
            conn.close()
            raise HTTPException(status_code=404, detail="Negotiation round not found")
        cols = [d[0] for d in conn.execute("SELECT * FROM negotiations LIMIT 0").description]
        nd = dict(zip(cols, neg))
        if nd["status"] != "pending":
            conn.close()
            raise HTTPException(status_code=400, detail=f"Cannot counter a {nd['status']} negotiation")
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute("""
            UPDATE negotiations SET status = 'countered', counter_amount = ?,
            response_note = ?, responded_by = ?, responded_at = ?, updated_at = ?
            WHERE negotiation_id = ?
        """, (counter_amount, response_note.strip(), responded_by, now, now, negotiation_id))
        conn.commit()
        conn.close()
        self.audit("negotiation_countered", {"negotiation_id": negotiation_id,
                                              "counter": counter_amount}, responded_by)
        return {"negotiation_id": negotiation_id, "status": "countered",
                "counter_amount": counter_amount, "responded_at": now}

    def resolve_negotiation(self, negotiation_id: str, status: str,
                             response_note: str = "",
                             responded_by: str = "operator") -> Dict[str, Any]:
        """Accept, reject, or withdraw a negotiation."""
        if status not in ("accepted", "rejected", "expired", "withdrawn"):
            raise HTTPException(status_code=400, detail="status must be accepted, rejected, expired, or withdrawn")
        conn = _get_db()
        neg = conn.execute("SELECT negotiation_id, status, claim_id, offer_amount, counter_amount FROM negotiations WHERE negotiation_id = ?",
                           (negotiation_id,)).fetchone()
        if not neg:
            conn.close()
            raise HTTPException(status_code=404, detail="Negotiation round not found")
        if neg[1] in ("accepted", "rejected", "expired", "withdrawn"):
            conn.close()
            raise HTTPException(status_code=400, detail=f"Negotiation already {neg[1]}")
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute("""
            UPDATE negotiations SET status = ?, response_note = ?,
            responded_by = ?, responded_at = ?, updated_at = ?
            WHERE negotiation_id = ?
        """, (status, response_note.strip(), responded_by, now, now, negotiation_id))
        conn.commit()
        conn.close()
        self.audit("negotiation_resolved", {"negotiation_id": negotiation_id,
                                             "status": status, "claim_id": neg[2]}, responded_by)
        return {"negotiation_id": negotiation_id, "status": status,
                "claim_id": neg[2], "resolved_at": now}

    def get_negotiation_stats(self) -> Dict[str, Any]:
        """Get overall negotiation statistics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM negotiations").fetchone()[0]
        by_status = {}
        for row in conn.execute("SELECT status, COUNT(*) FROM negotiations GROUP BY status").fetchall():
            by_status[row[0]] = row[1]
        active_claims = conn.execute(
            "SELECT COUNT(DISTINCT claim_id) FROM negotiations WHERE status IN ('pending','countered')").fetchone()[0]
        avg_rounds = conn.execute("""
            SELECT AVG(max_round) FROM (
                SELECT claim_id, MAX(round_number) as max_round
                FROM negotiations GROUP BY claim_id
            )
        """).fetchone()[0]
        # Total offer amounts
        total_offered = conn.execute(
            "SELECT COALESCE(SUM(offer_amount), 0) FROM negotiations").fetchone()[0]
        total_accepted = conn.execute(
            "SELECT COALESCE(SUM(COALESCE(counter_amount, offer_amount)), 0) FROM negotiations WHERE status = 'accepted'").fetchone()[0]
        # Claims with accepted negotiations
        accepted_claims = conn.execute(
            "SELECT COUNT(DISTINCT claim_id) FROM negotiations WHERE status = 'accepted'").fetchone()[0]
        conn.close()
        return {
            "total_rounds": total, "by_status": by_status,
            "active_negotiations": active_claims,
            "avg_rounds_per_claim": round(avg_rounds, 1) if avg_rounds else 0,
            "total_offered_usd": round(total_offered, 2),
            "total_accepted_usd": round(total_accepted, 2),
            "accepted_claims": accepted_claims,
        }

    # ── Claim Watchlist & Operator Bookmarks Methods ──

    WATCH_COLORS = ["#58a6ff", "#f85149", "#3fb950", "#d29922", "#f0883e",
                    "#d2a8ff", "#ff7b72", "#79c0ff", "#7ee787", "#e3b341"]

    def add_to_watchlist(self, claim_id: str, operator_id: str, label: str = "",
                         notes: str = "", priority: str = "normal",
                         color: str = "#58a6ff", notify: bool = True) -> Dict[str, Any]:
        """Add a claim to an operator's watchlist."""
        conn = _get_db()
        claim = conn.execute("SELECT claim_id, respondent_entity, amount_claimed_usd, status FROM claims WHERE claim_id = ?",
                             (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        # Check if already watching
        existing = conn.execute("SELECT watch_id FROM watchlist WHERE claim_id = ? AND operator_id = ?",
                                (claim_id, operator_id)).fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=409, detail="Claim already on watchlist")
        watch_id = f"WL-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute("""
            INSERT INTO watchlist (watch_id, claim_id, operator_id, label, notes,
                                   priority, color, notify, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (watch_id, claim_id, operator_id, label.strip(), notes.strip(),
              priority, color, 1 if notify else 0, now))
        conn.commit()
        conn.close()
        self.audit("watchlist_added", {"watch_id": watch_id, "claim_id": claim_id}, operator_id)
        return {"watch_id": watch_id, "claim_id": claim_id, "operator_id": operator_id,
                "label": label, "priority": priority, "color": color, "created_at": now}

    def get_watchlist(self, operator_id: str, priority: str = None) -> Dict[str, Any]:
        """Get an operator's watchlist with enriched claim data."""
        conn = _get_db()
        sql = """
            SELECT w.*, c.respondent_entity, c.amount_claimed_usd, c.status, c.vertical, c.filed_at
            FROM watchlist w JOIN claims c ON w.claim_id = c.claim_id
            WHERE w.operator_id = ?
        """
        params = [operator_id]
        if priority:
            sql += " AND w.priority = ?"
            params.append(priority)
        sql += " ORDER BY CASE w.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, w.created_at DESC"
        rows = conn.execute(sql, params).fetchall()
        cols = ["watch_id", "claim_id", "operator_id", "label", "notes", "priority",
                "color", "notify", "created_at", "updated_at",
                "respondent_entity", "amount_claimed_usd", "status", "vertical", "filed_at"]
        conn.close()
        items = []
        for r in rows:
            d = dict(zip(cols, r))
            d["notify"] = bool(d.get("notify", 0))
            items.append(d)
        return {"watchlist": items, "total": len(items), "operator_id": operator_id}

    def update_watchlist_item(self, watch_id: str, updates: dict) -> Dict[str, Any]:
        """Update a watchlist item."""
        allowed = {"label", "notes", "priority", "color", "notify"}
        conn = _get_db()
        existing = conn.execute("SELECT watch_id FROM watchlist WHERE watch_id = ?", (watch_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Watchlist item not found")
        sets, vals = [], []
        for k, v in updates.items():
            if k in allowed:
                if k == "notify":
                    v = 1 if v else 0
                sets.append(f"{k} = ?")
                vals.append(v)
        if sets:
            sets.append("updated_at = ?")
            vals.append(datetime.utcnow().isoformat() + "Z")
            vals.append(watch_id)
            conn.execute(f"UPDATE watchlist SET {', '.join(sets)} WHERE watch_id = ?", vals)
            conn.commit()
        conn.close()
        return self.get_watchlist_item(watch_id)

    def get_watchlist_item(self, watch_id: str) -> Dict[str, Any]:
        """Get a single watchlist item."""
        conn = _get_db()
        row = conn.execute("""
            SELECT w.*, c.respondent_entity, c.amount_claimed_usd, c.status
            FROM watchlist w JOIN claims c ON w.claim_id = c.claim_id
            WHERE w.watch_id = ?
        """, (watch_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Watchlist item not found")
        cols = ["watch_id", "claim_id", "operator_id", "label", "notes", "priority",
                "color", "notify", "created_at", "updated_at",
                "respondent_entity", "amount_claimed_usd", "status"]
        conn.close()
        d = dict(zip(cols, row))
        d["notify"] = bool(d.get("notify", 0))
        return d

    def remove_from_watchlist(self, watch_id: str) -> Dict[str, Any]:
        """Remove a claim from the watchlist."""
        conn = _get_db()
        existing = conn.execute("SELECT watch_id, claim_id, operator_id FROM watchlist WHERE watch_id = ?",
                                (watch_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Watchlist item not found")
        conn.execute("DELETE FROM watchlist WHERE watch_id = ?", (watch_id,))
        conn.commit()
        conn.close()
        self.audit("watchlist_removed", {"watch_id": watch_id, "claim_id": existing[1]}, existing[2])
        return {"deleted": True, "watch_id": watch_id}

    def is_watching(self, claim_id: str, operator_id: str) -> Dict[str, Any]:
        """Check if operator is watching a specific claim."""
        conn = _get_db()
        row = conn.execute("SELECT watch_id FROM watchlist WHERE claim_id = ? AND operator_id = ?",
                           (claim_id, operator_id)).fetchone()
        conn.close()
        return {"watching": row is not None, "watch_id": row[0] if row else None}

    def get_watchlist_stats(self, operator_id: str = None) -> Dict[str, Any]:
        """Get watchlist statistics."""
        conn = _get_db()
        if operator_id:
            total = conn.execute("SELECT COUNT(*) FROM watchlist WHERE operator_id = ?", (operator_id,)).fetchone()[0]
            by_priority = {}
            for row in conn.execute("SELECT priority, COUNT(*) FROM watchlist WHERE operator_id = ? GROUP BY priority",
                                    (operator_id,)).fetchall():
                by_priority[row[0]] = row[1]
            by_status = {}
            for row in conn.execute("""
                SELECT c.status, COUNT(*) FROM watchlist w
                JOIN claims c ON w.claim_id = c.claim_id
                WHERE w.operator_id = ? GROUP BY c.status
            """, (operator_id,)).fetchall():
                by_status[row[0]] = row[1]
        else:
            total = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
            by_priority = {}
            for row in conn.execute("SELECT priority, COUNT(*) FROM watchlist GROUP BY priority").fetchall():
                by_priority[row[0]] = row[1]
            by_status = {}
            for row in conn.execute("""
                SELECT c.status, COUNT(*) FROM watchlist w
                JOIN claims c ON w.claim_id = c.claim_id GROUP BY c.status
            """).fetchall():
                by_status[row[0]] = row[1]
        operators = conn.execute("SELECT operator_id, COUNT(*) FROM watchlist GROUP BY operator_id").fetchall()
        most_watched = conn.execute("""
            SELECT w.claim_id, c.respondent_entity, c.amount_claimed_usd, COUNT(*) as watchers
            FROM watchlist w JOIN claims c ON w.claim_id = c.claim_id
            GROUP BY w.claim_id ORDER BY watchers DESC LIMIT 5
        """).fetchall()
        conn.close()
        return {
            "total_watched": total,
            "by_priority": by_priority,
            "by_claim_status": by_status,
            "operators_watching": [{r[0]: r[1]} for r in operators],
            "most_watched": [{"claim_id": r[0], "respondent": r[1], "amount": r[2], "watchers": r[3]} for r in most_watched],
        }

    # ── Task Queue & Operator Assignments Methods ──

    TASK_TYPES = ["manual", "follow_up", "review", "outreach", "escalation", "compliance",
                  "document_request", "settlement", "investigation", "verification", "system"]
    TASK_PRIORITIES = ["low", "normal", "high", "urgent", "critical"]
    TASK_STATUSES = ["open", "in_progress", "completed", "cancelled", "blocked", "deferred"]

    def create_task(self, title: str, claim_id: str = None, description: str = "",
                    task_type: str = "manual", priority: str = "normal",
                    assigned_to: str = None, due_at: str = None,
                    estimated_minutes: int = None, tags: list = None,
                    parent_task_id: str = None, depends_on: list = None,
                    metadata: dict = None, created_by: str = "operator") -> Dict[str, Any]:
        """Create a new task, optionally linked to a claim."""
        task_id = f"TSK-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        if claim_id:
            claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
            if not claim:
                conn.close()
                raise HTTPException(status_code=404, detail="Claim not found")
        tags_json = json.dumps(tags or [])
        deps_json = json.dumps(depends_on or [])
        meta_json = json.dumps(metadata or {})
        conn.execute("""
            INSERT INTO tasks
            (task_id, claim_id, title, description, task_type, priority, status,
             assigned_to, created_by, due_at, estimated_minutes, tags,
             parent_task_id, depends_on, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (task_id, claim_id, title.strip(), description.strip(), task_type,
              priority, assigned_to, created_by, due_at, estimated_minutes,
              tags_json, parent_task_id, deps_json, meta_json, now))
        conn.commit()
        conn.close()
        self.audit("task.created", {
            "task_id": task_id, "claim_id": claim_id, "title": title,
            "task_type": task_type, "priority": priority, "assigned_to": assigned_to,
        }, actor=created_by)
        return {
            "task_id": task_id, "claim_id": claim_id, "title": title.strip(),
            "description": description.strip(), "task_type": task_type,
            "priority": priority, "status": "open", "assigned_to": assigned_to,
            "created_by": created_by, "due_at": due_at,
            "estimated_minutes": estimated_minutes, "tags": tags or [],
            "parent_task_id": parent_task_id, "depends_on": depends_on or [],
            "created_at": now,
        }

    def list_tasks(self, claim_id: str = None, assigned_to: str = None,
                   status: str = None, priority: str = None, task_type: str = None,
                   overdue_only: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
        """List tasks with optional filters."""
        conn = _get_db()
        query = "SELECT * FROM tasks WHERE 1=1"
        params = []
        if claim_id:
            query += " AND claim_id = ?"
            params.append(claim_id)
        if assigned_to:
            query += " AND assigned_to = ?"
            params.append(assigned_to)
        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if task_type:
            query += " AND task_type = ?"
            params.append(task_type)
        if overdue_only:
            now = datetime.utcnow().isoformat() + "Z"
            query += " AND due_at IS NOT NULL AND due_at < ? AND status NOT IN ('completed','cancelled')"
            params.append(now)
        query += " ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 WHEN 'low' THEN 4 END, due_at ASC NULLS LAST LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            for jf in ("tags", "depends_on", "metadata"):
                if d.get(jf):
                    try:
                        d[jf] = json.loads(d[jf])
                    except:
                        pass
            results.append(d)
        return results

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get a single task by ID."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        for jf in ("tags", "depends_on", "metadata"):
            if d.get(jf):
                try:
                    d[jf] = json.loads(d[jf])
                except:
                    pass
        return d

    def update_task(self, task_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update task fields (title, description, priority, assigned_to, due_at, etc.)."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if not row:
            conn.close()
            return None
        now = datetime.utcnow().isoformat() + "Z"
        allowed = {"title", "description", "task_type", "priority", "assigned_to",
                    "due_at", "estimated_minutes", "actual_minutes", "tags",
                    "parent_task_id", "depends_on", "metadata"}
        set_parts, params = [], []
        for k, v in updates.items():
            if k in allowed:
                if k in ("tags", "depends_on", "metadata"):
                    v = json.dumps(v) if isinstance(v, (list, dict)) else v
                set_parts.append(f"{k} = ?")
                params.append(v)
        if not set_parts:
            conn.close()
            return self.get_task(task_id)
        set_parts.append("updated_at = ?")
        params.append(now)
        params.append(task_id)
        conn.execute(f"UPDATE tasks SET {', '.join(set_parts)} WHERE task_id = ?", params)
        conn.commit()
        updated = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        conn.close()
        d = dict(updated)
        for jf in ("tags", "depends_on", "metadata"):
            if d.get(jf):
                try:
                    d[jf] = json.loads(d[jf])
                except:
                    pass
        return d

    def transition_task(self, task_id: str, new_status: str,
                        actor: str = "operator") -> Optional[Dict[str, Any]]:
        """Transition a task status (open → in_progress → completed, etc.)."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if not row:
            conn.close()
            return None
        current = row["status"]
        valid_transitions = {
            "open": ["in_progress", "cancelled", "deferred", "blocked"],
            "in_progress": ["completed", "cancelled", "blocked", "deferred", "open"],
            "blocked": ["open", "in_progress", "cancelled"],
            "deferred": ["open", "in_progress", "cancelled"],
            "completed": ["open"],  # reopen
            "cancelled": ["open"],  # reopen
        }
        if new_status not in valid_transitions.get(current, []):
            conn.close()
            raise HTTPException(status_code=400,
                                detail=f"Cannot transition from '{current}' to '{new_status}'")
        now = datetime.utcnow().isoformat() + "Z"
        updates = {"status": new_status, "updated_at": now}
        if new_status == "in_progress" and not row["started_at"]:
            updates["started_at"] = now
        if new_status == "completed":
            updates["completed_at"] = now
            if row["started_at"]:
                started = datetime.fromisoformat(row["started_at"].replace("Z", "+00:00"))
                ended = datetime.fromisoformat(now.replace("Z", "+00:00"))
                updates["actual_minutes"] = int((ended - started).total_seconds() / 60)
        set_parts = [f"{k} = ?" for k in updates]
        params = list(updates.values()) + [task_id]
        conn.execute(f"UPDATE tasks SET {', '.join(set_parts)} WHERE task_id = ?", params)
        conn.commit()
        updated = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        conn.close()
        d = dict(updated)
        for jf in ("tags", "depends_on", "metadata"):
            if d.get(jf):
                try:
                    d[jf] = json.loads(d[jf])
                except:
                    pass
        self.audit("task.transitioned", {
            "task_id": task_id, "from": current, "to": new_status,
        }, actor=actor)
        return d

    def assign_task(self, task_id: str, assigned_to: str,
                    actor: str = "operator") -> Optional[Dict[str, Any]]:
        """Assign or reassign a task to an operator."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if not row:
            conn.close()
            return None
        now = datetime.utcnow().isoformat() + "Z"
        prev = row["assigned_to"]
        conn.execute("UPDATE tasks SET assigned_to = ?, updated_at = ? WHERE task_id = ?",
                     (assigned_to, now, task_id))
        conn.commit()
        updated = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        conn.close()
        d = dict(updated)
        for jf in ("tags", "depends_on", "metadata"):
            if d.get(jf):
                try:
                    d[jf] = json.loads(d[jf])
                except:
                    pass
        self.audit("task.assigned", {
            "task_id": task_id, "previous": prev, "assigned_to": assigned_to,
        }, actor=actor)
        return d

    def delete_task(self, task_id: str) -> bool:
        """Delete a task (only open/cancelled tasks)."""
        conn = _get_db()
        row = conn.execute("SELECT status, claim_id, title FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if not row:
            conn.close()
            return False
        if row["status"] not in ("open", "cancelled", "deferred"):
            conn.close()
            raise HTTPException(status_code=400, detail="Can only delete open/cancelled/deferred tasks")
        conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
        conn.commit()
        conn.close()
        self.audit("task.deleted", {"task_id": task_id, "title": row["title"]}, actor="operator")
        return True

    def get_task_stats(self, assigned_to: str = None) -> Dict[str, Any]:
        """Get aggregate task statistics."""
        conn = _get_db()
        base_filter = ""
        params = []
        if assigned_to:
            base_filter = " WHERE assigned_to = ?"
            params.append(assigned_to)
        total = conn.execute(f"SELECT COUNT(*) FROM tasks{base_filter}", params).fetchone()[0]
        by_status = {}
        for row in conn.execute(f"SELECT status, COUNT(*) as c FROM tasks{base_filter} GROUP BY status", params).fetchall():
            by_status[row[0]] = row[1]
        by_priority = {}
        for row in conn.execute(f"SELECT priority, COUNT(*) as c FROM tasks{base_filter} GROUP BY priority", params).fetchall():
            by_priority[row[0]] = row[1]
        by_type = {}
        for row in conn.execute(f"SELECT task_type, COUNT(*) as c FROM tasks{base_filter} GROUP BY task_type", params).fetchall():
            by_type[row[0]] = row[1]
        now = datetime.utcnow().isoformat() + "Z"
        overdue_q = f"SELECT COUNT(*) FROM tasks WHERE due_at IS NOT NULL AND due_at < ? AND status NOT IN ('completed','cancelled'){' AND assigned_to = ?' if assigned_to else ''}"
        overdue_params = [now] + (params if assigned_to else [])
        overdue = conn.execute(overdue_q, overdue_params).fetchone()[0]
        # Completion metrics
        completed = conn.execute(
            f"SELECT COUNT(*) FROM tasks WHERE status = 'completed'{' AND assigned_to = ?' if assigned_to else ''}",
            params).fetchone()[0]
        avg_time = conn.execute(
            f"SELECT AVG(actual_minutes) FROM tasks WHERE status = 'completed' AND actual_minutes IS NOT NULL{' AND assigned_to = ?' if assigned_to else ''}",
            params).fetchone()[0]
        # Operator breakdown (only if not filtered to one)
        by_operator = []
        if not assigned_to:
            for row in conn.execute(
                "SELECT assigned_to, COUNT(*) as total, "
                "SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as done, "
                "SUM(CASE WHEN status='open' OR status='in_progress' THEN 1 ELSE 0 END) as active "
                "FROM tasks WHERE assigned_to IS NOT NULL GROUP BY assigned_to ORDER BY total DESC"
            ).fetchall():
                by_operator.append({
                    "operator_id": row[0], "total": row[1],
                    "completed": row[2], "active": row[3],
                })
        # Due soon (next 48 hours)
        due_soon_cutoff = (datetime.utcnow() + timedelta(hours=48)).isoformat() + "Z"
        due_soon = conn.execute(
            f"SELECT COUNT(*) FROM tasks WHERE due_at IS NOT NULL AND due_at > ? AND due_at <= ? AND status NOT IN ('completed','cancelled'){' AND assigned_to = ?' if assigned_to else ''}",
            [now, due_soon_cutoff] + (params if assigned_to else [])
        ).fetchone()[0]
        conn.close()
        return {
            "total_tasks": total, "by_status": by_status, "by_priority": by_priority,
            "by_type": by_type, "overdue": overdue, "due_soon_48h": due_soon,
            "completed": completed,
            "avg_completion_minutes": round(avg_time, 1) if avg_time else 0,
            "by_operator": by_operator,
        }

    def get_claim_tasks(self, claim_id: str) -> Dict[str, Any]:
        """Get all tasks for a specific claim."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM tasks WHERE claim_id = ? ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 WHEN 'low' THEN 4 END, created_at DESC",
            (claim_id,)).fetchall()
        conn.close()
        tasks = []
        for r in rows:
            d = dict(r)
            for jf in ("tags", "depends_on", "metadata"):
                if d.get(jf):
                    try:
                        d[jf] = json.loads(d[jf])
                    except:
                        pass
            tasks.append(d)
        open_count = sum(1 for t in tasks if t["status"] in ("open", "in_progress", "blocked"))
        completed_count = sum(1 for t in tasks if t["status"] == "completed")
        return {
            "claim_id": claim_id, "tasks": tasks, "total": len(tasks),
            "open": open_count, "completed": completed_count,
        }

    # ── Operator Performance Scorecards Methods ──

    def get_operator_scorecard(self, operator_id: str) -> Dict[str, Any]:
        """Build a comprehensive performance scorecard for a single operator."""
        conn = _get_db()
        # 1. Basic operator info
        op = conn.execute("SELECT * FROM operators WHERE operator_id = ?", (operator_id,)).fetchone()
        if not op:
            conn.close()
            raise HTTPException(status_code=404, detail="Operator not found")
        op_info = dict(op)

        # 2. Claims assigned
        assigned_claims = conn.execute(
            "SELECT COUNT(*) FROM assignments WHERE operator_id = ?", (operator_id,)).fetchone()[0]

        # 3. Tasks metrics
        task_total = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE assigned_to = ?", (operator_id,)).fetchone()[0]
        task_completed = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status = 'completed'",
            (operator_id,)).fetchone()[0]
        task_open = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status IN ('open','in_progress','blocked')",
            (operator_id,)).fetchone()[0]
        now = datetime.utcnow().isoformat() + "Z"
        task_overdue = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND due_at IS NOT NULL AND due_at < ? AND status NOT IN ('completed','cancelled')",
            (operator_id, now)).fetchone()[0]
        avg_task_time = conn.execute(
            "SELECT AVG(actual_minutes) FROM tasks WHERE assigned_to = ? AND status = 'completed' AND actual_minutes IS NOT NULL",
            (operator_id,)).fetchone()[0]
        task_completion_rate = round((task_completed / task_total * 100), 1) if task_total > 0 else 0

        # 4. Correspondence sent
        corr_sent = conn.execute(
            "SELECT COUNT(*) FROM correspondence WHERE created_by = ? AND status IN ('sent','delivered','responded')",
            (operator_id,)).fetchone()[0]
        corr_responded = conn.execute(
            "SELECT COUNT(*) FROM correspondence WHERE created_by = ? AND status = 'responded'",
            (operator_id,)).fetchone()[0]

        # 5. Compliance checks performed
        comp_checks = conn.execute(
            "SELECT COUNT(*) FROM compliance_checks WHERE checked_by = ?", (operator_id,)).fetchone()[0]
        comp_passed = conn.execute(
            "SELECT COUNT(*) FROM compliance_checks WHERE checked_by = ? AND status = 'pass'",
            (operator_id,)).fetchone()[0]

        # 6. Negotiations handled
        neg_created = conn.execute(
            "SELECT COUNT(*) FROM negotiations WHERE created_by = ?", (operator_id,)).fetchone()[0]
        neg_accepted = conn.execute(
            "SELECT COUNT(*) FROM negotiations WHERE created_by = ? AND status = 'accepted'",
            (operator_id,)).fetchone()[0]

        # 7. Audit activity (recent 30 days)
        thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"
        audit_actions = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE actor = ? AND timestamp >= ?",
            (operator_id, thirty_days_ago)).fetchone()[0]

        # 8. Watchlist items
        watch_count = conn.execute(
            "SELECT COUNT(*) FROM watchlist WHERE operator_id = ?", (operator_id,)).fetchone()[0]

        conn.close()

        # Calculate overall score (0-100)
        score_components = []
        # Task completion rate (40% weight)
        score_components.append(task_completion_rate * 0.4)
        # Low overdue ratio (20% weight)
        overdue_ratio = (1 - (task_overdue / max(task_open, 1))) * 100 if task_open > 0 else 100
        score_components.append(max(0, overdue_ratio) * 0.2)
        # Activity level (20% weight) — cap at 100 actions per 30 days
        activity_score = min(audit_actions / 100, 1) * 100
        score_components.append(activity_score * 0.2)
        # Correspondence efficiency (20% weight)
        corr_rate = (corr_sent / max(assigned_claims, 1)) * 100 if assigned_claims > 0 else 50
        score_components.append(min(corr_rate, 100) * 0.2)

        overall_score = round(sum(score_components), 1)
        if overall_score >= 85:
            grade = "A"
        elif overall_score >= 70:
            grade = "B"
        elif overall_score >= 55:
            grade = "C"
        elif overall_score >= 40:
            grade = "D"
        else:
            grade = "F"

        return {
            "operator_id": operator_id,
            "name": op_info.get("name", ""),
            "role": op_info.get("role", ""),
            "email": op_info.get("email", ""),
            "overall_score": overall_score,
            "grade": grade,
            "claims": {
                "assigned": assigned_claims,
                "max_caseload": op_info.get("max_caseload", 0),
                "utilization_pct": round(assigned_claims / max(op_info.get("max_caseload", 1), 1) * 100, 1),
            },
            "tasks": {
                "total": task_total, "completed": task_completed, "open": task_open,
                "overdue": task_overdue,
                "completion_rate": task_completion_rate,
                "avg_completion_minutes": round(avg_task_time, 1) if avg_task_time else 0,
            },
            "correspondence": {
                "sent": corr_sent, "responded": corr_responded,
            },
            "compliance": {
                "checks_performed": comp_checks, "passed": comp_passed,
            },
            "negotiations": {
                "created": neg_created, "accepted": neg_accepted,
            },
            "activity": {
                "actions_30d": audit_actions,
                "watchlist_items": watch_count,
            },
        }

    def get_all_scorecards(self) -> Dict[str, Any]:
        """Get scorecards for all operators."""
        conn = _get_db()
        operators = conn.execute(
            "SELECT operator_id, name, role FROM operators WHERE status = 'active'"
        ).fetchall()
        conn.close()
        scorecards = []
        for op in operators:
            try:
                sc = self.get_operator_scorecard(op["operator_id"])
                scorecards.append(sc)
            except:
                pass
        scorecards.sort(key=lambda s: s["overall_score"], reverse=True)
        avg_score = round(sum(s["overall_score"] for s in scorecards) / max(len(scorecards), 1), 1)
        total_tasks_done = sum(s["tasks"]["completed"] for s in scorecards)
        total_overdue = sum(s["tasks"]["overdue"] for s in scorecards)
        return {
            "scorecards": scorecards,
            "summary": {
                "total_operators": len(scorecards),
                "avg_score": avg_score,
                "total_tasks_completed": total_tasks_done,
                "total_overdue": total_overdue,
                "top_performer": scorecards[0]["operator_id"] if scorecards else None,
                "grade_distribution": {
                    g: sum(1 for s in scorecards if s["grade"] == g)
                    for g in ["A", "B", "C", "D", "F"]
                },
            },
        }

    def get_operator_activity_timeline(self, operator_id: str, days: int = 30) -> Dict[str, Any]:
        """Get daily activity breakdown for an operator."""
        conn = _get_db()
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        # Daily audit counts
        daily = conn.execute(
            "SELECT DATE(timestamp) as day, COUNT(*) as actions FROM audit_log WHERE actor = ? AND timestamp >= ? GROUP BY DATE(timestamp) ORDER BY day",
            (operator_id, cutoff)).fetchall()
        # Task completions by day
        task_daily = conn.execute(
            "SELECT DATE(completed_at) as day, COUNT(*) as done FROM tasks WHERE assigned_to = ? AND status = 'completed' AND completed_at >= ? GROUP BY DATE(completed_at) ORDER BY day",
            (operator_id, cutoff)).fetchall()
        conn.close()
        return {
            "operator_id": operator_id,
            "period_days": days,
            "daily_actions": [{"date": r[0], "actions": r[1]} for r in daily],
            "daily_completions": [{"date": r[0], "completed": r[1]} for r in task_daily],
        }

    # ── Export & Download Center Methods ──

    EXPORT_TYPES = ["claims", "respondents", "tasks", "correspondence", "compliance",
                    "negotiations", "watchlist", "audit_log", "analytics", "scorecards"]
    EXPORT_FORMATS = ["json", "csv"]

    def export_data(self, export_type: str = "claims", format: str = "json",
                    filters: dict = None, created_by: str = "operator") -> Dict[str, Any]:
        """Generate an export of data in the specified format."""
        export_id = f"EXP-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        filters = filters or {}
        data = []
        columns = []

        if export_type == "claims":
            query = "SELECT * FROM claims WHERE 1=1"
            params = []
            if filters.get("status"):
                query += " AND status = ?"
                params.append(filters["status"])
            if filters.get("respondent"):
                query += " AND respondent_entity LIKE ?"
                params.append(f"%{filters['respondent']}%")
            if filters.get("from_date"):
                query += " AND filed_at >= ?"
                params.append(filters["from_date"])
            if filters.get("to_date"):
                query += " AND filed_at <= ?"
                params.append(filters["to_date"])
            query += " ORDER BY filed_at DESC"
            rows = conn.execute(query, params).fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "respondents":
            rows = conn.execute("SELECT * FROM claims GROUP BY respondent_entity ORDER BY respondent_entity").fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "tasks":
            query = "SELECT * FROM tasks WHERE 1=1"
            params = []
            if filters.get("status"):
                query += " AND status = ?"
                params.append(filters["status"])
            if filters.get("assigned_to"):
                query += " AND assigned_to = ?"
                params.append(filters["assigned_to"])
            query += " ORDER BY created_at DESC"
            rows = conn.execute(query, params).fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "correspondence":
            query = "SELECT * FROM correspondence WHERE 1=1"
            params = []
            if filters.get("claim_id"):
                query += " AND claim_id = ?"
                params.append(filters["claim_id"])
            if filters.get("channel"):
                query += " AND channel = ?"
                params.append(filters["channel"])
            query += " ORDER BY created_at DESC"
            rows = conn.execute(query, params).fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "compliance":
            rows = conn.execute(
                "SELECT cc.*, cr.name as rule_name, cr.category, cr.severity "
                "FROM compliance_checks cc LEFT JOIN compliance_rules cr ON cc.rule_id = cr.rule_id "
                "ORDER BY cc.created_at DESC").fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "negotiations":
            rows = conn.execute("SELECT * FROM negotiations ORDER BY created_at DESC").fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "watchlist":
            rows = conn.execute(
                "SELECT w.*, c.respondent_entity, c.amount_claimed_usd "
                "FROM watchlist w LEFT JOIN claims c ON w.claim_id = c.claim_id "
                "ORDER BY w.created_at DESC").fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "audit_log":
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []
            if filters.get("action"):
                query += " AND action LIKE ?"
                params.append(f"%{filters['action']}%")
            if filters.get("actor"):
                query += " AND actor = ?"
                params.append(filters["actor"])
            if filters.get("from_date"):
                query += " AND timestamp >= ?"
                params.append(filters["from_date"])
            query += " ORDER BY timestamp DESC LIMIT 1000"
            rows = conn.execute(query, params).fetchall()
            data = [dict(r) for r in rows]

        elif export_type == "analytics":
            # Summary analytics export
            total_claims = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
            total_usd = conn.execute("SELECT SUM(amount_claimed_usd) FROM claims").fetchone()[0] or 0
            by_status = {}
            for r in conn.execute("SELECT status, COUNT(*) FROM claims GROUP BY status").fetchall():
                by_status[r[0]] = r[1]
            by_respondent = {}
            for r in conn.execute("SELECT respondent_entity, COUNT(*), SUM(amount_claimed_usd) FROM claims GROUP BY respondent_entity ORDER BY COUNT(*) DESC LIMIT 20").fetchall():
                by_respondent[r[0]] = {"count": r[1], "total_usd": round(r[2] or 0, 2)}
            data = [{
                "total_claims": total_claims,
                "total_usd": round(total_usd, 2),
                "by_status": by_status,
                "top_respondents": by_respondent,
                "export_date": now,
            }]

        elif export_type == "scorecards":
            conn.close()
            sc = self.get_all_scorecards()
            data = sc.get("scorecards", [])
            conn = _get_db()

        # Generate output
        record_count = len(data)
        if format == "csv" and data:
            import io, csv
            output = io.StringIO()
            if data:
                keys = list(data[0].keys())
                writer = csv.DictWriter(output, fieldnames=keys)
                writer.writeheader()
                for row in data:
                    # Flatten nested dicts/lists for CSV
                    flat = {}
                    for k, v in row.items():
                        flat[k] = json.dumps(v) if isinstance(v, (dict, list)) else v
                    writer.writerow(flat)
            content = output.getvalue()
            file_size = len(content.encode())
        else:
            content = json.dumps(data, indent=2, default=str)
            file_size = len(content.encode())

        # Record the export job
        conn.execute("""
            INSERT INTO export_jobs
            (export_id, export_type, format, filters, status, record_count,
             file_size_bytes, created_by, created_at, completed_at, metadata)
            VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)
        """, (export_id, export_type, format, json.dumps(filters or {}),
              record_count, file_size, created_by, now, now, json.dumps({})))
        conn.commit()
        conn.close()

        self.audit("export.created", {
            "export_id": export_id, "type": export_type, "format": format,
            "records": record_count, "size_bytes": file_size,
        }, actor=created_by)

        return {
            "export_id": export_id,
            "export_type": export_type,
            "format": format,
            "record_count": record_count,
            "file_size_bytes": file_size,
            "data": data if format == "json" else None,
            "csv_content": content if format == "csv" else None,
            "created_at": now,
        }

    def get_export_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent export job history."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM export_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            for jf in ("filters", "metadata"):
                if d.get(jf):
                    try:
                        d[jf] = json.loads(d[jf])
                    except:
                        pass
            results.append(d)
        return results

    def get_export_stats(self) -> Dict[str, Any]:
        """Get export statistics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM export_jobs").fetchone()[0]
        by_type = {}
        for r in conn.execute("SELECT export_type, COUNT(*) FROM export_jobs GROUP BY export_type").fetchall():
            by_type[r[0]] = r[1]
        by_format = {}
        for r in conn.execute("SELECT format, COUNT(*) FROM export_jobs GROUP BY format").fetchall():
            by_format[r[0]] = r[1]
        total_records = conn.execute("SELECT SUM(record_count) FROM export_jobs").fetchone()[0] or 0
        total_size = conn.execute("SELECT SUM(file_size_bytes) FROM export_jobs").fetchone()[0] or 0
        recent = conn.execute(
            "SELECT export_id, export_type, format, record_count, file_size_bytes, created_at, created_by "
            "FROM export_jobs ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
        conn.close()
        return {
            "total_exports": total,
            "by_type": by_type,
            "by_format": by_format,
            "total_records_exported": total_records,
            "total_size_bytes": total_size,
            "recent_exports": [dict(r) for r in recent],
        }

    # ── Case Milestones & Progress Tracking Methods ──

    MILESTONE_CATEGORIES = ["intake", "investigation", "outreach", "negotiation", "compliance",
                            "settlement", "recovery", "resolution", "general"]
    MILESTONE_STATUSES = ["pending", "in_progress", "completed", "skipped", "blocked"]
    DEFAULT_MILESTONES = [
        {"title": "Claim Filed & Validated", "category": "intake", "sequence_order": 1},
        {"title": "Evidence Collected", "category": "investigation", "sequence_order": 2},
        {"title": "Respondent Contacted", "category": "outreach", "sequence_order": 3},
        {"title": "Response Received", "category": "outreach", "sequence_order": 4},
        {"title": "Compliance Check Passed", "category": "compliance", "sequence_order": 5},
        {"title": "Settlement Offer Made", "category": "negotiation", "sequence_order": 6},
        {"title": "Agreement Reached", "category": "settlement", "sequence_order": 7},
        {"title": "Recovery Processed", "category": "recovery", "sequence_order": 8},
        {"title": "Case Resolved & Closed", "category": "resolution", "sequence_order": 9},
    ]

    def create_milestone(self, claim_id: str, title: str, description: str = "",
                         category: str = "general", sequence_order: int = 0,
                         target_date: str = None, auto_trigger: dict = None,
                         created_by: str = "operator") -> Dict[str, Any]:
        """Create a milestone for a claim."""
        ms_id = f"MS-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        trigger_json = json.dumps(auto_trigger or {})
        conn.execute("""
            INSERT INTO milestones
            (milestone_id, claim_id, title, description, category, sequence_order,
             status, target_date, auto_trigger, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
        """, (ms_id, claim_id, title.strip(), description.strip(), category,
              sequence_order, target_date, trigger_json, created_by, now))
        conn.commit()
        conn.close()
        return {
            "milestone_id": ms_id, "claim_id": claim_id, "title": title.strip(),
            "description": description.strip(), "category": category,
            "sequence_order": sequence_order, "status": "pending",
            "target_date": target_date, "created_at": now,
        }

    def initialize_claim_milestones(self, claim_id: str,
                                     created_by: str = "system") -> List[Dict[str, Any]]:
        """Create default milestones for a new claim."""
        conn = _get_db()
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        existing = conn.execute(
            "SELECT COUNT(*) FROM milestones WHERE claim_id = ?", (claim_id,)).fetchone()[0]
        conn.close()
        if existing > 0:
            raise HTTPException(status_code=409, detail="Milestones already exist for this claim")
        results = []
        for ms_def in self.DEFAULT_MILESTONES:
            ms = self.create_milestone(
                claim_id=claim_id, title=ms_def["title"],
                category=ms_def["category"], sequence_order=ms_def["sequence_order"],
                created_by=created_by,
            )
            results.append(ms)
        # Auto-complete the first one since claim is already filed
        if results:
            self.complete_milestone(results[0]["milestone_id"], completed_by="system")
        return results

    def get_claim_milestones(self, claim_id: str) -> Dict[str, Any]:
        """Get all milestones for a claim with progress calculation."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM milestones WHERE claim_id = ? ORDER BY sequence_order ASC, created_at ASC",
            (claim_id,)).fetchall()
        conn.close()
        milestones = []
        for r in rows:
            d = dict(r)
            if d.get("auto_trigger"):
                try:
                    d["auto_trigger"] = json.loads(d["auto_trigger"])
                except:
                    pass
            milestones.append(d)
        total = len(milestones)
        completed = sum(1 for m in milestones if m["status"] == "completed")
        in_progress = sum(1 for m in milestones if m["status"] == "in_progress")
        progress_pct = round((completed / total * 100), 1) if total > 0 else 0
        # Find current milestone (first non-completed)
        current = None
        for m in milestones:
            if m["status"] not in ("completed", "skipped"):
                current = m["milestone_id"]
                break
        return {
            "claim_id": claim_id, "milestones": milestones, "total": total,
            "completed": completed, "in_progress": in_progress,
            "progress_pct": progress_pct, "current_milestone": current,
        }

    def complete_milestone(self, milestone_id: str,
                           completed_by: str = "operator", notes: str = "") -> Optional[Dict[str, Any]]:
        """Mark a milestone as completed."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM milestones WHERE milestone_id = ?", (milestone_id,)).fetchone()
        if not row:
            conn.close()
            return None
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "UPDATE milestones SET status = 'completed', completed_at = ?, completed_by = ?, notes = ?, updated_at = ? WHERE milestone_id = ?",
            (now, completed_by, notes, now, milestone_id))
        conn.commit()
        updated = conn.execute("SELECT * FROM milestones WHERE milestone_id = ?", (milestone_id,)).fetchone()
        conn.close()
        d = dict(updated)
        self.audit("milestone.completed", {
            "milestone_id": milestone_id, "title": d["title"],
            "claim_id": d["claim_id"],
        }, actor=completed_by)
        return d

    def update_milestone(self, milestone_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update milestone fields."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM milestones WHERE milestone_id = ?", (milestone_id,)).fetchone()
        if not row:
            conn.close()
            return None
        now = datetime.utcnow().isoformat() + "Z"
        allowed = {"title", "description", "category", "sequence_order", "status",
                    "target_date", "notes", "auto_trigger"}
        set_parts, params = [], []
        for k, v in updates.items():
            if k in allowed:
                if k == "auto_trigger" and isinstance(v, dict):
                    v = json.dumps(v)
                set_parts.append(f"{k} = ?")
                params.append(v)
        if not set_parts:
            conn.close()
            return dict(row)
        # Auto-set timestamps for status transitions
        status = updates.get("status")
        if status == "completed":
            set_parts.append("completed_at = ?")
            params.append(now)
        if status == "in_progress" and row["status"] == "pending":
            pass  # just update status
        set_parts.append("updated_at = ?")
        params.append(now)
        params.append(milestone_id)
        conn.execute(f"UPDATE milestones SET {', '.join(set_parts)} WHERE milestone_id = ?", params)
        conn.commit()
        updated = conn.execute("SELECT * FROM milestones WHERE milestone_id = ?", (milestone_id,)).fetchone()
        conn.close()
        return dict(updated)

    def delete_milestone(self, milestone_id: str) -> bool:
        """Delete a milestone."""
        conn = _get_db()
        row = conn.execute("SELECT claim_id, title FROM milestones WHERE milestone_id = ?", (milestone_id,)).fetchone()
        if not row:
            conn.close()
            return False
        conn.execute("DELETE FROM milestones WHERE milestone_id = ?", (milestone_id,))
        conn.commit()
        conn.close()
        return True

    def get_milestone_stats(self) -> Dict[str, Any]:
        """Get aggregate milestone statistics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM milestones").fetchone()[0]
        by_status = {}
        for r in conn.execute("SELECT status, COUNT(*) FROM milestones GROUP BY status").fetchall():
            by_status[r[0]] = r[1]
        by_category = {}
        for r in conn.execute("SELECT category, COUNT(*) FROM milestones GROUP BY category").fetchall():
            by_category[r[0]] = r[1]
        claims_with_ms = conn.execute(
            "SELECT COUNT(DISTINCT claim_id) FROM milestones").fetchone()[0]
        completed = by_status.get("completed", 0)
        completion_rate = round((completed / total * 100), 1) if total > 0 else 0
        # Avg progress per claim
        claim_progress = conn.execute("""
            SELECT claim_id,
                   COUNT(*) as total,
                   SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as done
            FROM milestones GROUP BY claim_id
        """).fetchall()
        avg_progress = 0
        if claim_progress:
            avg_progress = round(
                sum(r[2] / r[1] * 100 for r in claim_progress) / len(claim_progress), 1)
        # Overdue milestones
        now = datetime.utcnow().isoformat() + "Z"
        overdue = conn.execute(
            "SELECT COUNT(*) FROM milestones WHERE target_date IS NOT NULL AND target_date < ? AND status NOT IN ('completed','skipped')",
            (now,)).fetchone()[0]
        conn.close()
        return {
            "total_milestones": total,
            "by_status": by_status,
            "by_category": by_category,
            "claims_with_milestones": claims_with_ms,
            "completion_rate": completion_rate,
            "avg_progress_pct": avg_progress,
            "overdue": overdue,
        }

    # ── Respondent Profile & History Methods ──

    def get_respondent_profile(self, respondent_entity: str) -> Dict[str, Any]:
        """Build a comprehensive profile for a respondent entity."""
        conn = _get_db()
        # 1. All claims against this respondent
        claims = conn.execute(
            "SELECT claim_id, status, amount_claimed_usd, harm_type, claimant_name, filed_at, updated_at "
            "FROM claims WHERE respondent_entity = ? ORDER BY filed_at DESC",
            (respondent_entity,)).fetchall()
        if not claims:
            conn.close()
            raise HTTPException(status_code=404, detail="Respondent not found")
        claim_list = [dict(c) for c in claims]
        claim_ids = [c["claim_id"] for c in claim_list]

        total_claimed = sum(c["amount_claimed_usd"] or 0 for c in claim_list)
        by_status = {}
        for c in claim_list:
            by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        harm_types = {}
        for c in claim_list:
            ht = c.get("harm_type") or "unknown"
            harm_types[ht] = harm_types.get(ht, 0) + 1

        # 2. Settlements
        placeholders = ",".join(["?"] * len(claim_ids))
        settlements = conn.execute(
            f"SELECT settlement_id, claim_id, offer_type, amount_offered, status, created_at "
            f"FROM settlements WHERE claim_id IN ({placeholders}) ORDER BY created_at DESC",
            claim_ids).fetchall()
        settlement_list = [dict(s) for s in settlements]
        total_offered = sum(s["amount_offered"] or 0 for s in settlement_list)
        accepted_settlements = [s for s in settlement_list if s["status"] == "accepted"]
        total_accepted = sum(s["amount_offered"] or 0 for s in accepted_settlements)

        # 3. Recoveries
        recoveries = conn.execute(
            f"SELECT claim_id, amount_recovered, recovery_method, recorded_at "
            f"FROM recoveries WHERE claim_id IN ({placeholders}) ORDER BY recorded_at DESC",
            claim_ids).fetchall()
        recovery_list = [dict(r) for r in recoveries]
        total_recovered = sum(r["amount_recovered"] or 0 for r in recovery_list)

        # 4. Negotiations
        neg_count = conn.execute(
            f"SELECT COUNT(*) FROM negotiations WHERE claim_id IN ({placeholders})",
            claim_ids).fetchone()[0]
        neg_accepted = conn.execute(
            f"SELECT COUNT(*) FROM negotiations WHERE claim_id IN ({placeholders}) AND status = 'accepted'",
            claim_ids).fetchone()[0]

        # 5. Correspondence count
        corr_count = conn.execute(
            f"SELECT COUNT(*) FROM correspondence WHERE claim_id IN ({placeholders})",
            claim_ids).fetchone()[0]

        # 6. Compliance checks
        comp_total = conn.execute(
            f"SELECT COUNT(*) FROM compliance_checks WHERE claim_id IN ({placeholders})",
            claim_ids).fetchone()[0]
        comp_failed = conn.execute(
            f"SELECT COUNT(*) FROM compliance_checks WHERE claim_id IN ({placeholders}) AND status = 'fail'",
            claim_ids).fetchone()[0]

        # 7. First and last claim dates
        first_claim = claim_list[-1]["filed_at"] if claim_list else None
        last_claim = claim_list[0]["filed_at"] if claim_list else None

        conn.close()

        # Risk rating based on volume and resolution
        resolved = by_status.get("resolved", 0) + by_status.get("closed", 0)
        risk_score = min(100, len(claim_list) * 8 + (len(claim_list) - resolved) * 5 + comp_failed * 10)
        if risk_score >= 80:
            risk_tier = "critical"
        elif risk_score >= 60:
            risk_tier = "high"
        elif risk_score >= 30:
            risk_tier = "medium"
        else:
            risk_tier = "low"

        return {
            "respondent_entity": respondent_entity,
            "risk_tier": risk_tier,
            "risk_score": risk_score,
            "claims": {
                "total": len(claim_list),
                "by_status": by_status,
                "harm_types": harm_types,
                "total_claimed_usd": round(total_claimed, 2),
                "first_claim": first_claim,
                "last_claim": last_claim,
                "recent": claim_list[:10],
            },
            "financial": {
                "total_claimed": round(total_claimed, 2),
                "total_offered": round(total_offered, 2),
                "total_accepted": round(total_accepted, 2),
                "total_recovered": round(total_recovered, 2),
                "recovery_rate": round(total_recovered / total_claimed * 100, 1) if total_claimed > 0 else 0,
            },
            "negotiations": {
                "total_rounds": neg_count,
                "accepted": neg_accepted,
            },
            "correspondence": {
                "total_messages": corr_count,
            },
            "compliance": {
                "total_checks": comp_total,
                "failures": comp_failed,
            },
            "settlements": {
                "total": len(settlement_list),
                "accepted": len(accepted_settlements),
                "recent": settlement_list[:5],
            },
            "recoveries": {
                "total": len(recovery_list),
                "recent": recovery_list[:5],
            },
        }

    def list_respondent_profiles(self, limit: int = 50) -> Dict[str, Any]:
        """List all respondents with summary metrics."""
        conn = _get_db()
        respondents = conn.execute(
            "SELECT respondent_entity, COUNT(*) as claim_count, "
            "SUM(amount_claimed_usd) as total_claimed, "
            "MIN(filed_at) as first_claim, MAX(filed_at) as last_claim "
            "FROM claims GROUP BY respondent_entity "
            "ORDER BY claim_count DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        profiles = []
        for r in respondents:
            resolved = 0
            try:
                conn2 = _get_db()
                resolved = conn2.execute(
                    "SELECT COUNT(*) FROM claims WHERE respondent_entity = ? AND status IN ('resolved','closed')",
                    (r[0],)).fetchone()[0]
                conn2.close()
            except:
                pass
            risk = min(100, r[1] * 8 + (r[1] - resolved) * 5)
            profiles.append({
                "respondent_entity": r[0],
                "claim_count": r[1],
                "total_claimed_usd": round(r[2] or 0, 2),
                "first_claim": r[3],
                "last_claim": r[4],
                "resolved": resolved,
                "risk_score": risk,
                "risk_tier": "critical" if risk >= 80 else "high" if risk >= 60 else "medium" if risk >= 30 else "low",
            })
        return {
            "respondents": profiles,
            "total": len(profiles),
        }

    def get_respondent_timeline(self, respondent_entity: str) -> Dict[str, Any]:
        """Get chronological timeline of all activity for a respondent."""
        conn = _get_db()
        claims = conn.execute(
            "SELECT claim_id, filed_at FROM claims WHERE respondent_entity = ?",
            (respondent_entity,)).fetchall()
        if not claims:
            conn.close()
            return {"respondent_entity": respondent_entity, "events": []}
        claim_ids = [c[0] for c in claims]
        placeholders = ",".join(["?"] * len(claim_ids))
        events = []
        # Claim filed events
        for c in claims:
            events.append({"type": "claim_filed", "claim_id": c[0], "date": c[1]})
        # Settlement events
        for s in conn.execute(
            f"SELECT claim_id, status, amount_offered, created_at FROM settlements WHERE claim_id IN ({placeholders})",
            claim_ids).fetchall():
            events.append({"type": f"settlement_{s[1]}", "claim_id": s[0],
                          "amount": s[2], "date": s[3]})
        # Recovery events
        for r in conn.execute(
            f"SELECT claim_id, amount_recovered, recorded_at FROM recoveries WHERE claim_id IN ({placeholders})",
            claim_ids).fetchall():
            events.append({"type": "recovery", "claim_id": r[0],
                          "amount": r[1], "date": r[2]})
        # Negotiation events
        for n in conn.execute(
            f"SELECT claim_id, status, offer_amount, created_at FROM negotiations WHERE claim_id IN ({placeholders})",
            claim_ids).fetchall():
            events.append({"type": f"negotiation_{n[1]}", "claim_id": n[0],
                          "amount": n[2], "date": n[3]})
        conn.close()
        events.sort(key=lambda e: e.get("date", ""), reverse=True)
        return {
            "respondent_entity": respondent_entity,
            "events": events[:100],
            "total_events": len(events),
        }

    # ── Correspondence & Communication Log Methods ──

    CORR_CHANNELS = ["email", "letter", "phone", "portal", "sms", "in_person", "legal_notice"]
    CORR_STATUSES = ["draft", "sent", "delivered", "failed", "responded", "archived"]
    CORR_DIRECTIONS = ["inbound", "outbound"]

    def create_correspondence(self, claim_id: str, direction: str = "outbound",
                              channel: str = "email", subject: str = "",
                              body: str = "", sender: str = "", recipient: str = "",
                              status: str = "draft", priority: str = "normal",
                              template_used: str = None, related_to: str = None,
                              created_by: str = "operator") -> Dict[str, Any]:
        """Create a new correspondence record."""
        msg_id = f"MSG-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        # Validate claim exists
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        sent_at = now if status == "sent" else None
        conn.execute("""
            INSERT INTO correspondence
            (message_id, claim_id, direction, channel, subject, body, sender, recipient,
             status, priority, template_used, related_to, sent_at, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (msg_id, claim_id, direction, channel, subject.strip(), body.strip(),
              sender.strip(), recipient.strip(), status, priority,
              template_used, related_to, sent_at, created_by, now))
        conn.commit()
        conn.close()
        self.audit("correspondence_created", {"message_id": msg_id, "claim_id": claim_id,
                                               "direction": direction, "channel": channel}, created_by)
        return {"message_id": msg_id, "claim_id": claim_id, "direction": direction,
                "channel": channel, "subject": subject, "status": status, "created_at": now}

    def list_correspondence(self, claim_id: str = None, direction: str = None,
                            channel: str = None, status: str = None,
                            limit: int = 50) -> Dict[str, Any]:
        """List correspondence with filters."""
        conn = _get_db()
        sql = "SELECT * FROM correspondence WHERE 1=1"
        params = []
        if claim_id:
            sql += " AND claim_id = ?"
            params.append(claim_id)
        if direction:
            sql += " AND direction = ?"
            params.append(direction)
        if channel:
            sql += " AND channel = ?"
            params.append(channel)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM correspondence LIMIT 0").description]
        conn.close()
        messages = [dict(zip(cols, r)) for r in rows]
        return {"messages": messages, "total": len(messages)}

    def get_correspondence(self, message_id: str) -> Dict[str, Any]:
        """Get a single correspondence message."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM correspondence WHERE message_id = ?", (message_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Message not found")
        cols = [d[0] for d in conn.execute("SELECT * FROM correspondence LIMIT 0").description]
        conn.close()
        return dict(zip(cols, row))

    def update_correspondence(self, message_id: str, updates: dict) -> Dict[str, Any]:
        """Update a correspondence message."""
        allowed = {"subject", "body", "sender", "recipient", "status",
                    "priority", "channel", "direction", "template_used", "related_to"}
        conn = _get_db()
        existing = conn.execute("SELECT message_id, status FROM correspondence WHERE message_id = ?",
                                (message_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Message not found")
        sets, vals = [], []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        # Auto-set timestamps based on status changes
        new_status = updates.get("status")
        if new_status == "sent" and existing[1] != "sent":
            sets.append("sent_at = ?")
            vals.append(datetime.utcnow().isoformat() + "Z")
        elif new_status == "delivered":
            sets.append("delivered_at = ?")
            vals.append(datetime.utcnow().isoformat() + "Z")
        elif new_status == "responded":
            sets.append("responded_at = ?")
            vals.append(datetime.utcnow().isoformat() + "Z")
        if sets:
            sets.append("updated_at = ?")
            vals.append(datetime.utcnow().isoformat() + "Z")
            vals.append(message_id)
            conn.execute(f"UPDATE correspondence SET {', '.join(sets)} WHERE message_id = ?", vals)
            conn.commit()
        conn.close()
        self.audit("correspondence_updated", {"message_id": message_id, "fields": list(updates.keys())}, "operator")
        return self.get_correspondence(message_id)

    def send_correspondence(self, message_id: str, sent_by: str = "operator") -> Dict[str, Any]:
        """Mark a correspondence as sent."""
        conn = _get_db()
        existing = conn.execute("SELECT message_id, status, claim_id FROM correspondence WHERE message_id = ?",
                                (message_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Message not found")
        if existing[1] not in ("draft",):
            conn.close()
            raise HTTPException(status_code=400, detail=f"Cannot send message with status '{existing[1]}'")
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute("UPDATE correspondence SET status = 'sent', sent_at = ?, updated_at = ? WHERE message_id = ?",
                     (now, now, message_id))
        conn.commit()
        conn.close()
        self.audit("correspondence_sent", {"message_id": message_id, "claim_id": existing[2]}, sent_by)
        return {"message_id": message_id, "status": "sent", "sent_at": now}

    def delete_correspondence(self, message_id: str) -> Dict[str, Any]:
        """Delete a correspondence message (only drafts)."""
        conn = _get_db()
        existing = conn.execute("SELECT message_id, status FROM correspondence WHERE message_id = ?",
                                (message_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Message not found")
        if existing[1] != "draft":
            conn.close()
            raise HTTPException(status_code=400, detail="Only draft messages can be deleted")
        conn.execute("DELETE FROM correspondence WHERE message_id = ?", (message_id,))
        conn.commit()
        conn.close()
        self.audit("correspondence_deleted", {"message_id": message_id}, "operator")
        return {"deleted": True, "message_id": message_id}

    def get_claim_correspondence(self, claim_id: str) -> Dict[str, Any]:
        """Get full correspondence timeline for a claim."""
        conn = _get_db()
        rows = conn.execute("""
            SELECT * FROM correspondence WHERE claim_id = ?
            ORDER BY created_at DESC
        """, (claim_id,)).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM correspondence LIMIT 0").description]
        conn.close()
        messages = [dict(zip(cols, r)) for r in rows]
        inbound = sum(1 for m in messages if m["direction"] == "inbound")
        outbound = sum(1 for m in messages if m["direction"] == "outbound")
        sent = sum(1 for m in messages if m["status"] == "sent")
        responded = sum(1 for m in messages if m["status"] == "responded")
        return {"claim_id": claim_id, "messages": messages, "total": len(messages),
                "inbound": inbound, "outbound": outbound, "sent": sent, "responded": responded}

    def get_correspondence_stats(self) -> Dict[str, Any]:
        """Get overall correspondence statistics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM correspondence").fetchone()[0]
        by_status = {}
        for row in conn.execute("SELECT status, COUNT(*) FROM correspondence GROUP BY status").fetchall():
            by_status[row[0]] = row[1]
        by_channel = {}
        for row in conn.execute("SELECT channel, COUNT(*) FROM correspondence GROUP BY channel").fetchall():
            by_channel[row[0]] = row[1]
        by_direction = {}
        for row in conn.execute("SELECT direction, COUNT(*) FROM correspondence GROUP BY direction").fetchall():
            by_direction[row[0]] = row[1]
        # Recent activity (last 30 days)
        cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"
        recent = conn.execute("SELECT COUNT(*) FROM correspondence WHERE created_at >= ?", (cutoff,)).fetchone()[0]
        # Response rate
        total_sent = by_status.get("sent", 0) + by_status.get("delivered", 0) + by_status.get("responded", 0)
        responded = by_status.get("responded", 0)
        response_rate = round(responded / total_sent * 100, 1) if total_sent > 0 else 0
        # Claims with correspondence
        claims_with = conn.execute("SELECT COUNT(DISTINCT claim_id) FROM correspondence").fetchone()[0]
        conn.close()
        return {
            "total_messages": total, "by_status": by_status, "by_channel": by_channel,
            "by_direction": by_direction, "recent_30d": recent,
            "response_rate_pct": response_rate, "claims_with_correspondence": claims_with,
        }

    # ── Compliance & Regulatory Framework Methods ──

    COMPLIANCE_CATEGORIES = ["general", "consumer_protection", "financial_regulation",
                             "data_privacy", "dispute_resolution", "reporting",
                             "anti_fraud", "licensing", "cross_border", "aml_kyc"]
    COMPLIANCE_SEVERITIES = ["low", "medium", "high", "critical"]
    COMPLIANCE_JURISDICTIONS = ["global", "us_federal", "us_state", "eu", "uk",
                                "canada", "australia", "international"]

    def create_compliance_rule(self, name: str, description: str = "",
                               category: str = "general", jurisdiction: str = "global",
                               applies_to: str = "all_claims", conditions: dict = None,
                               deadline_days: int = None, severity: str = "medium",
                               auto_flag: bool = False, created_by: str = "operator") -> Dict[str, Any]:
        """Create a new compliance/regulatory rule."""
        rule_id = f"CRL-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        conn.execute("""
            INSERT INTO compliance_rules
            (rule_id, name, description, category, jurisdiction, applies_to,
             conditions, deadline_days, severity, status, auto_flag, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
        """, (rule_id, name.strip(), description.strip(), category, jurisdiction,
              applies_to, json.dumps(conditions or {}), deadline_days, severity,
              1 if auto_flag else 0, created_by, now))
        conn.commit()
        conn.close()
        self.audit("compliance_rule_created", {"rule_id": rule_id, "name": name}, created_by)
        return {"rule_id": rule_id, "name": name, "category": category,
                "jurisdiction": jurisdiction, "severity": severity, "created_at": now}

    def list_compliance_rules(self, category: str = None, jurisdiction: str = None,
                              status: str = "active") -> Dict[str, Any]:
        """List compliance rules with optional filters."""
        conn = _get_db()
        sql = "SELECT * FROM compliance_rules WHERE 1=1"
        params = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if category:
            sql += " AND category = ?"
            params.append(category)
        if jurisdiction:
            sql += " AND jurisdiction = ?"
            params.append(jurisdiction)
        sql += " ORDER BY severity DESC, created_at DESC"
        rows = conn.execute(sql, params).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM compliance_rules LIMIT 0").description]
        conn.close()
        rules = []
        for r in rows:
            d = dict(zip(cols, r))
            d["conditions"] = json.loads(d.get("conditions", "{}"))
            d["auto_flag"] = bool(d.get("auto_flag", 0))
            rules.append(d)
        return {"rules": rules, "total": len(rules)}

    def get_compliance_rule(self, rule_id: str) -> Dict[str, Any]:
        """Get a single compliance rule."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM compliance_rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Compliance rule not found")
        cols = [d[0] for d in conn.execute("SELECT * FROM compliance_rules LIMIT 0").description]
        d = dict(zip(cols, row))
        d["conditions"] = json.loads(d.get("conditions", "{}"))
        d["auto_flag"] = bool(d.get("auto_flag", 0))
        # Get associated check stats
        stats = conn.execute("""
            SELECT status, COUNT(*) FROM compliance_checks
            WHERE rule_id = ? GROUP BY status
        """, (rule_id,)).fetchall()
        conn.close()
        d["check_stats"] = {s[0]: s[1] for s in stats}
        return d

    def update_compliance_rule(self, rule_id: str, updates: dict) -> Dict[str, Any]:
        """Update a compliance rule."""
        allowed = {"name", "description", "category", "jurisdiction", "applies_to",
                    "conditions", "deadline_days", "severity", "status", "auto_flag"}
        conn = _get_db()
        existing = conn.execute("SELECT rule_id FROM compliance_rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Compliance rule not found")
        sets, vals = [], []
        for k, v in updates.items():
            if k in allowed:
                if k == "conditions":
                    v = json.dumps(v)
                if k == "auto_flag":
                    v = 1 if v else 0
                sets.append(f"{k} = ?")
                vals.append(v)
        if sets:
            sets.append("updated_at = ?")
            vals.append(datetime.utcnow().isoformat() + "Z")
            vals.append(rule_id)
            conn.execute(f"UPDATE compliance_rules SET {', '.join(sets)} WHERE rule_id = ?", vals)
            conn.commit()
        conn.close()
        self.audit("compliance_rule_updated", {"rule_id": rule_id, "fields": list(updates.keys())}, "operator")
        return self.get_compliance_rule(rule_id)

    def delete_compliance_rule(self, rule_id: str) -> Dict[str, Any]:
        """Soft-delete a compliance rule by setting status to inactive."""
        conn = _get_db()
        existing = conn.execute("SELECT rule_id, name FROM compliance_rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Compliance rule not found")
        conn.execute("UPDATE compliance_rules SET status = 'inactive', updated_at = ? WHERE rule_id = ?",
                     (datetime.utcnow().isoformat() + "Z", rule_id))
        conn.commit()
        conn.close()
        self.audit("compliance_rule_deleted", {"rule_id": rule_id}, "operator")
        return {"deleted": True, "rule_id": rule_id}

    def run_compliance_check(self, claim_id: str, rule_ids: list = None,
                             checked_by: str = "system") -> Dict[str, Any]:
        """Run compliance checks against a claim. If rule_ids is None, checks all active rules."""
        conn = _get_db()
        claim = conn.execute("SELECT claim_id, vertical, amount_claimed_usd, status FROM claims WHERE claim_id = ?",
                             (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        now = datetime.utcnow().isoformat() + "Z"
        if rule_ids:
            rules_sql = f"SELECT * FROM compliance_rules WHERE status = 'active' AND rule_id IN ({','.join(['?']*len(rule_ids))})"
            rules = conn.execute(rules_sql, rule_ids).fetchall()
        else:
            rules = conn.execute("SELECT * FROM compliance_rules WHERE status = 'active'").fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM compliance_rules LIMIT 0").description]
        results = []
        for r in rules:
            rd = dict(zip(cols, r))
            conds = json.loads(rd.get("conditions", "{}"))
            # Evaluate applicability
            applies = True
            if rd["applies_to"] == "high_value" and (claim[2] or 0) < 10000:
                applies = False
            elif rd["applies_to"] == "escalated" and claim[3] != "escalated":
                applies = False
            elif rd["applies_to"] != "all_claims" and rd["applies_to"] not in ["high_value", "escalated"]:
                if rd["applies_to"] != claim[1]:  # vertical match
                    applies = False
            if not applies:
                continue
            # Check if already checked
            existing_check = conn.execute(
                "SELECT check_id, status FROM compliance_checks WHERE rule_id = ? AND claim_id = ?",
                (rd["rule_id"], claim_id)).fetchone()
            if existing_check:
                results.append({"rule_id": rd["rule_id"], "name": rd["name"],
                                "check_id": existing_check[0], "status": existing_check[1],
                                "already_checked": True})
                continue
            check_id = f"CCK-{uuid.uuid4().hex[:12].upper()}"
            due_at = None
            if rd.get("deadline_days"):
                due_at = (datetime.utcnow() + timedelta(days=rd["deadline_days"])).isoformat() + "Z"
            conn.execute("""
                INSERT INTO compliance_checks
                (check_id, rule_id, claim_id, status, checked_by, checked_at, due_at, created_at)
                VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)
            """, (check_id, rd["rule_id"], claim_id, checked_by, now, due_at, now))
            results.append({"rule_id": rd["rule_id"], "name": rd["name"],
                            "check_id": check_id, "status": "pending", "due_at": due_at,
                            "severity": rd["severity"], "already_checked": False})
        conn.commit()
        conn.close()
        self.audit("compliance_check_run", {"claim_id": claim_id, "checks_created": len([r for r in results if not r.get("already_checked")])}, checked_by)
        return {"claim_id": claim_id, "checks": results, "total": len(results)}

    def get_claim_compliance(self, claim_id: str) -> Dict[str, Any]:
        """Get all compliance checks for a claim."""
        conn = _get_db()
        rows = conn.execute("""
            SELECT cc.*, cr.name as rule_name, cr.category, cr.severity, cr.jurisdiction
            FROM compliance_checks cc
            JOIN compliance_rules cr ON cc.rule_id = cr.rule_id
            WHERE cc.claim_id = ?
            ORDER BY cr.severity DESC, cc.created_at DESC
        """, (claim_id,)).fetchall()
        cols = ["check_id", "rule_id", "claim_id", "status", "checked_by",
                "checked_at", "notes", "due_at", "created_at",
                "rule_name", "category", "severity", "jurisdiction"]
        conn.close()
        checks = [dict(zip(cols, r)) for r in rows]
        passed = sum(1 for c in checks if c["status"] == "passed")
        failed = sum(1 for c in checks if c["status"] == "failed")
        pending = sum(1 for c in checks if c["status"] == "pending")
        score = round(passed / len(checks) * 100) if checks else 100
        return {"claim_id": claim_id, "checks": checks, "total": len(checks),
                "passed": passed, "failed": failed, "pending": pending,
                "compliance_score": score}

    def resolve_compliance_check(self, check_id: str, status: str,
                                  notes: str = "", resolved_by: str = "operator") -> Dict[str, Any]:
        """Resolve a compliance check (pass/fail/waived)."""
        if status not in ("passed", "failed", "waived"):
            raise HTTPException(status_code=400, detail="status must be passed, failed, or waived")
        conn = _get_db()
        existing = conn.execute("SELECT check_id, rule_id, claim_id FROM compliance_checks WHERE check_id = ?",
                                (check_id,)).fetchone()
        if not existing:
            conn.close()
            raise HTTPException(status_code=404, detail="Compliance check not found")
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute("""
            UPDATE compliance_checks SET status = ?, notes = ?, checked_by = ?, checked_at = ?
            WHERE check_id = ?
        """, (status, notes, resolved_by, now, check_id))
        conn.commit()
        conn.close()
        self.audit("compliance_check_resolved", {"check_id": check_id, "status": status,
                                                  "rule_id": existing[1], "claim_id": existing[2]}, resolved_by)
        return {"check_id": check_id, "status": status, "resolved_at": now}

    def get_compliance_stats(self) -> Dict[str, Any]:
        """Get overall compliance statistics."""
        conn = _get_db()
        total_rules = conn.execute("SELECT COUNT(*) FROM compliance_rules WHERE status = 'active'").fetchone()[0]
        total_checks = conn.execute("SELECT COUNT(*) FROM compliance_checks").fetchone()[0]
        by_status = {}
        for row in conn.execute("SELECT status, COUNT(*) FROM compliance_checks GROUP BY status").fetchall():
            by_status[row[0]] = row[1]
        by_severity = {}
        for row in conn.execute("""
            SELECT cr.severity, COUNT(*)
            FROM compliance_checks cc JOIN compliance_rules cr ON cc.rule_id = cr.rule_id
            WHERE cc.status = 'failed'
            GROUP BY cr.severity
        """).fetchall():
            by_severity[row[0]] = row[1]
        overdue = conn.execute("""
            SELECT COUNT(*) FROM compliance_checks
            WHERE status = 'pending' AND due_at IS NOT NULL AND due_at < ?
        """, (datetime.utcnow().isoformat() + "Z",)).fetchone()[0]
        # Compliance score across all checked claims
        checked_claims = conn.execute("""
            SELECT claim_id, SUM(CASE WHEN status='passed' THEN 1 ELSE 0 END) as p,
                   SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as f,
                   COUNT(*) as t
            FROM compliance_checks GROUP BY claim_id
        """).fetchall()
        avg_score = 0
        if checked_claims:
            scores = [round(c[1] / c[3] * 100) for c in checked_claims if c[3] > 0]
            avg_score = round(sum(scores) / len(scores)) if scores else 0
        by_category = {}
        for row in conn.execute("""
            SELECT cr.category, COUNT(*)
            FROM compliance_rules cr WHERE cr.status = 'active' GROUP BY cr.category
        """).fetchall():
            by_category[row[0]] = row[1]
        conn.close()
        return {
            "active_rules": total_rules, "total_checks": total_checks,
            "checks_by_status": by_status, "failed_by_severity": by_severity,
            "overdue_checks": overdue, "avg_compliance_score": avg_score,
            "rules_by_category": by_category, "claims_checked": len(checked_claims),
        }

    def get_overdue_checks(self) -> Dict[str, Any]:
        """Get all overdue compliance checks."""
        conn = _get_db()
        now = datetime.utcnow().isoformat() + "Z"
        rows = conn.execute("""
            SELECT cc.*, cr.name as rule_name, cr.severity, cr.category
            FROM compliance_checks cc
            JOIN compliance_rules cr ON cc.rule_id = cr.rule_id
            WHERE cc.status = 'pending' AND cc.due_at IS NOT NULL AND cc.due_at < ?
            ORDER BY cr.severity DESC, cc.due_at ASC
        """, (now,)).fetchall()
        cols = ["check_id", "rule_id", "claim_id", "status", "checked_by",
                "checked_at", "notes", "due_at", "created_at",
                "rule_name", "severity", "category"]
        conn.close()
        return {"overdue": [dict(zip(cols, r)) for r in rows], "total": len(rows)}

    # ── Knowledge Base & SOPs Methods ──

    KB_CATEGORIES = ["general", "sop", "claim_handling", "escalation", "recovery",
                     "settlement", "compliance", "onboarding", "faq", "policy"]

    def create_article(self, title: str, content: str, category: str = "general",
                       tags: list = None, author: str = "operator",
                       priority: int = 0) -> Dict[str, Any]:
        """Create a new knowledge base article."""
        conn = _get_db()
        article_id = f"kb_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            """INSERT INTO kb_articles
               (article_id, title, content, category, tags, author, priority, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (article_id, title.strip(), content.strip(), category,
             json.dumps(tags or []), author, priority, now),
        )
        conn.commit()
        conn.close()
        self.audit("kb.article_created", {"article_id": article_id, "title": title, "category": category}, author)
        return {"article_id": article_id, "title": title, "category": category, "created_at": now}

    def list_articles(self, category: str = None, status: str = "published",
                      search_query: str = None) -> List[Dict[str, Any]]:
        """List knowledge base articles with optional filters."""
        conn = _get_db()
        query = "SELECT * FROM kb_articles WHERE 1=1"
        params: list = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if category:
            query += " AND category = ?"
            params.append(category)
        if search_query:
            query += " AND (LOWER(title) LIKE ? OR LOWER(content) LIKE ? OR LOWER(tags) LIKE ?)"
            sq = f"%{search_query.lower()}%"
            params.extend([sq, sq, sq])
        query += " ORDER BY priority DESC, helpful_votes DESC, created_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            results.append({
                "article_id": r["article_id"],
                "title": r["title"],
                "content": r["content"][:200] + ("..." if len(r["content"]) > 200 else ""),
                "full_content": r["content"],
                "category": r["category"],
                "tags": json.loads(r["tags"]) if r["tags"] else [],
                "author": r["author"],
                "status": r["status"],
                "priority": r["priority"],
                "helpful_votes": r["helpful_votes"],
                "view_count": r["view_count"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return results

    def get_article(self, article_id: str, increment_views: bool = True) -> Optional[Dict[str, Any]]:
        """Get a single article and optionally increment view count."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM kb_articles WHERE article_id = ?", (article_id,)).fetchone()
        if not row:
            conn.close()
            return None
        if increment_views:
            conn.execute("UPDATE kb_articles SET view_count = view_count + 1 WHERE article_id = ?", (article_id,))
            conn.commit()
        conn.close()
        return {
            "article_id": row["article_id"],
            "title": row["title"],
            "content": row["content"],
            "category": row["category"],
            "tags": json.loads(row["tags"]) if row["tags"] else [],
            "author": row["author"],
            "status": row["status"],
            "priority": row["priority"],
            "helpful_votes": row["helpful_votes"],
            "view_count": row["view_count"] + (1 if increment_views else 0),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def update_article(self, article_id: str, updates: dict) -> Dict[str, Any]:
        """Update a knowledge base article."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM kb_articles WHERE article_id = ?", (article_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Article {article_id} not found")
        allowed = {"title", "content", "category", "tags", "status", "priority"}
        sets = []
        params: list = []
        for k, v in updates.items():
            if k in allowed:
                if k == "tags":
                    v = json.dumps(v)
                sets.append(f"{k} = ?")
                params.append(v)
        if sets:
            sets.append("updated_at = ?")
            params.append(datetime.utcnow().isoformat() + "Z")
            params.append(article_id)
            conn.execute(f"UPDATE kb_articles SET {', '.join(sets)} WHERE article_id = ?", params)
            conn.commit()
        conn.close()
        self.audit("kb.article_updated", {"article_id": article_id, "updates": list(updates.keys())}, "operator")
        return self.get_article(article_id, increment_views=False)

    def delete_article(self, article_id: str) -> bool:
        """Delete a knowledge base article."""
        conn = _get_db()
        row = conn.execute("SELECT article_id FROM kb_articles WHERE article_id = ?", (article_id,)).fetchone()
        if not row:
            conn.close()
            return False
        conn.execute("DELETE FROM kb_articles WHERE article_id = ?", (article_id,))
        conn.commit()
        conn.close()
        self.audit("kb.article_deleted", {"article_id": article_id}, "operator")
        return True

    def vote_article(self, article_id: str) -> Dict[str, Any]:
        """Upvote an article as helpful."""
        conn = _get_db()
        row = conn.execute("SELECT helpful_votes FROM kb_articles WHERE article_id = ?", (article_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Article {article_id} not found")
        new_votes = row["helpful_votes"] + 1
        conn.execute("UPDATE kb_articles SET helpful_votes = ? WHERE article_id = ?", (new_votes, article_id))
        conn.commit()
        conn.close()
        return {"article_id": article_id, "helpful_votes": new_votes}

    def get_kb_stats(self) -> Dict[str, Any]:
        """Knowledge base dashboard statistics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM kb_articles").fetchone()[0]
        published = conn.execute("SELECT COUNT(*) FROM kb_articles WHERE status = 'published'").fetchone()[0]
        total_views = conn.execute("SELECT COALESCE(SUM(view_count), 0) FROM kb_articles").fetchone()[0]
        total_votes = conn.execute("SELECT COALESCE(SUM(helpful_votes), 0) FROM kb_articles").fetchone()[0]

        by_category = {}
        for row in conn.execute("SELECT category, COUNT(*) as cnt FROM kb_articles WHERE status = 'published' GROUP BY category").fetchall():
            by_category[row[0]] = row[1]

        popular = conn.execute(
            "SELECT article_id, title, category, view_count, helpful_votes FROM kb_articles WHERE status = 'published' ORDER BY view_count DESC LIMIT 5"
        ).fetchall()

        conn.close()
        return {
            "total": total,
            "published": published,
            "draft": total - published,
            "total_views": total_views,
            "total_votes": total_votes,
            "by_category": by_category,
            "popular": [{"article_id": r[0], "title": r[1], "category": r[2], "views": r[3], "votes": r[4]} for r in popular],
        }

    # ── Claim Templates Methods ──

    TEMPLATE_CATEGORIES = ["general", "financial_fraud", "service_failure", "data_breach",
                           "harassment", "unauthorized_charge", "ecommerce", "fintech", "custom"]

    def create_template(self, name: str, category: str = "general", vertical: str = "platform_dispute",
                        harm_type: str = "", description: str = "", default_fields: dict = None,
                        field_prompts: dict = None, created_by: str = "operator") -> Dict[str, Any]:
        """Create a claim template with default field values and prompts."""
        conn = _get_db()
        template_id = f"tpl_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            """INSERT INTO claim_templates
               (template_id, name, description, category, vertical, harm_type,
                default_fields, field_prompts, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (template_id, name.strip(), description.strip(), category, vertical, harm_type,
             json.dumps(default_fields or {}), json.dumps(field_prompts or {}), created_by, now),
        )
        conn.commit()
        conn.close()
        self.audit("template.created", {"template_id": template_id, "name": name, "category": category}, created_by)
        return {"template_id": template_id, "name": name, "category": category, "created_at": now}

    def list_templates(self, category: str = None, active_only: bool = True) -> List[Dict[str, Any]]:
        """List claim templates with optional filters."""
        conn = _get_db()
        query = "SELECT * FROM claim_templates WHERE 1=1"
        params: list = []
        if active_only:
            query += " AND is_active = 1"
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY use_count DESC, name ASC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            results.append({
                "template_id": r["template_id"],
                "name": r["name"],
                "description": r["description"],
                "category": r["category"],
                "vertical": r["vertical"],
                "harm_type": r["harm_type"],
                "default_fields": json.loads(r["default_fields"]) if r["default_fields"] else {},
                "field_prompts": json.loads(r["field_prompts"]) if r["field_prompts"] else {},
                "is_active": bool(r["is_active"]),
                "use_count": r["use_count"],
                "created_by": r["created_by"],
                "created_at": r["created_at"],
            })
        return results

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Get a single template by ID."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM claim_templates WHERE template_id = ?", (template_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "template_id": row["template_id"],
            "name": row["name"],
            "description": row["description"],
            "category": row["category"],
            "vertical": row["vertical"],
            "harm_type": row["harm_type"],
            "default_fields": json.loads(row["default_fields"]) if row["default_fields"] else {},
            "field_prompts": json.loads(row["field_prompts"]) if row["field_prompts"] else {},
            "is_active": bool(row["is_active"]),
            "use_count": row["use_count"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def update_template(self, template_id: str, updates: dict) -> Dict[str, Any]:
        """Update a claim template."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM claim_templates WHERE template_id = ?", (template_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Template {template_id} not found")
        allowed = {"name", "description", "category", "vertical", "harm_type",
                    "default_fields", "field_prompts", "is_active"}
        sets = []
        params: list = []
        for k, v in updates.items():
            if k in allowed:
                if k in ("default_fields", "field_prompts"):
                    v = json.dumps(v)
                if k == "is_active":
                    v = 1 if v else 0
                sets.append(f"{k} = ?")
                params.append(v)
        if sets:
            sets.append("updated_at = ?")
            params.append(datetime.utcnow().isoformat() + "Z")
            params.append(template_id)
            conn.execute(f"UPDATE claim_templates SET {', '.join(sets)} WHERE template_id = ?", params)
            conn.commit()
        conn.close()
        self.audit("template.updated", {"template_id": template_id, "updates": list(updates.keys())}, "operator")
        return self.get_template(template_id)

    def delete_template(self, template_id: str) -> bool:
        """Delete a claim template."""
        conn = _get_db()
        row = conn.execute("SELECT template_id FROM claim_templates WHERE template_id = ?", (template_id,)).fetchone()
        if not row:
            conn.close()
            return False
        conn.execute("DELETE FROM claim_templates WHERE template_id = ?", (template_id,))
        conn.commit()
        conn.close()
        self.audit("template.deleted", {"template_id": template_id}, "operator")
        return True

    def instantiate_template(self, template_id: str, overrides: dict = None,
                             created_by: str = "operator") -> Dict[str, Any]:
        """Create a new claim from a template, with optional field overrides."""
        tpl = self.get_template(template_id)
        if not tpl:
            raise ValueError(f"Template {template_id} not found")

        defaults = tpl.get("default_fields", {})
        if overrides:
            defaults.update(overrides)

        # Build claim data
        claim_data = {
            "vertical": defaults.get("vertical", tpl["vertical"]),
            "status": "filed",
            "claimant_name": defaults.get("claimant_name", ""),
            "claimant_email": defaults.get("claimant_email", ""),
            "respondent_entity": defaults.get("respondent_entity", tpl.get("default_fields", {}).get("respondent_entity", "")),
            "harm_type": defaults.get("harm_type", tpl["harm_type"]),
            "amount_claimed_usd": float(defaults.get("amount_claimed_usd", 0)),
            "description": defaults.get("description", tpl.get("description", "")),
            "contacted_support": defaults.get("contacted_support", "unknown"),
            "referral_source": defaults.get("referral_source", "template"),
            "execution_score": 0,
        }

        # Must have at least claimant_name
        if not claim_data["claimant_name"]:
            raise ValueError("claimant_name is required (provide in overrides)")

        # Save claim
        claim_id = self.save_claim(claim_data)

        # Increment template use count
        conn = _get_db()
        conn.execute("UPDATE claim_templates SET use_count = use_count + 1 WHERE template_id = ?", (template_id,))
        conn.commit()
        conn.close()

        self.audit("template.instantiated", {
            "template_id": template_id, "template_name": tpl["name"],
            "claim_id": claim_id, "overrides": list((overrides or {}).keys()),
        }, created_by)

        return {
            "claim_id": claim_id,
            "template_id": template_id,
            "template_name": tpl["name"],
            "fields_applied": list(claim_data.keys()),
            "overrides_applied": list((overrides or {}).keys()),
        }

    def get_template_stats(self) -> Dict[str, Any]:
        """Dashboard stats for templates."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM claim_templates").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM claim_templates WHERE is_active = 1").fetchone()[0]
        total_uses = conn.execute("SELECT COALESCE(SUM(use_count), 0) FROM claim_templates").fetchone()[0]

        by_category = {}
        for row in conn.execute("SELECT category, COUNT(*) as cnt FROM claim_templates WHERE is_active = 1 GROUP BY category").fetchall():
            by_category[row[0]] = row[1]

        top_used = conn.execute(
            "SELECT template_id, name, category, use_count FROM claim_templates WHERE is_active = 1 ORDER BY use_count DESC LIMIT 5"
        ).fetchall()

        conn.close()
        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "total_uses": total_uses,
            "by_category": by_category,
            "top_used": [{"template_id": r[0], "name": r[1], "category": r[2], "use_count": r[3]} for r in top_used],
        }

    # ── Reminders & Follow-up Scheduler Methods ──

    REMINDER_TYPES = ["manual", "idle_claim", "sla_warning", "follow_up", "escalation_check", "recurring"]

    def create_reminder(self, title: str, due_at: str, claim_id: str = None,
                        description: str = "", reminder_type: str = "manual",
                        priority: str = "normal", assigned_to: str = "operator",
                        created_by: str = "operator", recurrence: str = None) -> Dict[str, Any]:
        """Create a new reminder."""
        conn = _get_db()
        reminder_id = f"rem_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            """INSERT INTO reminders
               (reminder_id, claim_id, title, description, reminder_type, due_at,
                status, priority, assigned_to, created_by, created_at, recurrence)
               VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)""",
            (reminder_id, claim_id, title.strip(), description.strip(),
             reminder_type, due_at, priority, assigned_to, created_by, now, recurrence),
        )
        conn.commit()
        conn.close()
        self.audit("reminder.created", {
            "reminder_id": reminder_id, "claim_id": claim_id,
            "title": title, "due_at": due_at, "type": reminder_type,
        }, created_by)
        return {"reminder_id": reminder_id, "title": title, "due_at": due_at, "status": "pending", "created_at": now}

    def list_reminders(self, status_filter: str = None, claim_id: str = None,
                       assigned_to: str = None, include_snoozed: bool = True) -> List[Dict[str, Any]]:
        """List reminders with optional filters."""
        conn = _get_db()
        query = "SELECT * FROM reminders WHERE 1=1"
        params: list = []
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        if claim_id:
            query += " AND claim_id = ?"
            params.append(claim_id)
        if assigned_to:
            query += " AND assigned_to = ?"
            params.append(assigned_to)
        if not include_snoozed:
            query += " AND (snoozed_until IS NULL OR snoozed_until <= ?)"
            params.append(datetime.utcnow().isoformat() + "Z")
        query += " ORDER BY CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 END, due_at ASC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_reminder(self, reminder_id: str) -> Optional[Dict[str, Any]]:
        """Get a single reminder."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM reminders WHERE reminder_id = ?", (reminder_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def update_reminder(self, reminder_id: str, updates: dict) -> Dict[str, Any]:
        """Update a reminder."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM reminders WHERE reminder_id = ?", (reminder_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Reminder {reminder_id} not found")
        allowed = {"title", "description", "due_at", "priority", "assigned_to", "status", "recurrence"}
        sets = []
        params: list = []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                params.append(v)
        if sets:
            params.append(reminder_id)
            conn.execute(f"UPDATE reminders SET {', '.join(sets)} WHERE reminder_id = ?", params)
            conn.commit()
        conn.close()
        self.audit("reminder.updated", {"reminder_id": reminder_id, "updates": list(updates.keys())}, "operator")
        return self.get_reminder(reminder_id)

    def complete_reminder(self, reminder_id: str, completed_by: str = "operator") -> Dict[str, Any]:
        """Mark a reminder as completed. If recurring, auto-create the next one."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM reminders WHERE reminder_id = ?", (reminder_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Reminder {reminder_id} not found")
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "UPDATE reminders SET status = 'completed', completed_at = ? WHERE reminder_id = ?",
            (now, reminder_id),
        )
        conn.commit()
        conn.close()
        self.audit("reminder.completed", {"reminder_id": reminder_id}, completed_by)

        # Handle recurrence
        recurrence = row["recurrence"]
        if recurrence and recurrence in ("daily", "weekly", "biweekly", "monthly"):
            old_due = datetime.fromisoformat(row["due_at"].replace("Z", "+00:00").replace("+00:00", ""))
            if recurrence == "daily":
                next_due = old_due + timedelta(days=1)
            elif recurrence == "weekly":
                next_due = old_due + timedelta(weeks=1)
            elif recurrence == "biweekly":
                next_due = old_due + timedelta(weeks=2)
            else:
                next_due = old_due + timedelta(days=30)
            self.create_reminder(
                title=row["title"], due_at=next_due.isoformat() + "Z",
                claim_id=row["claim_id"], description=row["description"],
                reminder_type=row["reminder_type"], priority=row["priority"],
                assigned_to=row["assigned_to"], created_by="system",
                recurrence=recurrence,
            )

        return {"reminder_id": reminder_id, "status": "completed", "completed_at": now}

    def snooze_reminder(self, reminder_id: str, snooze_until: str) -> Dict[str, Any]:
        """Snooze a reminder until a future date."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM reminders WHERE reminder_id = ?", (reminder_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Reminder {reminder_id} not found")
        conn.execute(
            "UPDATE reminders SET snoozed_until = ?, status = 'snoozed' WHERE reminder_id = ?",
            (snooze_until, reminder_id),
        )
        conn.commit()
        conn.close()
        self.audit("reminder.snoozed", {"reminder_id": reminder_id, "until": snooze_until}, "operator")
        return {"reminder_id": reminder_id, "status": "snoozed", "snoozed_until": snooze_until}

    def dismiss_reminder(self, reminder_id: str) -> bool:
        """Dismiss a reminder."""
        conn = _get_db()
        row = conn.execute("SELECT reminder_id FROM reminders WHERE reminder_id = ?", (reminder_id,)).fetchone()
        if not row:
            conn.close()
            return False
        conn.execute("UPDATE reminders SET status = 'dismissed' WHERE reminder_id = ?", (reminder_id,))
        conn.commit()
        conn.close()
        self.audit("reminder.dismissed", {"reminder_id": reminder_id}, "operator")
        return True

    def get_due_reminders(self, look_ahead_hours: int = 24) -> Dict[str, Any]:
        """Get reminders that are due or coming due soon."""
        conn = _get_db()
        now = datetime.utcnow()
        cutoff = (now + timedelta(hours=look_ahead_hours)).isoformat() + "Z"
        now_str = now.isoformat() + "Z"

        # Overdue
        overdue = conn.execute(
            "SELECT * FROM reminders WHERE status = 'pending' AND due_at < ? ORDER BY due_at ASC",
            (now_str,),
        ).fetchall()

        # Due soon (within look-ahead window)
        due_soon = conn.execute(
            "SELECT * FROM reminders WHERE status = 'pending' AND due_at >= ? AND due_at <= ? ORDER BY due_at ASC",
            (now_str, cutoff),
        ).fetchall()

        # Unsnoozed (snooze expired)
        unsnoozed = conn.execute(
            "SELECT * FROM reminders WHERE status = 'snoozed' AND snoozed_until <= ?",
            (now_str,),
        ).fetchall()
        # Auto-unsnooze
        for r in unsnoozed:
            conn.execute("UPDATE reminders SET status = 'pending', snoozed_until = NULL WHERE reminder_id = ?",
                         (r["reminder_id"],))
        if unsnoozed:
            conn.commit()

        conn.close()
        return {
            "overdue": [dict(r) for r in overdue],
            "overdue_count": len(overdue),
            "due_soon": [dict(r) for r in due_soon],
            "due_soon_count": len(due_soon),
            "unsnoozed": len(unsnoozed),
            "look_ahead_hours": look_ahead_hours,
            "checked_at": now_str,
        }

    def get_reminder_stats(self) -> Dict[str, Any]:
        """Dashboard stats for reminders."""
        conn = _get_db()
        now_str = datetime.utcnow().isoformat() + "Z"
        total = conn.execute("SELECT COUNT(*) FROM reminders").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM reminders WHERE status = 'pending'").fetchone()[0]
        overdue = conn.execute("SELECT COUNT(*) FROM reminders WHERE status = 'pending' AND due_at < ?", (now_str,)).fetchone()[0]
        completed = conn.execute("SELECT COUNT(*) FROM reminders WHERE status = 'completed'").fetchone()[0]
        snoozed = conn.execute("SELECT COUNT(*) FROM reminders WHERE status = 'snoozed'").fetchone()[0]

        # Type breakdown
        by_type = {}
        for row in conn.execute("SELECT reminder_type, COUNT(*) as cnt FROM reminders WHERE status = 'pending' GROUP BY reminder_type").fetchall():
            by_type[row[0]] = row[1]

        # Priority breakdown
        by_priority = {}
        for row in conn.execute("SELECT priority, COUNT(*) as cnt FROM reminders WHERE status = 'pending' GROUP BY priority").fetchall():
            by_priority[row[0]] = row[1]

        # Upcoming 5
        upcoming = conn.execute(
            "SELECT * FROM reminders WHERE status = 'pending' ORDER BY due_at ASC LIMIT 5"
        ).fetchall()

        conn.close()
        return {
            "total": total,
            "pending": pending,
            "overdue": overdue,
            "completed": completed,
            "snoozed": snoozed,
            "by_type": by_type,
            "by_priority": by_priority,
            "upcoming": [dict(r) for r in upcoming],
            "completion_rate_pct": round(completed / total * 100, 1) if total > 0 else 0,
        }

    def generate_idle_reminders(self, idle_days: int = 14) -> Dict[str, Any]:
        """Auto-generate reminders for claims that have been idle."""
        conn = _get_db()
        cutoff = (datetime.utcnow() - timedelta(days=idle_days)).isoformat() + "Z"
        now_str = datetime.utcnow().isoformat() + "Z"

        # Find claims with no recent activity (no notes, no audit entries mentioning them)
        idle_claims = conn.execute("""
            SELECT c.claim_id, c.claimant_name, c.respondent_entity, c.status, c.updated_at
            FROM claims c
            WHERE c.status NOT IN ('resolved', 'dismissed', 'closed')
            AND (c.updated_at IS NULL OR c.updated_at < ?)
            AND c.claim_id NOT IN (
                SELECT DISTINCT claim_id FROM reminders
                WHERE reminder_type = 'idle_claim' AND status = 'pending'
            )
        """, (cutoff,)).fetchall()

        created = 0
        for claim in idle_claims:
            due = (datetime.utcnow() + timedelta(days=1)).isoformat() + "Z"
            rid = f"rem_{uuid.uuid4().hex[:12]}"
            conn.execute(
                """INSERT INTO reminders
                   (reminder_id, claim_id, title, description, reminder_type, due_at,
                    status, priority, assigned_to, created_by, created_at)
                   VALUES (?, ?, ?, ?, 'idle_claim', ?, 'pending', 'high', 'operator', 'system', ?)""",
                (rid, claim["claim_id"],
                 f"Idle claim: {claim['claimant_name']} vs {claim['respondent_entity']}",
                 f"Claim {claim['claim_id']} has been idle for {idle_days}+ days (status: {claim['status']}). Review and take action.",
                 due, now_str),
            )
            created += 1

        if created:
            conn.commit()
        conn.close()
        self.audit("reminders.idle_generated", {"idle_days": idle_days, "created": created}, "system")
        return {"idle_days": idle_days, "claims_checked": len(idle_claims) + created, "reminders_created": created}

    # ── Saved Searches & Smart Filters Methods ──

    def create_saved_search(self, name: str, filters: dict, description: str = "",
                            sort_by: str = "filed_at", sort_order: str = "desc",
                            created_by: str = "operator") -> Dict[str, Any]:
        """Create a new saved search."""
        conn = _get_db()
        search_id = f"ss_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            """INSERT INTO saved_searches
               (search_id, name, description, filters, sort_by, sort_order, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (search_id, name.strip(), description.strip(), json.dumps(filters),
             sort_by, sort_order, created_by, now),
        )
        conn.commit()
        conn.close()
        self.audit("saved_search.created", {"search_id": search_id, "name": name}, created_by)
        return {"search_id": search_id, "name": name, "created_at": now}

    def list_saved_searches(self, created_by: str = None, pinned_only: bool = False) -> List[Dict[str, Any]]:
        """List saved searches with optional filters."""
        conn = _get_db()
        query = "SELECT * FROM saved_searches WHERE 1=1"
        params: list = []
        if created_by:
            query += " AND created_by = ?"
            params.append(created_by)
        if pinned_only:
            query += " AND is_pinned = 1"
        query += " ORDER BY is_pinned DESC, use_count DESC, created_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            results.append({
                "search_id": r["search_id"],
                "name": r["name"],
                "description": r["description"],
                "filters": json.loads(r["filters"]) if r["filters"] else {},
                "sort_by": r["sort_by"],
                "sort_order": r["sort_order"],
                "created_by": r["created_by"],
                "created_at": r["created_at"],
                "last_used": r["last_used"],
                "use_count": r["use_count"],
                "is_pinned": bool(r["is_pinned"]),
            })
        return results

    def get_saved_search(self, search_id: str) -> Optional[Dict[str, Any]]:
        """Get a single saved search by ID."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM saved_searches WHERE search_id = ?", (search_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "search_id": row["search_id"],
            "name": row["name"],
            "description": row["description"],
            "filters": json.loads(row["filters"]) if row["filters"] else {},
            "sort_by": row["sort_by"],
            "sort_order": row["sort_order"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "last_used": row["last_used"],
            "use_count": row["use_count"],
            "is_pinned": bool(row["is_pinned"]),
        }

    def update_saved_search(self, search_id: str, updates: dict) -> Dict[str, Any]:
        """Update a saved search."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM saved_searches WHERE search_id = ?", (search_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Saved search {search_id} not found")
        allowed = {"name", "description", "filters", "sort_by", "sort_order", "is_pinned"}
        sets = []
        params: list = []
        for k, v in updates.items():
            if k in allowed:
                if k == "filters":
                    v = json.dumps(v)
                if k == "is_pinned":
                    v = 1 if v else 0
                sets.append(f"{k} = ?")
                params.append(v)
        if sets:
            params.append(search_id)
            conn.execute(f"UPDATE saved_searches SET {', '.join(sets)} WHERE search_id = ?", params)
            conn.commit()
        conn.close()
        self.audit("saved_search.updated", {"search_id": search_id, "updates": list(updates.keys())}, "operator")
        return self.get_saved_search(search_id)

    def delete_saved_search(self, search_id: str) -> bool:
        """Delete a saved search."""
        conn = _get_db()
        row = conn.execute("SELECT search_id FROM saved_searches WHERE search_id = ?", (search_id,)).fetchone()
        if not row:
            conn.close()
            return False
        conn.execute("DELETE FROM saved_searches WHERE search_id = ?", (search_id,))
        conn.commit()
        conn.close()
        self.audit("saved_search.deleted", {"search_id": search_id}, "operator")
        return True

    def toggle_pin_saved_search(self, search_id: str) -> Dict[str, Any]:
        """Toggle the pinned state of a saved search."""
        conn = _get_db()
        row = conn.execute("SELECT is_pinned FROM saved_searches WHERE search_id = ?", (search_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Saved search {search_id} not found")
        new_val = 0 if row["is_pinned"] else 1
        conn.execute("UPDATE saved_searches SET is_pinned = ? WHERE search_id = ?", (new_val, search_id))
        conn.commit()
        conn.close()
        return {"search_id": search_id, "is_pinned": bool(new_val)}

    def execute_saved_search(self, search_id: str) -> Dict[str, Any]:
        """Execute a saved search and return matching claims."""
        search = self.get_saved_search(search_id)
        if not search:
            raise ValueError(f"Saved search {search_id} not found")

        filters = search["filters"]
        sort_by = search.get("sort_by", "filed_at")
        sort_order = search.get("sort_order", "desc")

        # Build dynamic query
        conn = _get_db()
        query = "SELECT data FROM claims WHERE 1=1"
        params: list = []

        if filters.get("status"):
            query += " AND status = ?"
            params.append(filters["status"])
        if filters.get("respondent"):
            query += " AND LOWER(respondent_entity) LIKE ?"
            params.append(f"%{filters['respondent'].lower()}%")
        if filters.get("vertical"):
            query += " AND vertical = ?"
            params.append(filters["vertical"])
        if filters.get("harm_type"):
            query += " AND harm_type = ?"
            params.append(filters["harm_type"])
        if filters.get("claimant_name"):
            query += " AND LOWER(claimant_name) LIKE ?"
            params.append(f"%{filters['claimant_name'].lower()}%")
        if filters.get("claimant_email"):
            query += " AND LOWER(claimant_email) LIKE ?"
            params.append(f"%{filters['claimant_email'].lower()}%")
        if filters.get("min_amount"):
            query += " AND amount_claimed_usd >= ?"
            params.append(float(filters["min_amount"]))
        if filters.get("max_amount"):
            query += " AND amount_claimed_usd <= ?"
            params.append(float(filters["max_amount"]))
        if filters.get("filed_after"):
            query += " AND filed_at >= ?"
            params.append(filters["filed_after"])
        if filters.get("filed_before"):
            query += " AND filed_at <= ?"
            params.append(filters["filed_before"])

        # Sort
        valid_sorts = {"filed_at", "amount_claimed_usd", "status", "claimant_name", "respondent_entity", "updated_at"}
        if sort_by not in valid_sorts:
            sort_by = "filed_at"
        direction = "DESC" if sort_order.lower() == "desc" else "ASC"
        query += f" ORDER BY {sort_by} {direction}"

        rows = conn.execute(query, params).fetchall()
        claims = [json.loads(r["data"]) for r in rows]

        # Update use stats
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "UPDATE saved_searches SET last_used = ?, use_count = use_count + 1 WHERE search_id = ?",
            (now, search_id),
        )
        conn.commit()
        conn.close()

        return {
            "search_id": search_id,
            "name": search["name"],
            "filters": filters,
            "total_results": len(claims),
            "claims": claims,
        }

    # ── Webhook & Integration Methods ──

    WEBHOOK_EVENTS = [
        "claim.created", "claim.status_changed", "claim.escalated",
        "recovery.recorded", "settlement.created", "settlement.updated",
        "note.added", "document.uploaded", "tag.applied",
        "bulk.status_change", "bulk.assign", "bulk.escalate",
        "merge.completed", "triage.override",
    ]

    def register_webhook(self, url: str, events: List[str] = None, secret: str = "",
                         description: str = "", created_by: str = "operator") -> Dict[str, Any]:
        """Register a new webhook endpoint."""
        webhook_id = f"wh_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        if events is None or events == ["*"]:
            events = ["*"]
        else:
            invalid = [e for e in events if e not in self.WEBHOOK_EVENTS and e != "*"]
            if invalid:
                return {"error": f"Invalid events: {', '.join(invalid)}"}
        if not secret:
            secret = uuid.uuid4().hex
        conn = _get_db()
        conn.execute(
            "INSERT INTO webhooks (webhook_id, url, events, secret, status, description, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (webhook_id, url, json.dumps(events), secret, "active", description, created_by, now)
        )
        conn.commit()
        conn.close()
        self.audit("webhook.registered", {"webhook_id": webhook_id, "url": url, "events": events}, created_by)
        return {"webhook_id": webhook_id, "url": url, "events": events, "secret": secret, "status": "active", "created_at": now}

    def list_webhooks(self, status: str = None) -> List[Dict[str, Any]]:
        """List all registered webhooks."""
        conn = _get_db()
        if status:
            rows = conn.execute("SELECT * FROM webhooks WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["events"] = json.loads(d.get("events", '["*"]'))
            results.append(d)
        return results

    def get_webhook(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """Get a single webhook by ID."""
        conn = _get_db()
        r = conn.execute("SELECT * FROM webhooks WHERE webhook_id = ?", (webhook_id,)).fetchone()
        conn.close()
        if not r:
            return None
        d = dict(r)
        d["events"] = json.loads(d.get("events", '["*"]'))
        return d

    def update_webhook(self, webhook_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update webhook configuration."""
        conn = _get_db()
        wh = conn.execute("SELECT * FROM webhooks WHERE webhook_id = ?", (webhook_id,)).fetchone()
        if not wh:
            conn.close()
            return {"error": "webhook_not_found"}
        allowed = {"url", "events", "secret", "status", "description"}
        sets = []
        vals = []
        for k, v in updates.items():
            if k in allowed:
                if k == "events":
                    v = json.dumps(v)
                sets.append(f"{k} = ?")
                vals.append(v)
        if sets:
            vals.append(webhook_id)
            conn.execute(f"UPDATE webhooks SET {', '.join(sets)} WHERE webhook_id = ?", vals)
            conn.commit()
        conn.close()
        return self.get_webhook(webhook_id) or {"error": "update_failed"}

    def delete_webhook(self, webhook_id: str) -> Dict[str, Any]:
        """Delete a webhook and its deliveries."""
        conn = _get_db()
        wh = conn.execute("SELECT webhook_id FROM webhooks WHERE webhook_id = ?", (webhook_id,)).fetchone()
        if not wh:
            conn.close()
            return {"error": "webhook_not_found"}
        conn.execute("DELETE FROM webhook_deliveries WHERE webhook_id = ?", (webhook_id,))
        conn.execute("DELETE FROM webhooks WHERE webhook_id = ?", (webhook_id,))
        conn.commit()
        conn.close()
        return {"deleted": webhook_id}

    def fire_webhooks(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Fire all active webhooks that subscribe to this event (non-blocking record)."""
        conn = _get_db()
        hooks = conn.execute("SELECT * FROM webhooks WHERE status = 'active'").fetchall()
        fired = 0
        for hook in hooks:
            events = json.loads(hook["events"] or '["*"]')
            if "*" not in events and event not in events:
                continue
            delivery_id = f"dlv_{uuid.uuid4().hex[:12]}"
            now = datetime.utcnow().isoformat() + "Z"
            full_payload = {
                "event": event,
                "timestamp": now,
                "webhook_id": hook["webhook_id"],
                "data": payload,
            }
            # Record the delivery attempt (actual HTTP delivery would be async in production)
            conn.execute(
                "INSERT INTO webhook_deliveries (delivery_id, webhook_id, event, payload, status_code, response, success, delivered_at) VALUES (?,?,?,?,?,?,?,?)",
                (delivery_id, hook["webhook_id"], event, json.dumps(full_payload), 200, "queued", 1, now)
            )
            conn.execute(
                "UPDATE webhooks SET last_triggered = ? WHERE webhook_id = ?",
                (now, hook["webhook_id"])
            )
            fired += 1
        conn.commit()
        conn.close()
        return {"event": event, "webhooks_fired": fired}

    def get_webhook_deliveries(self, webhook_id: str = None, event: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get webhook delivery history."""
        conn = _get_db()
        query = "SELECT * FROM webhook_deliveries"
        params = []
        conditions = []
        if webhook_id:
            conditions.append("webhook_id = ?")
            params.append(webhook_id)
        if event:
            conditions.append("event = ?")
            params.append(event)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY delivered_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d.get("payload", "{}"))
            except (json.JSONDecodeError, TypeError):
                pass
            results.append(d)
        return results

    def get_webhook_stats(self) -> Dict[str, Any]:
        """Get webhook system statistics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) as c FROM webhooks").fetchone()["c"]
        active = conn.execute("SELECT COUNT(*) as c FROM webhooks WHERE status = 'active'").fetchone()["c"]
        deliveries_total = conn.execute("SELECT COUNT(*) as c FROM webhook_deliveries").fetchone()["c"]
        deliveries_success = conn.execute("SELECT COUNT(*) as c FROM webhook_deliveries WHERE success = 1").fetchone()["c"]
        recent = conn.execute(
            "SELECT event, COUNT(*) as c FROM webhook_deliveries GROUP BY event ORDER BY c DESC LIMIT 10"
        ).fetchall()
        conn.close()
        return {
            "total_webhooks": total,
            "active_webhooks": active,
            "total_deliveries": deliveries_total,
            "successful_deliveries": deliveries_success,
            "delivery_rate": round(deliveries_success / max(deliveries_total, 1) * 100, 1),
            "events_breakdown": {r["event"]: r["c"] for r in recent},
        }

    # ── Bulk Operations Methods ──

    def bulk_update_status(self, claim_ids: List[str], new_status: str, performed_by: str = "operator") -> Dict[str, Any]:
        """Bulk update status for multiple claims."""
        valid_statuses = ["open", "under_review", "escalated", "resolved", "closed", "pending", "in_progress"]
        if new_status not in valid_statuses:
            return {"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"}
        conn = _get_db()
        updated = 0
        skipped = 0
        errors = []
        for cid in claim_ids:
            claim = conn.execute("SELECT claim_id, status FROM claims WHERE claim_id = ?", (cid,)).fetchone()
            if not claim:
                errors.append({"claim_id": cid, "reason": "not_found"})
                skipped += 1
                continue
            if claim["status"] == new_status:
                skipped += 1
                continue
            old_status = claim["status"]
            conn.execute("UPDATE claims SET status = ? WHERE claim_id = ?", (new_status, cid))
            updated += 1
        conn.commit()
        conn.close()
        self.audit("bulk.status_change", {"count": updated, "new_status": new_status}, performed_by)
        return {"updated": updated, "skipped": skipped, "errors": errors, "new_status": new_status}

    def bulk_assign(self, claim_ids: List[str], operator_id: str, performed_by: str = "operator") -> Dict[str, Any]:
        """Bulk assign multiple claims to an operator."""
        conn = _get_db()
        # Verify operator exists
        op = conn.execute("SELECT operator_id FROM operators WHERE operator_id = ?", (operator_id,)).fetchone()
        if not op:
            conn.close()
            return {"assigned": 0, "skipped": len(claim_ids), "errors": [{"reason": f"operator '{operator_id}' not found"}], "operator_id": operator_id}
        assigned = 0
        skipped = 0
        errors = []
        now = datetime.utcnow().isoformat() + "Z"
        for cid in claim_ids:
            claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (cid,)).fetchone()
            if not claim:
                errors.append({"claim_id": cid, "reason": "not_found"})
                skipped += 1
                continue
            existing = conn.execute("SELECT operator_id FROM assignments WHERE claim_id = ?", (cid,)).fetchone()
            if existing and existing["operator_id"] == operator_id:
                skipped += 1
                continue
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO assignments (claim_id, operator_id, assigned_at, assigned_by) VALUES (?,?,?,?)",
                    (cid, operator_id, now, performed_by)
                )
                assigned += 1
            except Exception:
                errors.append({"claim_id": cid, "reason": "assignment_failed"})
                skipped += 1
        conn.commit()
        conn.close()
        self.audit("bulk.assign", {"operator_id": operator_id, "count": assigned}, performed_by)
        return {"assigned": assigned, "skipped": skipped, "errors": errors, "operator_id": operator_id}

    def bulk_tag(self, claim_ids: List[str], tag_name: str, performed_by: str = "operator") -> Dict[str, Any]:
        """Bulk apply a tag to multiple claims. Auto-creates tag if needed."""
        conn = _get_db()
        # Find or create tag
        tag = conn.execute("SELECT tag_id FROM tags WHERE LOWER(name) = LOWER(?)", (tag_name,)).fetchone()
        if tag:
            tag_id = tag["tag_id"]
        else:
            tag_id = f"tag_{uuid.uuid4().hex[:12]}"
            now = datetime.utcnow().isoformat() + "Z"
            conn.execute(
                "INSERT INTO tags (tag_id, name, color, category, created_by, created_at) VALUES (?,?,?,?,?,?)",
                (tag_id, tag_name, "#58a6ff", "general", performed_by, now)
            )
        tagged = 0
        skipped = 0
        for cid in claim_ids:
            claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (cid,)).fetchone()
            if not claim:
                skipped += 1
                continue
            existing = conn.execute(
                "SELECT 1 FROM claim_tags WHERE claim_id = ? AND tag_id = ?", (cid, tag_id)
            ).fetchone()
            if existing:
                skipped += 1
                continue
            now = datetime.utcnow().isoformat() + "Z"
            conn.execute(
                "INSERT INTO claim_tags (claim_id, tag_id, tagged_by, tagged_at) VALUES (?,?,?,?)",
                (cid, tag_id, performed_by, now)
            )
            tagged += 1
        # Update tag usage count
        usage = conn.execute("SELECT COUNT(*) as c FROM claim_tags WHERE tag_id = ?", (tag_id,)).fetchone()["c"]
        conn.execute("UPDATE tags SET usage_count = ? WHERE tag_id = ?", (usage, tag_id))
        conn.commit()
        conn.close()
        return {"tagged": tagged, "skipped": skipped, "tag_id": tag_id, "tag_name": tag_name}

    def bulk_escalate(self, claim_ids: List[str], reason: str = "", performed_by: str = "operator") -> Dict[str, Any]:
        """Bulk escalate multiple claims."""
        conn = _get_db()
        escalated = 0
        skipped = 0
        for cid in claim_ids:
            claim = conn.execute("SELECT claim_id, status FROM claims WHERE claim_id = ?", (cid,)).fetchone()
            if not claim:
                skipped += 1
                continue
            if claim["status"] == "escalated":
                skipped += 1
                continue
            conn.execute("UPDATE claims SET status = 'escalated' WHERE claim_id = ?", (cid,))
            escalated += 1
        conn.commit()
        conn.close()
        self.audit("bulk.escalate", {"count": escalated, "reason": reason}, performed_by)
        return {"escalated": escalated, "skipped": skipped, "reason": reason}

    def bulk_export_csv(self, claim_ids: List[str] = None, status_filter: str = None) -> Dict[str, Any]:
        """Export claims as CSV data."""
        conn = _get_db()
        if claim_ids:
            placeholders = ",".join(["?"] * len(claim_ids))
            rows = conn.execute(
                f"SELECT claim_id, claimant_name, claimant_email, respondent_entity, "
                f"amount_claimed_usd, harm_type, status, filed_at "
                f"FROM claims WHERE claim_id IN ({placeholders}) ORDER BY filed_at DESC",
                claim_ids
            ).fetchall()
        elif status_filter:
            rows = conn.execute(
                "SELECT claim_id, claimant_name, claimant_email, respondent_entity, "
                "amount_claimed_usd, harm_type, status, filed_at "
                "FROM claims WHERE status = ? ORDER BY filed_at DESC",
                (status_filter,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT claim_id, claimant_name, claimant_email, respondent_entity, "
                "amount_claimed_usd, harm_type, status, filed_at "
                "FROM claims ORDER BY filed_at DESC"
            ).fetchall()
        conn.close()

        headers = ["claim_id", "claimant_name", "claimant_email", "respondent_entity",
                    "amount_claimed_usd", "harm_type", "status", "filed_at"]
        csv_lines = [",".join(headers)]
        for r in rows:
            vals = []
            for h in headers:
                v = str(r[h] or "").replace('"', '""')
                if "," in v or '"' in v or "\n" in v:
                    v = f'"{v}"'
                vals.append(v)
            csv_lines.append(",".join(vals))

        return {
            "csv_data": "\n".join(csv_lines),
            "total_rows": len(rows),
            "headers": headers,
        }

    def get_bulk_operations_summary(self) -> Dict[str, Any]:
        """Get summary of recent bulk operations from audit log."""
        conn = _get_db()
        recent = conn.execute(
            "SELECT * FROM audit_log WHERE action LIKE 'bulk.%' ORDER BY timestamp DESC LIMIT 20"
        ).fetchall()
        conn.close()
        ops = []
        for r in recent:
            try:
                detail = json.loads(r["detail"]) if r["detail"] else {}
            except (json.JSONDecodeError, TypeError):
                detail = {}
            ops.append({
                "audit_id": r["audit_id"],
                "action": r["action"],
                "actor": r["actor"],
                "detail": detail,
                "timestamp": r["timestamp"],
            })
        return {"recent_operations": ops, "total": len(ops)}

    # ── Feature #43: Claimant Satisfaction Surveys ──

    SURVEY_TRIGGERS = ["resolution", "settlement_accepted", "outreach_complete", "escalation_closed", "manual"]
    SURVEY_STATUSES = ["pending", "sent", "completed", "expired", "skipped"]
    SURVEY_CATEGORIES = ["communication", "timeliness", "outcome", "professionalism", "overall"]

    def create_survey(self, claim_id: str, trigger_event: str = "resolution",
                      claimant_email: str = None) -> Dict[str, Any]:
        """Create a satisfaction survey for a claim."""
        conn = _get_db()
        claim = conn.execute("SELECT claim_id, claimant_name, claimant_email, respondent_entity FROM claims WHERE claim_id = ?",
                             (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        claim = dict(claim)
        now = datetime.utcnow().isoformat()
        survey_id = f"srv_{hashlib.md5(f'{claim_id}{now}'.encode()).hexdigest()[:12]}"
        expires = (datetime.utcnow() + timedelta(days=14)).isoformat()
        email = claimant_email or claim.get("claimant_email", "")
        conn.execute(
            "INSERT INTO satisfaction_surveys (survey_id, claim_id, trigger_event, status, claimant_email, respondent_name, created_at, expires_at) "
            "VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)",
            (survey_id, claim_id, trigger_event, email, claim.get("respondent_entity", ""), now, expires))
        conn.commit()
        conn.close()
        return {"survey_id": survey_id, "claim_id": claim_id, "trigger_event": trigger_event,
                "status": "pending", "claimant_email": email, "created_at": now, "expires_at": expires}

    def send_survey(self, survey_id: str) -> Dict[str, Any]:
        """Mark a survey as sent."""
        conn = _get_db()
        survey = conn.execute("SELECT * FROM satisfaction_surveys WHERE survey_id = ?", (survey_id,)).fetchone()
        if not survey:
            conn.close()
            raise HTTPException(status_code=404, detail="Survey not found")
        now = datetime.utcnow().isoformat()
        conn.execute("UPDATE satisfaction_surveys SET status = 'sent', sent_at = ? WHERE survey_id = ?", (now, survey_id))
        conn.commit()
        conn.close()
        return {"survey_id": survey_id, "status": "sent", "sent_at": now}

    def submit_survey_response(self, survey_id: str, rating: int, feedback_text: str = "",
                                categories: List[str] = None) -> Dict[str, Any]:
        """Submit a claimant's survey response."""
        conn = _get_db()
        survey = conn.execute("SELECT * FROM satisfaction_surveys WHERE survey_id = ?", (survey_id,)).fetchone()
        if not survey:
            conn.close()
            raise HTTPException(status_code=404, detail="Survey not found")
        if rating < 1 or rating > 5:
            conn.close()
            raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")
        now = datetime.utcnow().isoformat()
        cat_json = json.dumps(categories or [])
        conn.execute(
            "UPDATE satisfaction_surveys SET status = 'completed', rating = ?, feedback_text = ?, "
            "categories = ?, completed_at = ? WHERE survey_id = ?",
            (rating, feedback_text or "", cat_json, now, survey_id))
        conn.commit()
        conn.close()
        return {"survey_id": survey_id, "status": "completed", "rating": rating, "completed_at": now}

    def get_survey(self, survey_id: str) -> Dict[str, Any]:
        """Get a single survey."""
        conn = _get_db()
        survey = conn.execute("SELECT * FROM satisfaction_surveys WHERE survey_id = ?", (survey_id,)).fetchone()
        conn.close()
        if not survey:
            raise HTTPException(status_code=404, detail="Survey not found")
        s = dict(survey)
        try:
            s["categories"] = json.loads(s.get("categories") or "[]")
        except Exception:
            s["categories"] = []
        return s

    def list_surveys(self, claim_id: str = None, status: str = None,
                     trigger_event: str = None, limit: int = 50) -> Dict[str, Any]:
        """List surveys with optional filters."""
        conn = _get_db()
        sql = "SELECT * FROM satisfaction_surveys WHERE 1=1"
        params = []
        if claim_id:
            sql += " AND claim_id = ?"
            params.append(claim_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if trigger_event:
            sql += " AND trigger_event = ?"
            params.append(trigger_event)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        surveys = []
        for r in rows:
            s = dict(r)
            try:
                s["categories"] = json.loads(s.get("categories") or "[]")
            except Exception:
                s["categories"] = []
            surveys.append(s)
        return {"surveys": surveys, "total": len(surveys)}

    def expire_surveys(self) -> Dict[str, Any]:
        """Mark overdue pending/sent surveys as expired."""
        conn = _get_db()
        now = datetime.utcnow().isoformat()
        cur = conn.execute(
            "UPDATE satisfaction_surveys SET status = 'expired' "
            "WHERE status IN ('pending', 'sent') AND expires_at < ?", (now,))
        count = cur.rowcount
        conn.commit()
        conn.close()
        return {"expired_count": count}

    def get_survey_stats(self) -> Dict[str, Any]:
        """Get overall satisfaction survey statistics and metrics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM satisfaction_surveys").fetchone()[0]
        completed = conn.execute("SELECT COUNT(*) FROM satisfaction_surveys WHERE status = 'completed'").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM satisfaction_surveys WHERE status = 'pending'").fetchone()[0]
        sent = conn.execute("SELECT COUNT(*) FROM satisfaction_surveys WHERE status = 'sent'").fetchone()[0]
        expired = conn.execute("SELECT COUNT(*) FROM satisfaction_surveys WHERE status = 'expired'").fetchone()[0]

        # Average rating
        avg_row = conn.execute("SELECT AVG(rating), MIN(rating), MAX(rating) FROM satisfaction_surveys WHERE rating IS NOT NULL").fetchone()
        avg_rating = round(avg_row[0], 2) if avg_row[0] else 0
        min_rating = avg_row[1] or 0
        max_rating = avg_row[2] or 0

        # Rating distribution
        dist = {}
        for i in range(1, 6):
            c = conn.execute("SELECT COUNT(*) FROM satisfaction_surveys WHERE rating = ?", (i,)).fetchone()[0]
            dist[str(i)] = c

        # By trigger event
        by_trigger = {}
        for row in conn.execute(
            "SELECT trigger_event, COUNT(*), AVG(rating) FROM satisfaction_surveys GROUP BY trigger_event"
        ).fetchall():
            by_trigger[row[0]] = {"count": row[1], "avg_rating": round(row[2], 2) if row[2] else None}

        # Response rate
        response_rate = round(completed / total * 100, 1) if total > 0 else 0

        # NPS calculation (ratings 4-5 = promoters, 3 = passive, 1-2 = detractors)
        promoters = dist.get("5", 0) + dist.get("4", 0)
        detractors = dist.get("1", 0) + dist.get("2", 0)
        nps = round((promoters - detractors) / completed * 100, 1) if completed > 0 else 0

        # Recent feedback
        recent = conn.execute(
            "SELECT survey_id, claim_id, rating, feedback_text, trigger_event, completed_at, respondent_name "
            "FROM satisfaction_surveys WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 10"
        ).fetchall()
        recent_list = [dict(r) for r in recent]

        # Trend (last 30 days, grouped by day)
        thirty_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
        trend_rows = conn.execute(
            "SELECT DATE(completed_at) as day, AVG(rating) as avg_r, COUNT(*) as cnt "
            "FROM satisfaction_surveys WHERE status = 'completed' AND completed_at >= ? "
            "GROUP BY DATE(completed_at) ORDER BY day", (thirty_ago,)
        ).fetchall()
        trend = [{"date": r[0], "avg_rating": round(r[1], 2), "count": r[2]} for r in trend_rows]

        conn.close()
        return {
            "total_surveys": total,
            "completed": completed,
            "pending": pending,
            "sent": sent,
            "expired": expired,
            "response_rate": response_rate,
            "avg_rating": avg_rating,
            "min_rating": min_rating,
            "max_rating": max_rating,
            "nps_score": nps,
            "rating_distribution": dist,
            "by_trigger": by_trigger,
            "recent_feedback": recent_list,
            "trend_30d": trend,
        }

    def get_claim_surveys(self, claim_id: str) -> Dict[str, Any]:
        """Get all surveys for a specific claim."""
        conn = _get_db()
        rows = conn.execute("SELECT * FROM satisfaction_surveys WHERE claim_id = ? ORDER BY created_at DESC",
                            (claim_id,)).fetchall()
        conn.close()
        surveys = []
        for r in rows:
            s = dict(r)
            try:
                s["categories"] = json.loads(s.get("categories") or "[]")
            except Exception:
                s["categories"] = []
            surveys.append(s)
        return {"surveys": surveys, "total": len(surveys)}

    # ── Feature #44: Escalation Playbooks ──

    PLAYBOOK_TRIGGERS = ["manual", "stale_days", "unresponsive", "amount_threshold", "sla_breach", "status_change"]
    PLAYBOOK_STEP_TYPES = ["add_note", "change_status", "send_outreach", "create_task", "escalate", "notify", "wait"]
    PLAYBOOK_STATUSES = ["running", "completed", "failed", "paused", "cancelled"]

    def _seed_default_playbooks(self):
        """Seed default playbooks if none exist."""
        conn = _get_db()
        count = conn.execute("SELECT COUNT(*) FROM escalation_playbooks").fetchone()[0]
        if count > 0:
            conn.close()
            return
        now = datetime.utcnow().isoformat()
        defaults = [
            {
                "playbook_id": f"pb_{hashlib.md5(b'standard_escalation').hexdigest()[:12]}",
                "name": "Standard Escalation Path",
                "description": "3-step escalation: initial outreach, follow-up, formal escalation",
                "trigger_type": "stale_days",
                "trigger_config": json.dumps({"stale_days": 7, "statuses": ["filed", "under_review"]}),
                "steps": json.dumps([
                    {"type": "add_note", "config": {"content": "Auto-escalation playbook initiated", "category": "system"}, "delay_hours": 0},
                    {"type": "send_outreach", "config": {"template": "initial_demand", "channel": "email"}, "delay_hours": 1},
                    {"type": "wait", "config": {"hours": 72}, "delay_hours": 0},
                    {"type": "send_outreach", "config": {"template": "follow_up", "channel": "email"}, "delay_hours": 0},
                    {"type": "wait", "config": {"hours": 120}, "delay_hours": 0},
                    {"type": "change_status", "config": {"status": "escalated", "reason": "Unresponsive after standard escalation"}, "delay_hours": 0},
                    {"type": "notify", "config": {"message": "Claim auto-escalated after standard playbook completion"}, "delay_hours": 0},
                ]),
            },
            {
                "playbook_id": f"pb_{hashlib.md5(b'high_value_fast').hexdigest()[:12]}",
                "name": "High-Value Fast Track",
                "description": "Accelerated escalation for claims over $5,000",
                "trigger_type": "amount_threshold",
                "trigger_config": json.dumps({"min_amount": 5000, "statuses": ["filed"]}),
                "steps": json.dumps([
                    {"type": "change_status", "config": {"status": "under_review", "reason": "High-value fast-track"}, "delay_hours": 0},
                    {"type": "add_note", "config": {"content": "HIGH VALUE: Fast-track playbook activated for $5k+ claim", "category": "system"}, "delay_hours": 0},
                    {"type": "send_outreach", "config": {"template": "initial_demand", "channel": "email"}, "delay_hours": 2},
                    {"type": "notify", "config": {"message": "High-value claim requires immediate attention"}, "delay_hours": 0},
                ]),
            },
            {
                "playbook_id": f"pb_{hashlib.md5(b'sla_breach_response').hexdigest()[:12]}",
                "name": "SLA Breach Response",
                "description": "Auto-action when SLA is breached",
                "trigger_type": "sla_breach",
                "trigger_config": json.dumps({"breach_type": "any"}),
                "steps": json.dumps([
                    {"type": "add_note", "config": {"content": "SLA BREACH: Automated response playbook initiated", "category": "system"}, "delay_hours": 0},
                    {"type": "escalate", "config": {"reason": "SLA breach detected"}, "delay_hours": 0},
                    {"type": "notify", "config": {"message": "SLA breach — automatic escalation applied"}, "delay_hours": 0},
                ]),
            },
        ]
        for pb in defaults:
            conn.execute(
                "INSERT OR IGNORE INTO escalation_playbooks (playbook_id, name, description, trigger_type, trigger_config, steps, is_active, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (pb["playbook_id"], pb["name"], pb["description"], pb["trigger_type"],
                 pb["trigger_config"], pb["steps"], now))
        conn.commit()
        conn.close()

    def create_playbook(self, name: str, description: str = "", trigger_type: str = "manual",
                        trigger_config: dict = None, steps: list = None,
                        cooldown_hours: int = 24, created_by: str = "operator") -> Dict[str, Any]:
        """Create a new escalation playbook."""
        conn = _get_db()
        now = datetime.utcnow().isoformat()
        pb_id = f"pb_{hashlib.md5(f'{name}{now}'.encode()).hexdigest()[:12]}"
        conn.execute(
            "INSERT INTO escalation_playbooks (playbook_id, name, description, trigger_type, trigger_config, steps, cooldown_hours, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (pb_id, name, description or "", trigger_type,
             json.dumps(trigger_config or {}), json.dumps(steps or []),
             cooldown_hours, created_by, now))
        conn.commit()
        conn.close()
        return {"playbook_id": pb_id, "name": name, "trigger_type": trigger_type,
                "steps_count": len(steps or []), "created_at": now}

    def list_playbooks(self, active_only: bool = False) -> Dict[str, Any]:
        """List all escalation playbooks."""
        self._seed_default_playbooks()
        conn = _get_db()
        sql = "SELECT * FROM escalation_playbooks"
        if active_only:
            sql += " WHERE is_active = 1"
        sql += " ORDER BY created_at DESC"
        rows = conn.execute(sql).fetchall()
        conn.close()
        playbooks = []
        for r in rows:
            p = dict(r)
            try:
                p["trigger_config"] = json.loads(p.get("trigger_config") or "{}")
            except Exception:
                p["trigger_config"] = {}
            try:
                p["steps"] = json.loads(p.get("steps") or "[]")
            except Exception:
                p["steps"] = []
            p["steps_count"] = len(p["steps"])
            playbooks.append(p)
        return {"playbooks": playbooks, "total": len(playbooks)}

    def get_playbook(self, playbook_id: str) -> Dict[str, Any]:
        """Get a single playbook with full details."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM escalation_playbooks WHERE playbook_id = ?", (playbook_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Playbook not found")
        # Get execution history
        execs = conn.execute(
            "SELECT execution_id, claim_id, status, current_step, total_steps, started_at, completed_at "
            "FROM playbook_executions WHERE playbook_id = ? ORDER BY started_at DESC LIMIT 20",
            (playbook_id,)).fetchall()
        conn.close()
        p = dict(row)
        try:
            p["trigger_config"] = json.loads(p.get("trigger_config") or "{}")
        except Exception:
            p["trigger_config"] = {}
        try:
            p["steps"] = json.loads(p.get("steps") or "[]")
        except Exception:
            p["steps"] = []
        p["steps_count"] = len(p["steps"])
        p["recent_executions"] = [dict(e) for e in execs]
        return p

    def update_playbook(self, playbook_id: str, updates: dict) -> Dict[str, Any]:
        """Update a playbook's configuration."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM escalation_playbooks WHERE playbook_id = ?", (playbook_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Playbook not found")
        now = datetime.utcnow().isoformat()
        fields = []
        params = []
        for key in ("name", "description", "trigger_type", "cooldown_hours", "is_active"):
            if key in updates:
                fields.append(f"{key} = ?")
                params.append(updates[key])
        if "trigger_config" in updates:
            fields.append("trigger_config = ?")
            params.append(json.dumps(updates["trigger_config"]))
        if "steps" in updates:
            fields.append("steps = ?")
            params.append(json.dumps(updates["steps"]))
        if fields:
            fields.append("updated_at = ?")
            params.append(now)
            params.append(playbook_id)
            conn.execute(f"UPDATE escalation_playbooks SET {', '.join(fields)} WHERE playbook_id = ?", params)
            conn.commit()
        conn.close()
        return self.get_playbook(playbook_id)

    def delete_playbook(self, playbook_id: str) -> Dict[str, Any]:
        """Delete a playbook."""
        conn = _get_db()
        row = conn.execute("SELECT playbook_id FROM escalation_playbooks WHERE playbook_id = ?", (playbook_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Playbook not found")
        conn.execute("DELETE FROM escalation_playbooks WHERE playbook_id = ?", (playbook_id,))
        conn.commit()
        conn.close()
        return {"deleted": playbook_id}

    def execute_playbook(self, playbook_id: str, claim_id: str) -> Dict[str, Any]:
        """Execute a playbook against a claim (simulate step execution)."""
        conn = _get_db()
        pb = conn.execute("SELECT * FROM escalation_playbooks WHERE playbook_id = ?", (playbook_id,)).fetchone()
        if not pb:
            conn.close()
            raise HTTPException(status_code=404, detail="Playbook not found")
        claim = conn.execute("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if not claim:
            conn.close()
            raise HTTPException(status_code=404, detail="Claim not found")
        pb = dict(pb)
        try:
            steps = json.loads(pb.get("steps") or "[]")
        except Exception:
            steps = []
        now = datetime.utcnow().isoformat()
        exec_id = f"pbe_{hashlib.md5(f'{playbook_id}{claim_id}{now}'.encode()).hexdigest()[:12]}"
        step_results = []
        for i, step in enumerate(steps):
            step_type = step.get("type", "unknown")
            config = step.get("config", {})
            result = {"step": i, "type": step_type, "status": "completed", "executed_at": now}
            if step_type == "add_note":
                try:
                    conn.execute(
                        "INSERT INTO notes (note_id, claim_id, content, category, created_at) VALUES (?, ?, ?, ?, ?)",
                        (f"n_{hashlib.md5(f'{exec_id}{i}'.encode()).hexdigest()[:12]}",
                         claim_id, config.get("content", "Playbook note"), config.get("category", "system"), now))
                    result["detail"] = "Note added"
                except Exception as e:
                    result["status"] = "failed"
                    result["error"] = str(e)
            elif step_type == "change_status":
                try:
                    new_status = config.get("status", "escalated")
                    conn.execute("UPDATE claims SET status = ?, updated_at = ? WHERE claim_id = ?",
                                 (new_status, now, claim_id))
                    result["detail"] = f"Status changed to {new_status}"
                except Exception as e:
                    result["status"] = "failed"
                    result["error"] = str(e)
            elif step_type == "notify":
                result["detail"] = f"Notification: {config.get('message', 'Playbook notification')}"
            elif step_type == "wait":
                result["detail"] = f"Wait {config.get('hours', 0)} hours (simulated)"
            elif step_type == "escalate":
                try:
                    conn.execute("UPDATE claims SET status = 'escalated', updated_at = ? WHERE claim_id = ?", (now, claim_id))
                    result["detail"] = f"Escalated: {config.get('reason', 'playbook escalation')}"
                except Exception as e:
                    result["status"] = "failed"
                    result["error"] = str(e)
            elif step_type == "send_outreach":
                result["detail"] = f"Outreach queued: {config.get('template', 'default')} via {config.get('channel', 'email')}"
            else:
                result["detail"] = f"Step type '{step_type}' executed"
            step_results.append(result)

        all_ok = all(r["status"] == "completed" for r in step_results)
        final_status = "completed" if all_ok else "failed"
        conn.execute(
            "INSERT INTO playbook_executions (execution_id, playbook_id, claim_id, status, current_step, total_steps, step_results, started_at, completed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (exec_id, playbook_id, claim_id, final_status, len(steps), len(steps),
             json.dumps(step_results), now, now))
        conn.commit()
        conn.close()
        return {
            "execution_id": exec_id, "playbook_id": playbook_id, "claim_id": claim_id,
            "status": final_status, "steps_executed": len(step_results),
            "step_results": step_results, "started_at": now, "completed_at": now,
        }

    def list_playbook_executions(self, playbook_id: str = None, claim_id: str = None,
                                  status: str = None, limit: int = 50) -> Dict[str, Any]:
        """List playbook executions with filters."""
        conn = _get_db()
        sql = "SELECT * FROM playbook_executions WHERE 1=1"
        params = []
        if playbook_id:
            sql += " AND playbook_id = ?"
            params.append(playbook_id)
        if claim_id:
            sql += " AND claim_id = ?"
            params.append(claim_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        execs = []
        for r in rows:
            e = dict(r)
            try:
                e["step_results"] = json.loads(e.get("step_results") or "[]")
            except Exception:
                e["step_results"] = []
            execs.append(e)
        return {"executions": execs, "total": len(execs)}

    def get_playbook_stats(self) -> Dict[str, Any]:
        """Get playbook statistics and execution metrics."""
        self._seed_default_playbooks()
        conn = _get_db()
        total_pb = conn.execute("SELECT COUNT(*) FROM escalation_playbooks").fetchone()[0]
        active_pb = conn.execute("SELECT COUNT(*) FROM escalation_playbooks WHERE is_active = 1").fetchone()[0]
        total_exec = conn.execute("SELECT COUNT(*) FROM playbook_executions").fetchone()[0]
        completed = conn.execute("SELECT COUNT(*) FROM playbook_executions WHERE status = 'completed'").fetchone()[0]
        failed = conn.execute("SELECT COUNT(*) FROM playbook_executions WHERE status = 'failed'").fetchone()[0]
        running = conn.execute("SELECT COUNT(*) FROM playbook_executions WHERE status = 'running'").fetchone()[0]

        # By playbook
        by_pb = conn.execute(
            "SELECT p.name, p.playbook_id, COUNT(e.execution_id) as exec_count, "
            "SUM(CASE WHEN e.status='completed' THEN 1 ELSE 0 END) as success "
            "FROM escalation_playbooks p LEFT JOIN playbook_executions e ON p.playbook_id = e.playbook_id "
            "GROUP BY p.playbook_id ORDER BY exec_count DESC"
        ).fetchall()
        by_playbook = [{"name": r[0], "playbook_id": r[1], "executions": r[2], "successes": r[3] or 0} for r in by_pb]

        # Recent executions
        recent = conn.execute(
            "SELECT e.execution_id, e.claim_id, e.status, e.started_at, e.completed_at, p.name "
            "FROM playbook_executions e JOIN escalation_playbooks p ON e.playbook_id = p.playbook_id "
            "ORDER BY e.started_at DESC LIMIT 10"
        ).fetchall()
        recent_list = [{"execution_id": r[0], "claim_id": r[1], "status": r[2],
                        "started_at": r[3], "completed_at": r[4], "playbook_name": r[5]} for r in recent]

        success_rate = round(completed / total_exec * 100, 1) if total_exec > 0 else 0
        conn.close()
        return {
            "total_playbooks": total_pb,
            "active_playbooks": active_pb,
            "total_executions": total_exec,
            "completed": completed,
            "failed": failed,
            "running": running,
            "success_rate": success_rate,
            "by_playbook": by_playbook,
            "recent_executions": recent_list,
        }

    # ── Feature #45: Communication Channel Registry ──

    CHANNEL_TYPES = ["email", "phone", "portal", "social_media", "legal_notice", "postal", "fax", "chat"]
    CHANNEL_STATUSES = ["active", "inactive", "bounced", "blocked"]

    def add_channel(self, respondent_entity: str, channel_type: str, contact_value: str,
                    label: str = "", is_primary: bool = False, notes: str = "") -> Dict[str, Any]:
        """Register a communication channel for a respondent."""
        conn = _get_db()
        now = datetime.utcnow().isoformat()
        ch_id = f"ch_{hashlib.md5(f'{respondent_entity}{channel_type}{contact_value}'.encode()).hexdigest()[:12]}"
        # If setting as primary, unset existing primaries for same respondent+type
        if is_primary:
            conn.execute(
                "UPDATE comm_channels SET is_primary = 0 WHERE respondent_entity = ? AND channel_type = ?",
                (respondent_entity, channel_type))
        conn.execute(
            "INSERT OR REPLACE INTO comm_channels (channel_id, respondent_entity, channel_type, contact_value, "
            "label, is_primary, status, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)",
            (ch_id, respondent_entity, channel_type, contact_value, label or "", is_primary, notes or "", now))
        conn.commit()
        conn.close()
        return {"channel_id": ch_id, "respondent_entity": respondent_entity,
                "channel_type": channel_type, "contact_value": contact_value,
                "is_primary": is_primary, "created_at": now}

    def list_channels(self, respondent_entity: str = None, channel_type: str = None,
                      status: str = None, limit: int = 100) -> Dict[str, Any]:
        """List communication channels with optional filters."""
        conn = _get_db()
        sql = "SELECT * FROM comm_channels WHERE 1=1"
        params = []
        if respondent_entity:
            sql += " AND respondent_entity = ?"
            params.append(respondent_entity)
        if channel_type:
            sql += " AND channel_type = ?"
            params.append(channel_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY respondent_entity, is_primary DESC, created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return {"channels": [dict(r) for r in rows], "total": len(rows)}

    def get_channel(self, channel_id: str) -> Dict[str, Any]:
        """Get a single channel."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM comm_channels WHERE channel_id = ?", (channel_id,)).fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail="Channel not found")
        return dict(row)

    def update_channel(self, channel_id: str, updates: dict) -> Dict[str, Any]:
        """Update a channel's properties."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM comm_channels WHERE channel_id = ?", (channel_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Channel not found")
        now = datetime.utcnow().isoformat()
        fields, params = [], []
        for k in ("contact_value", "label", "is_primary", "is_verified", "status", "notes"):
            if k in updates:
                fields.append(f"{k} = ?")
                params.append(updates[k])
        if fields:
            fields.append("updated_at = ?")
            params.append(now)
            params.append(channel_id)
            conn.execute(f"UPDATE comm_channels SET {', '.join(fields)} WHERE channel_id = ?", params)
            conn.commit()
        conn.close()
        return self.get_channel(channel_id)

    def delete_channel(self, channel_id: str) -> Dict[str, Any]:
        """Delete a channel."""
        conn = _get_db()
        row = conn.execute("SELECT channel_id FROM comm_channels WHERE channel_id = ?", (channel_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Channel not found")
        conn.execute("DELETE FROM comm_channels WHERE channel_id = ?", (channel_id,))
        conn.commit()
        conn.close()
        return {"deleted": channel_id}

    def record_channel_outcome(self, channel_id: str, success: bool) -> Dict[str, Any]:
        """Record a success or failure for a channel (tracks effectiveness)."""
        conn = _get_db()
        row = conn.execute("SELECT * FROM comm_channels WHERE channel_id = ?", (channel_id,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Channel not found")
        now = datetime.utcnow().isoformat()
        if success:
            conn.execute("UPDATE comm_channels SET success_count = success_count + 1, last_used_at = ?, updated_at = ? WHERE channel_id = ?",
                         (now, now, channel_id))
        else:
            conn.execute("UPDATE comm_channels SET fail_count = fail_count + 1, last_used_at = ?, updated_at = ? WHERE channel_id = ?",
                         (now, now, channel_id))
        conn.commit()
        conn.close()
        return self.get_channel(channel_id)

    def get_respondent_channels(self, respondent_entity: str) -> Dict[str, Any]:
        """Get all channels for a respondent with effectiveness metrics."""
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM comm_channels WHERE respondent_entity = ? ORDER BY is_primary DESC, channel_type",
            (respondent_entity,)).fetchall()
        conn.close()
        channels = []
        for r in rows:
            ch = dict(r)
            total = (ch.get("success_count") or 0) + (ch.get("fail_count") or 0)
            ch["effectiveness"] = round(ch.get("success_count", 0) / total * 100, 1) if total > 0 else None
            channels.append(ch)
        return {"respondent_entity": respondent_entity, "channels": channels, "total": len(channels)}

    def get_channel_stats(self) -> Dict[str, Any]:
        """Get channel registry statistics and effectiveness analytics."""
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM comm_channels").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM comm_channels WHERE status = 'active'").fetchone()[0]
        verified = conn.execute("SELECT COUNT(*) FROM comm_channels WHERE is_verified = 1").fetchone()[0]
        primary_count = conn.execute("SELECT COUNT(*) FROM comm_channels WHERE is_primary = 1").fetchone()[0]

        # By type
        by_type = {}
        for row in conn.execute(
            "SELECT channel_type, COUNT(*), SUM(success_count), SUM(fail_count) FROM comm_channels GROUP BY channel_type"
        ).fetchall():
            total_attempts = (row[2] or 0) + (row[3] or 0)
            by_type[row[0]] = {
                "count": row[1],
                "successes": row[2] or 0,
                "failures": row[3] or 0,
                "effectiveness": round((row[2] or 0) / total_attempts * 100, 1) if total_attempts > 0 else None,
            }

        # By status
        by_status = {}
        for row in conn.execute("SELECT status, COUNT(*) FROM comm_channels GROUP BY status").fetchall():
            by_status[row[0]] = row[1]

        # Respondents with most channels
        top = conn.execute(
            "SELECT respondent_entity, COUNT(*) as ch_count FROM comm_channels GROUP BY respondent_entity "
            "ORDER BY ch_count DESC LIMIT 10"
        ).fetchall()
        top_respondents = [{"respondent_entity": r[0], "channel_count": r[1]} for r in top]

        # Total effectiveness
        total_success = conn.execute("SELECT SUM(success_count) FROM comm_channels").fetchone()[0] or 0
        total_fail = conn.execute("SELECT SUM(fail_count) FROM comm_channels").fetchone()[0] or 0
        total_attempts = total_success + total_fail
        overall_effectiveness = round(total_success / total_attempts * 100, 1) if total_attempts > 0 else None

        conn.close()
        return {
            "total_channels": total,
            "active": active,
            "verified": verified,
            "primary": primary_count,
            "overall_effectiveness": overall_effectiveness,
            "total_attempts": total_attempts,
            "by_type": by_type,
            "by_status": by_status,
            "top_respondents": top_respondents,
        }


    # ── Feature #46: Fee & Billing Tracker ──

    def create_billing_entry(self, claim_id: str, entry_type: str = "contingency_fee",
                             description: str = "", amount_usd: float = 0.0,
                             fee_pct: float = None, due_date: str = None,
                             notes: str = "", created_by: str = "system") -> dict:
        entry_id = "bil_" + hashlib.md5(f"{claim_id}{entry_type}{datetime.utcnow().timestamp()}".encode()).hexdigest()[:12]
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        conn.execute(
            "INSERT INTO billing_entries (entry_id, claim_id, entry_type, description, amount_usd, fee_pct, status, due_date, notes, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (entry_id, claim_id, entry_type, description, amount_usd, fee_pct, "pending", due_date, notes, created_by, now),
        )
        conn.commit()
        self.audit("billing_entry_created", {"entry_id": entry_id, "claim_id": claim_id, "entry_type": entry_type, "amount_usd": amount_usd})
        return {"entry_id": entry_id, "claim_id": claim_id, "entry_type": entry_type, "amount_usd": amount_usd, "status": "pending", "created_at": now}

    def list_billing_entries(self, claim_id: str = None, status: str = None, entry_type: str = None,
                             limit: int = 100, offset: int = 0) -> dict:
        conn = _get_db()
        where, params = [], []
        if claim_id:
            where.append("claim_id = ?")
            params.append(claim_id)
        if status:
            where.append("status = ?")
            params.append(status)
        if entry_type:
            where.append("entry_type = ?")
            params.append(entry_type)
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM billing_entries{clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM billing_entries{clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return {"entries": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

    def get_billing_entry(self, entry_id: str) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM billing_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        return dict(row)

    def update_billing_entry(self, entry_id: str, updates: dict) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM billing_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        allowed = {"description", "amount_usd", "fee_pct", "status", "due_date", "paid_date", "payment_method", "invoice_number", "notes"}
        sets, vals = [], []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return dict(row)
        sets.append("updated_at = ?")
        vals.append(datetime.utcnow().isoformat() + "Z")
        vals.append(entry_id)
        conn.execute(f"UPDATE billing_entries SET {', '.join(sets)} WHERE entry_id = ?", vals)
        conn.commit()
        updated = conn.execute("SELECT * FROM billing_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        return dict(updated)

    def delete_billing_entry(self, entry_id: str) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM billing_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM billing_entries WHERE entry_id = ?", (entry_id,))
        conn.commit()
        return {"deleted": entry_id}

    def mark_billing_paid(self, entry_id: str, payment_method: str = "", notes: str = "") -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM billing_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "UPDATE billing_entries SET status = 'paid', paid_date = ?, payment_method = ?, notes = CASE WHEN notes = '' THEN ? ELSE notes || ' | ' || ? END, updated_at = ? WHERE entry_id = ?",
            (now, payment_method, notes, notes, now, entry_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM billing_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        self.audit("billing_entry_paid", {"entry_id": entry_id, "payment_method": payment_method, "amount_usd": dict(row)["amount_usd"]})
        return dict(updated)

    def generate_invoice(self, claim_id: str, entries: list = None) -> dict:
        conn = _get_db()
        if entries:
            placeholders = ",".join("?" * len(entries))
            rows = conn.execute(
                f"SELECT * FROM billing_entries WHERE claim_id = ? AND entry_id IN ({placeholders})",
                [claim_id] + entries,
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM billing_entries WHERE claim_id = ? AND status = 'pending'",
                (claim_id,),
            ).fetchall()
        items = [dict(r) for r in rows]
        total = sum(i.get("amount_usd", 0) for i in items)
        inv_num = f"INV-{claim_id[:8].upper()}-{int(datetime.utcnow().timestamp()) % 100000}"
        now = datetime.utcnow().isoformat() + "Z"
        for item in items:
            conn.execute("UPDATE billing_entries SET invoice_number = ?, updated_at = ? WHERE entry_id = ?",
                         (inv_num, now, item["entry_id"]))
        conn.commit()
        return {"invoice_number": inv_num, "claim_id": claim_id, "line_items": len(items), "total_usd": total, "entries": items, "generated_at": now}

    def get_billing_stats(self) -> dict:
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM billing_entries").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM billing_entries WHERE status = 'pending'").fetchone()[0]
        paid = conn.execute("SELECT COUNT(*) FROM billing_entries WHERE status = 'paid'").fetchone()[0]
        overdue = conn.execute("SELECT COUNT(*) FROM billing_entries WHERE status = 'pending' AND due_date < ?", (datetime.utcnow().isoformat(),)).fetchone()[0]
        total_billed = conn.execute("SELECT COALESCE(SUM(amount_usd), 0) FROM billing_entries").fetchone()[0]
        total_collected = conn.execute("SELECT COALESCE(SUM(amount_usd), 0) FROM billing_entries WHERE status = 'paid'").fetchone()[0]
        total_outstanding = conn.execute("SELECT COALESCE(SUM(amount_usd), 0) FROM billing_entries WHERE status = 'pending'").fetchone()[0]
        by_type = {}
        for row in conn.execute("SELECT entry_type, COUNT(*), COALESCE(SUM(amount_usd),0) FROM billing_entries GROUP BY entry_type").fetchall():
            by_type[row[0]] = {"count": row[1], "total_usd": row[2]}
        claims_with_billing = conn.execute("SELECT COUNT(DISTINCT claim_id) FROM billing_entries").fetchone()[0]
        return {
            "total_entries": total, "pending": pending, "paid": paid, "overdue": overdue,
            "total_billed_usd": round(total_billed, 2), "total_collected_usd": round(total_collected, 2),
            "total_outstanding_usd": round(total_outstanding, 2),
            "collection_rate": round(total_collected / max(total_billed, 0.01) * 100, 1),
            "by_type": by_type, "claims_with_billing": claims_with_billing,
        }

    def get_billing_types(self) -> dict:
        conn = _get_db()
        rows = conn.execute("SELECT DISTINCT entry_type FROM billing_entries ORDER BY entry_type").fetchall()
        return {"types": [r[0] for r in rows]}

    # ── Feature #47: Claim Dependencies & Linked Cases ──

    def create_claim_link(self, source_claim_id: str, target_claim_id: str,
                          link_type: str = "related", description: str = "",
                          strength: float = 1.0, created_by: str = "system") -> dict:
        """Create a dependency link between two claims."""
        dep_id = "dep_" + hashlib.md5(f"{source_claim_id}{target_claim_id}{link_type}{datetime.utcnow().timestamp()}".encode()).hexdigest()[:12]
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        if source_claim_id == target_claim_id:
            return {"error": "Cannot link a claim to itself"}
        existing = conn.execute(
            "SELECT dep_id FROM claim_dependencies WHERE source_claim_id = ? AND target_claim_id = ? AND link_type = ?",
            (source_claim_id, target_claim_id, link_type),
        ).fetchone()
        if existing:
            return {"error": "Link already exists", "existing_link_id": existing[0]}
        conn.execute(
            "INSERT INTO claim_dependencies (dep_id, source_claim_id, target_claim_id, link_type, description, strength, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (dep_id, source_claim_id, target_claim_id, link_type, description, strength, created_by, now),
        )
        conn.commit()
        self.audit("claim_link_created", {"dep_id": dep_id, "source": source_claim_id, "target": target_claim_id, "link_type": link_type})
        return {"link_id": dep_id, "source_claim_id": source_claim_id, "target_claim_id": target_claim_id, "link_type": link_type, "created_at": now}

    def list_claim_links(self, claim_id: str = None, link_type: str = None,
                         limit: int = 100, offset: int = 0) -> dict:
        """List claim dependency links, optionally filtered."""
        conn = _get_db()
        where, params = [], []
        if claim_id:
            where.append("(source_claim_id = ? OR target_claim_id = ?)")
            params.extend([claim_id, claim_id])
        if link_type:
            where.append("link_type = ?")
            params.append(link_type)
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM claim_dependencies{clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT dep_id as link_id, source_claim_id, target_claim_id, link_type, description, strength, created_by, created_at FROM claim_dependencies{clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return {"links": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

    def get_claim_link(self, link_id: str) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT dep_id as link_id, source_claim_id, target_claim_id, link_type, description, strength, created_by, created_at FROM claim_dependencies WHERE dep_id = ?", (link_id,)).fetchone()
        if not row:
            return None
        return dict(row)

    def update_claim_link(self, link_id: str, updates: dict) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM claim_dependencies WHERE dep_id = ?", (link_id,)).fetchone()
        if not row:
            return None
        allowed = {"link_type", "description", "strength"}
        sets, vals = [], []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return dict(row)
        vals.append(link_id)
        conn.execute(f"UPDATE claim_dependencies SET {', '.join(sets)} WHERE dep_id = ?", vals)
        conn.commit()
        updated = conn.execute("SELECT dep_id as link_id, source_claim_id, target_claim_id, link_type, description, strength, created_by, created_at FROM claim_dependencies WHERE dep_id = ?", (link_id,)).fetchone()
        return dict(updated)

    def delete_claim_link(self, link_id: str) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM claim_dependencies WHERE dep_id = ?", (link_id,)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM claim_dependencies WHERE dep_id = ?", (link_id,))
        conn.commit()
        return {"deleted": link_id}

    def get_claim_dependencies(self, claim_id: str) -> dict:
        """Get full dependency graph for a specific claim."""
        conn = _get_db()
        outgoing = conn.execute(
            "SELECT dep_id as link_id, source_claim_id, target_claim_id, link_type, description, strength, created_by, created_at FROM claim_dependencies WHERE source_claim_id = ?", (claim_id,)
        ).fetchall()
        incoming = conn.execute(
            "SELECT dep_id as link_id, source_claim_id, target_claim_id, link_type, description, strength, created_by, created_at FROM claim_dependencies WHERE target_claim_id = ?", (claim_id,)
        ).fetchall()
        related_ids = set()
        for r in outgoing:
            related_ids.add(dict(r)["target_claim_id"])
        for r in incoming:
            related_ids.add(dict(r)["source_claim_id"])
        return {
            "claim_id": claim_id,
            "outgoing": [dict(r) for r in outgoing],
            "incoming": [dict(r) for r in incoming],
            "total_links": len(outgoing) + len(incoming),
            "related_claim_ids": list(related_ids),
        }

    def get_link_stats(self) -> dict:
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM claim_dependencies").fetchone()[0]
        by_type = {}
        for row in conn.execute("SELECT link_type, COUNT(*) FROM claim_dependencies GROUP BY link_type").fetchall():
            by_type[row[0]] = row[1]
        claims_with_links = conn.execute(
            "SELECT COUNT(DISTINCT id) FROM (SELECT source_claim_id AS id FROM claim_dependencies UNION SELECT target_claim_id AS id FROM claim_dependencies)"
        ).fetchone()[0]
        avg_strength = conn.execute("SELECT COALESCE(AVG(strength), 0) FROM claim_dependencies").fetchone()[0]
        return {
            "total_links": total,
            "by_type": by_type,
            "claims_with_links": claims_with_links,
            "avg_strength": round(avg_strength, 2),
            "link_types": list(by_type.keys()),
        }

    def get_link_types(self) -> dict:
        conn = _get_db()
        rows = conn.execute("SELECT DISTINCT link_type FROM claim_dependencies ORDER BY link_type").fetchall()
        defaults = ["related", "parent_child", "duplicate", "supersedes", "blocks"]
        existing = [r[0] for r in rows]
        all_types = sorted(set(defaults + existing))
        return {"types": all_types}

    # ── Feature #48: Claim Evidence Vault ──

    def add_evidence(self, claim_id: str, evidence_type: str = "document",
                     title: str = "", description: str = "", source_url: str = "",
                     file_hash: str = "", file_size_bytes: int = 0,
                     mime_type: str = "", tags: list = None,
                     uploaded_by: str = "system") -> dict:
        ev_id = "ev_" + hashlib.md5(f"{claim_id}{title}{datetime.utcnow().timestamp()}".encode()).hexdigest()[:12]
        now = datetime.utcnow().isoformat() + "Z"
        conn = _get_db()
        tag_json = json.dumps(tags or [])
        custody = json.dumps([{"action": "uploaded", "by": uploaded_by, "at": now}])
        conn.execute(
            "INSERT INTO evidence_items (evidence_id, claim_id, evidence_type, title, description, source_url, file_hash, file_size_bytes, mime_type, tags, chain_of_custody, uploaded_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev_id, claim_id, evidence_type, title, description, source_url, file_hash, file_size_bytes, mime_type, tag_json, custody, uploaded_by, now),
        )
        conn.commit()
        self.audit("evidence_added", {"evidence_id": ev_id, "claim_id": claim_id, "type": evidence_type, "title": title})
        return {"evidence_id": ev_id, "claim_id": claim_id, "evidence_type": evidence_type, "title": title, "status": "pending", "created_at": now}

    def list_evidence(self, claim_id: str = None, evidence_type: str = None,
                      verified: bool = None, status: str = None,
                      limit: int = 100, offset: int = 0) -> dict:
        conn = _get_db()
        where, params = [], []
        if claim_id:
            where.append("claim_id = ?")
            params.append(claim_id)
        if evidence_type:
            where.append("evidence_type = ?")
            params.append(evidence_type)
        if verified is not None:
            where.append("verified = ?")
            params.append(1 if verified else 0)
        if status:
            where.append("status = ?")
            params.append(status)
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM evidence_items{clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM evidence_items{clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            d["chain_of_custody"] = json.loads(d.get("chain_of_custody", "[]"))
            d["verified"] = bool(d.get("verified", 0))
            items.append(d)
        return {"evidence": items, "total": total, "limit": limit, "offset": offset}

    def get_evidence(self, evidence_id: str) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["tags"] = json.loads(d.get("tags", "[]"))
        d["chain_of_custody"] = json.loads(d.get("chain_of_custody", "[]"))
        d["verified"] = bool(d.get("verified", 0))
        return d

    def update_evidence(self, evidence_id: str, updates: dict) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            return None
        allowed = {"title", "description", "source_url", "evidence_type", "status", "mime_type"}
        sets, vals = [], []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if "tags" in updates:
            sets.append("tags = ?")
            vals.append(json.dumps(updates["tags"]))
        if not sets:
            return self.get_evidence(evidence_id)
        sets.append("updated_at = ?")
        vals.append(datetime.utcnow().isoformat() + "Z")
        vals.append(evidence_id)
        conn.execute(f"UPDATE evidence_items SET {', '.join(sets)} WHERE evidence_id = ?", vals)
        conn.commit()
        return self.get_evidence(evidence_id)

    def delete_evidence(self, evidence_id: str) -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM evidence_items WHERE evidence_id = ?", (evidence_id,))
        conn.commit()
        return {"deleted": evidence_id}

    def verify_evidence(self, evidence_id: str, verified_by: str = "operator", notes: str = "") -> dict:
        conn = _get_db()
        row = conn.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            return None
        now = datetime.utcnow().isoformat() + "Z"
        custody = json.loads(dict(row).get("chain_of_custody", "[]"))
        custody.append({"action": "verified", "by": verified_by, "at": now, "notes": notes})
        conn.execute(
            "UPDATE evidence_items SET verified = 1, verified_by = ?, verified_at = ?, chain_of_custody = ?, status = 'verified', updated_at = ? WHERE evidence_id = ?",
            (verified_by, now, json.dumps(custody), now, evidence_id),
        )
        conn.commit()
        self.audit("evidence_verified", {"evidence_id": evidence_id, "verified_by": verified_by})
        return self.get_evidence(evidence_id)

    def get_evidence_stats(self) -> dict:
        conn = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
        verified = conn.execute("SELECT COUNT(*) FROM evidence_items WHERE verified = 1").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM evidence_items WHERE status = 'pending'").fetchone()[0]
        rejected = conn.execute("SELECT COUNT(*) FROM evidence_items WHERE status = 'rejected'").fetchone()[0]
        total_size = conn.execute("SELECT COALESCE(SUM(file_size_bytes), 0) FROM evidence_items").fetchone()[0]
        by_type = {}
        for r in conn.execute("SELECT evidence_type, COUNT(*) FROM evidence_items GROUP BY evidence_type").fetchall():
            by_type[r[0]] = r[1]
        claims_with_evidence = conn.execute("SELECT COUNT(DISTINCT claim_id) FROM evidence_items").fetchone()[0]
        return {
            "total_items": total, "verified": verified, "pending": pending, "rejected": rejected,
            "verification_rate": round(verified / max(total, 1) * 100, 1),
            "total_size_bytes": total_size,
            "by_type": by_type,
            "claims_with_evidence": claims_with_evidence,
        }

    def get_evidence_types(self) -> dict:
        conn = _get_db()
        rows = conn.execute("SELECT DISTINCT evidence_type FROM evidence_items ORDER BY evidence_type").fetchall()
        defaults = ["screenshot", "email", "receipt", "contract", "correspondence", "bank_statement", "document", "other"]
        existing = [r[0] for r in rows]
        return {"types": sorted(set(defaults + existing))}


def _human_size(nbytes: int) -> str:
    """Convert bytes to human-readable size string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} PB"


store = Store()


# ============================================================================
# SIGNAL SCOUTS — Telemetry & Pattern Detection Engine
# ============================================================================
# Signal Scouts watches claim data for patterns that reveal systemic abuse:
#   - Respondent clustering (same company, many claims)
#   - Amount anomalies (unusually large/small clusters)
#   - Harm type concentrations
#   - Geographic patterns (same respondent, different claimants)
#   - Velocity signals (spikes in claims against one entity)
# ============================================================================


class SignalType(str, Enum):
    """Types of signals the scout engine can detect."""
    RESPONDENT_CLUSTER  = "respondent_cluster"     # Many claims vs same company
    AMOUNT_ANOMALY      = "amount_anomaly"          # Unusual amount patterns
    HARM_CONCENTRATION  = "harm_concentration"      # Same harm type repeated
    VELOCITY_SPIKE      = "velocity_spike"          # Sudden burst of claims
    SYSTEMIC_PATTERN    = "systemic_pattern"        # Cross-signal systemic flag
    REPEAT_OFFENDER     = "repeat_offender"         # Respondent with resolved + new claims
    HIGH_VALUE_CLUSTER  = "high_value_cluster"      # Multiple high-value claims vs one entity


class SignalSeverity(str, Enum):
    INFO    = "info"
    WARNING = "warning"
    ALERT   = "alert"
    CRITICAL = "critical"


def _get_respondent_key(claim: Dict) -> str:
    """Get the best normalized respondent key for grouping."""
    return claim.get("respondent_normalized_id") or (claim.get("respondent_entity") or "unknown").lower().strip()


def _get_respondent_display(claim: Dict) -> str:
    """Get the display name for a respondent."""
    return claim.get("respondent_entity") or "Unknown"


def _scout_respondent_clusters(claims: List[Dict]) -> List[Dict]:
    """Detect when multiple claimants target the same respondent."""
    signals = []
    respondent_map: Dict[str, List[Dict]] = {}
    for c in claims:
        resp = _get_respondent_key(c)
        respondent_map.setdefault(resp, []).append(c)

    for resp_id, cluster in respondent_map.items():
        if len(cluster) >= 2:
            total_amount = sum(c.get("amount_claimed_usd", 0) for c in cluster)
            unique_claimants = len(set(c.get("claimant_email", "") for c in cluster))
            display = _get_respondent_display(cluster[0])
            severity = SignalSeverity.WARNING
            if len(cluster) >= 5:
                severity = SignalSeverity.CRITICAL
            elif len(cluster) >= 3:
                severity = SignalSeverity.ALERT

            signals.append({
                "signal_type": SignalType.RESPONDENT_CLUSTER.value,
                "severity": severity.value,
                "respondent": display,
                "respondent_id": resp_id,
                "claim_count": len(cluster),
                "unique_claimants": unique_claimants,
                "total_amount": round(total_amount, 2),
                "avg_amount": round(total_amount / len(cluster), 2),
                "claim_ids": [c["claim_id"] for c in cluster],
                "message": f"{display}: {len(cluster)} claims from {unique_claimants} claimants totaling ${total_amount:,.2f}",
            })
    return signals


def _scout_amount_anomalies(claims: List[Dict]) -> List[Dict]:
    """Detect unusual amount patterns — very large or clustered amounts."""
    signals = []
    amounts = [c.get("amount_claimed_usd", 0) for c in claims if c.get("amount_claimed_usd", 0) > 0]
    if not amounts:
        return signals

    avg_amount = sum(amounts) / len(amounts)
    # Flag any claim more than 5x the average
    for c in claims:
        amt = c.get("amount_claimed_usd", 0)
        if amt > 0 and avg_amount > 0 and amt > avg_amount * 5:
            signals.append({
                "signal_type": SignalType.AMOUNT_ANOMALY.value,
                "severity": SignalSeverity.ALERT.value,
                "claim_id": c.get("claim_id"),
                "respondent": c.get("respondent_entity", "Unknown"),
                "amount": amt,
                "avg_amount": round(avg_amount, 2),
                "ratio": round(amt / avg_amount, 1),
                "message": f"Claim {c.get('claim_id', '?')}: ${amt:,.2f} is {amt/avg_amount:.1f}x the average (${avg_amount:,.2f})",
            })
    return signals


def _scout_harm_concentration(claims: List[Dict]) -> List[Dict]:
    """Detect concentrated harm types against specific respondents."""
    signals = []
    # Group by (respondent_normalized, harm_type)
    combos: Dict[tuple, List[Dict]] = {}
    for c in claims:
        resp = _get_respondent_key(c)
        harm = c.get("harm_type", "unknown")
        combos.setdefault((resp, harm), []).append(c)

    for (resp_id, harm), group in combos.items():
        if len(group) >= 2:
            display = _get_respondent_display(group[0])
            signals.append({
                "signal_type": SignalType.HARM_CONCENTRATION.value,
                "severity": SignalSeverity.WARNING.value if len(group) < 4 else SignalSeverity.ALERT.value,
                "respondent": display,
                "respondent_id": resp_id,
                "harm_type": harm,
                "claim_count": len(group),
                "total_amount": round(sum(c.get("amount_claimed_usd", 0) for c in group), 2),
                "claim_ids": [c["claim_id"] for c in group],
                "message": f"{display}: {len(group)} claims for {harm.replace('_', ' ')}",
            })
    return signals


def _scout_velocity_spikes(claims: List[Dict]) -> List[Dict]:
    """Detect sudden bursts of claims against a single respondent."""
    signals = []
    now = datetime.utcnow()
    respondent_recent: Dict[str, List[Dict]] = {}

    for c in claims:
        filed_str = c.get("filed_at", "")
        try:
            filed = datetime.fromisoformat(filed_str.replace("Z", "").replace("+00:00", ""))
            age = (now - filed).days
        except (ValueError, TypeError):
            age = 999

        if age <= 7:  # Last 7 days
            resp = _get_respondent_key(c)
            respondent_recent.setdefault(resp, []).append(c)

    for resp_id, recent in respondent_recent.items():
        if len(recent) >= 3:
            display = _get_respondent_display(recent[0])
            signals.append({
                "signal_type": SignalType.VELOCITY_SPIKE.value,
                "severity": SignalSeverity.CRITICAL.value,
                "respondent": display,
                "respondent_id": resp_id,
                "claims_this_week": len(recent),
                "total_amount": round(sum(c.get("amount_claimed_usd", 0) for c in recent), 2),
                "claim_ids": [c["claim_id"] for c in recent],
                "message": f"VELOCITY: {len(recent)} claims vs {display} in the last 7 days",
            })
    return signals


def _scout_high_value_clusters(claims: List[Dict]) -> List[Dict]:
    """Detect respondents with multiple high-value claims (>$1000)."""
    signals = []
    respondent_high: Dict[str, List[Dict]] = {}
    for c in claims:
        if c.get("amount_claimed_usd", 0) >= 1000:
            resp = _get_respondent_key(c)
            respondent_high.setdefault(resp, []).append(c)

    for resp_id, group in respondent_high.items():
        if len(group) >= 2:
            total = sum(c.get("amount_claimed_usd", 0) for c in group)
            display = _get_respondent_display(group[0])
            signals.append({
                "signal_type": SignalType.HIGH_VALUE_CLUSTER.value,
                "severity": SignalSeverity.ALERT.value,
                "respondent": display,
                "respondent_id": resp_id,
                "claim_count": len(group),
                "total_amount": round(total, 2),
                "claim_ids": [c["claim_id"] for c in group],
                "message": f"{resp.title()}: {len(group)} high-value claims totaling ${total:,.2f}",
            })
    return signals


def _compute_signal_decay(signals: List[Dict], claims_by_id: Dict[str, Dict]) -> List[Dict]:
    """
    Apply time-based decay to signals.

    Freshness tiers:
      fresh   — newest claim ≤ 7 days old
      recent  — newest claim ≤ 30 days old
      aging   — newest claim ≤ 90 days old
      stale   — newest claim > 90 days old

    Decay rules:
      - Stale signals: severity downgraded one level
        (critical→alert, alert→warning, warning→info)
      - Aging signals: flagged but not downgraded
      - Fresh/recent: unchanged
    """
    now = datetime.utcnow()
    downgrade_map = {"critical": "alert", "alert": "warning", "warning": "info", "info": "info"}

    for sig in signals:
        # Find the newest claim in this signal
        claim_ids = sig.get("claim_ids", [])
        single_id = sig.get("claim_id")
        if single_id and not claim_ids:
            claim_ids = [single_id]

        newest_age = 9999
        for cid in claim_ids:
            c = claims_by_id.get(cid, {})
            filed_str = c.get("filed_at", "")
            try:
                filed = datetime.fromisoformat(filed_str.replace("Z", "").replace("+00:00", ""))
                age = (now - filed).days
                newest_age = min(newest_age, age)
            except (ValueError, TypeError, AttributeError):
                pass

        # Assign freshness tier
        if newest_age <= 7:
            freshness = "fresh"
        elif newest_age <= 30:
            freshness = "recent"
        elif newest_age <= 90:
            freshness = "aging"
        else:
            freshness = "stale"

        sig["signal_age_days"] = newest_age if newest_age < 9999 else None
        sig["freshness"] = freshness

        # Downgrade stale signals — old patterns should not carry the same weight
        if freshness == "stale":
            original = sig["severity"]
            sig["severity"] = downgrade_map.get(original, original)
            sig["decay_applied"] = original != sig["severity"]
            sig["original_severity"] = original
        else:
            sig["decay_applied"] = False

    return signals


def run_signal_scouts(claims: List[Dict]) -> Dict[str, Any]:
    """
    Run all Signal Scout detectors on the full claims dataset.
    Returns a structured intelligence report with decay applied.
    """
    all_signals: List[Dict] = []

    # Run each scout
    all_signals.extend(_scout_respondent_clusters(claims))
    all_signals.extend(_scout_amount_anomalies(claims))
    all_signals.extend(_scout_harm_concentration(claims))
    all_signals.extend(_scout_velocity_spikes(claims))
    all_signals.extend(_scout_high_value_clusters(claims))

    # Build claim lookup for decay computation
    claims_by_id = {c.get("claim_id", ""): c for c in claims}

    # Apply time-based decay
    all_signals = _compute_signal_decay(all_signals, claims_by_id)

    # Sort by severity (post-decay)
    severity_order = {"critical": 0, "alert": 1, "warning": 2, "info": 3}
    all_signals.sort(key=lambda s: severity_order.get(s.get("severity", "info"), 9))

    # Mark claims with systemic flags (only fresh/recent signals count)
    systemic_claim_ids = set()
    for sig in all_signals:
        if sig.get("severity") in ("critical", "alert") and sig.get("freshness") in ("fresh", "recent"):
            for cid in sig.get("claim_ids", []):
                systemic_claim_ids.add(cid)

    # Summary counts (post-decay)
    summary = {
        "total_signals": len(all_signals),
        "critical": len([s for s in all_signals if s["severity"] == "critical"]),
        "alerts": len([s for s in all_signals if s["severity"] == "alert"]),
        "warnings": len([s for s in all_signals if s["severity"] == "warning"]),
        "stale_signals": len([s for s in all_signals if s.get("freshness") == "stale"]),
        "decayed_signals": len([s for s in all_signals if s.get("decay_applied")]),
        "systemic_claims": len(systemic_claim_ids),
        "systemic_claim_ids": list(systemic_claim_ids),
    }

    # Top signal sources — weighted by recency (fresh=3, recent=2, aging=1, stale=0.25)
    freshness_weights = {"fresh": 3.0, "recent": 2.0, "aging": 1.0, "stale": 0.25}
    respondent_scores: Dict[str, float] = {}
    respondent_counts: Dict[str, int] = {}
    for sig in all_signals:
        resp = sig.get("respondent", "Unknown")
        weight = freshness_weights.get(sig.get("freshness", "recent"), 1.0)
        respondent_scores[resp] = respondent_scores.get(resp, 0) + weight
        respondent_counts[resp] = respondent_counts.get(resp, 0) + 1
    top_threats = sorted(respondent_scores.items(), key=lambda x: -x[1])[:5]

    return {
        "signals": all_signals,
        "summary": summary,
        "top_threats": [
            {"respondent": r, "signal_count": respondent_counts.get(r, 0), "weighted_score": round(sc, 2)}
            for r, sc in top_threats
        ],
        "scanned_at": datetime.utcnow().isoformat(),
        "claims_scanned": len(claims),
    }


# ============================================================================
# MAPPING FUNCTIONS
# ============================================================================

def normalize_support_status(raw: str) -> SupportContactStatus:
    """Map Google Form answer to enum."""
    raw_lower = raw.strip().lower()
    if "no resolution" in raw_lower:
        return SupportContactStatus.YES_NO_RESOLUTION
    elif "still waiting" in raw_lower:
        return SupportContactStatus.YES_STILL_WAITING
    elif "not yet" in raw_lower or raw_lower.startswith("no"):
        return SupportContactStatus.NO_NOT_YET
    return SupportContactStatus.NO_NOT_YET


def normalize_referral(raw: Optional[str]) -> ReferralSource:
    """Map Google Form answer to enum."""
    if not raw:
        return ReferralSource.OTHER
    raw_lower = raw.strip().lower()
    mapping = {
        "reddit": ReferralSource.REDDIT,
        "twitter": ReferralSource.TWITTER_X,
        "x": ReferralSource.TWITTER_X,
        "twitter/x": ReferralSource.TWITTER_X,
        "discord": ReferralSource.DISCORD,
        "word of mouth": ReferralSource.WORD_OF_MOUTH,
        "tiktok": ReferralSource.TIKTOK,
    }
    return mapping.get(raw_lower, ReferralSource.OTHER)


def classify_harm_type(platform: str, reason: str) -> HarmType:
    """Infer harm type from platform and reason text."""
    combined = f"{platform} {reason}".lower()
    if any(kw in combined for kw in ["payout", "payment", "withh", "delay"]):
        return HarmType.PAYOUT_WITHHOLDING
    if any(kw in combined for kw in ["lock", "suspend", "ban", "restrict"]):
        return HarmType.PLATFORM_LOCKOUT
    if any(kw in combined for kw in ["wage", "salary", "pay", "owed"]):
        return HarmType.WAGE_THEFT
    if any(kw in combined for kw in ["fee", "charge", "deduction"]):
        return HarmType.UNDISCLOSED_FEE
    return HarmType.PAYOUT_WITHHOLDING  # default for payment recovery


def intake_to_claim(submission_id: str, req: IntakeRequest) -> Dict[str, Any]:
    """Convert an IntakeRequest into a Claim record."""
    harm_type = classify_harm_type(req.platform_or_company, req.platform_reason)
    resp_norm = normalize_respondent(req.platform_or_company)
    canonical_name = normalize_claimant_name(req.full_name)

    return {
        "vertical": "platform_dispute",
        "status": CaseStatus.FILED.value,
        "claimant_name": canonical_name,
        "claimant_email": req.email,
        "claimant_phone": req.phone,
        "intake_submission_id": submission_id,
        "respondent_entity": resp_norm["display_name"],
        "respondent_normalized_id": resp_norm["normalized_id"],
        "respondent_original": resp_norm["original"],
        "harm_type": harm_type.value,
        "amount_claimed_usd": req.estimated_amount_usd,
        "description": req.platform_reason,
        "last_expected_payment": req.last_expected_payment,
        "contacted_support": normalize_support_status(req.contacted_support).value,
        "referral_source": normalize_referral(req.referral_source).value,
        "execution_score": 0.0,
        "evidence": [],
        "escalation_history": [],
    }


# ============================================================================
# AUTH MIDDLEWARE
# ============================================================================

def verify_api_key(authorization: Optional[str] = Header(None)) -> str:
    """Verify the Bearer token matches our intake API key.
    In local dev mode, auth is skipped if no key is provided.
    In production, set REQUIRE_AUTH=true in environment.
    """
    import os
    require_auth = os.environ.get("REQUIRE_AUTH", "false").lower() == "true"

    if not authorization:
        if require_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "UNAUTHORIZED", "message": "Missing Authorization header"},
            )
        return "local_dev"

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        if require_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "UNAUTHORIZED", "message": "Invalid Authorization format"},
            )
        return "local_dev"

    if not hmac.compare_digest(parts[1], config.INTAKE_API_KEY):
        if require_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "UNAUTHORIZED", "message": "Invalid API key"},
            )
        return "local_dev"

    return parts[1]


# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="GhostLedger Intake Service",
    description="Payment Recovery Intake Pipeline — Google Form to Claim",
    version="1.0.0",
)

# --- OPS DASHBOARD AUTH ---
import secrets as _secrets
_security = HTTPBasic()
_OPS_USER = os.environ.get("GL_OPS_USER", "ops")
_OPS_PASS = os.environ.get("GL_OPS_PASS", "gl-recovery-2026")

def _verify_ops(credentials: HTTPBasicCredentials = Depends(_security)):
    ok_user = _secrets.compare_digest(credentials.username, _OPS_USER)
    ok_pass = _secrets.compare_digest(credentials.password, _OPS_PASS)
    if not ok_user or ok_pass == False:
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

# CORS — allow browser requests from localhost and deployed origins
_allowed_origins = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:8081,http://127.0.0.1:8081,http://localhost:3000",
).split(",")

# In production, set CORS_ORIGINS to your actual domain(s)
# e.g. CORS_ORIGINS=https://ghostledger.fly.dev,https://ghostledger.railway.app
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins if _allowed_origins != ["*"] else ["*"],
    allow_credentials=True if _allowed_origins != ["*"] else False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root_redirect():
    """Redirect public visitors to the how-it-works page."""
    return RedirectResponse(url="/how-it-works")

@app.get("/ops", response_class=HTMLResponse)
async def dashboard(operator: str = Depends(_verify_ops)):
    """Serve the GhostLedger Operations Hub dashboard (auth required)."""
    html_path = Path(__file__).parent / "GhostLedger.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(
        content="<h1>GhostLedger</h1><p>Dashboard HTML not found.</p>",
        status_code=200,
    )


@app.get("/portal", response_class=HTMLResponse)
async def portal():
    """Serve the Claimant Portal — public-facing status check page."""
    html_path = Path(__file__).parent / "portal.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(
        content="<h1>GhostLedger</h1><p>Portal not found.</p>",
        status_code=200,
    )



@app.get("/doctrine", response_class=HTMLResponse)
async def doctrine_page():
    """Serve the Doctrine page — public-facing."""
    html_path = Path(__file__).parent / "doctrine.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(content="<h1>Coming Soon</h1>", status_code=200)

@app.get("/transparency", response_class=HTMLResponse)
async def transparency_page():
    """Serve the Transparency page — public-facing."""
    html_path = Path(__file__).parent / "transparency.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(content="<h1>Coming Soon</h1>", status_code=200)

@app.get("/litmus", response_class=HTMLResponse)
async def litmus_page():
    """Serve the LITMUS editorial page — public-facing."""
    html_path = Path(__file__).parent / "litmus.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(content="<h1>Coming Soon</h1>", status_code=200)

@app.get("/professionals", response_class=HTMLResponse)
async def professionals_page():
    """Serve the ILF Professional Entry Page — public-facing."""
    html_path = Path(__file__).parent / "professionals.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(content="<h1>Coming Soon</h1>", status_code=200)

@app.get("/how-it-works", response_class=HTMLResponse)
async def how_it_works():
    """Public-facing explainer page — describes how GhostLedger works."""
    html_path = Path(__file__).parent / "how-it-works.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(
        content="<h1>GhostLedger</h1><p>Explainer page not found.</p>",
        status_code=200,
    )


@app.get("/health", response_model=HealthResponse)
async def health():
    """Service health check."""
    uptime = (datetime.utcnow() - store.start_time).total_seconds()
    return HealthResponse(
        uptime_seconds=round(uptime, 1),
        submissions_processed=store.submission_count,
    )


@app.get("/ready")
async def ready():
    """Readiness probe. Returns 200 when the service can accept traffic."""
    return {"ready": True}


@app.get("/v1/verticals")
async def list_verticals(
    authorization: Optional[str] = Header(None),
):
    """
    List supported claim verticals and their status.
    Verticals define the type of dispute/claim being tracked.
    Currently supported: platform_dispute (active).
    Coming soon: insurance_auto, insurance_property.
    """
    verify_api_key(authorization)
    return {"verticals": SUPPORTED_VERTICALS}


@app.post(
    "/v1/intake/submissions",
    response_model=IntakeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_intake(
    req: IntakeRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Receive a Google Form submission and process it into a Claim.

    Flow:
    1. Validate authorization
    2. Validate form fields
    3. Create IntakeSubmission
    4. Convert to Claim via intake_to_claim()
    5. Publish events to bus
    6. Return submission + claim IDs
    """
    # Auth
    verify_api_key(authorization)

    logger.info(f"Intake received: {req.full_name} vs {req.platform_or_company} "
                f"(${req.estimated_amount_usd:.2f})")

    # Save submission
    submission_data = req.model_dump()
    submission_data["contacted_support"] = normalize_support_status(
        req.contacted_support
    ).value
    submission_data["referral_source"] = normalize_referral(
        req.referral_source
    ).value
    submission_id = store.save_submission(submission_data)

    # Convert to claim
    claim_data = intake_to_claim(submission_id, req)

    # ── CCE: Auto-classify before saving ──
    cce_result = run_cce(claim_data)
    claim_data.update(cce_result)
    logger.info(
        f"CCE classified: band={cce_result['classification']['value_band']}, "
        f"type={cce_result['classification']['dispute_type']}, "
        f"complexity={cce_result['classification']['complexity_score']}, "
        f"path={cce_result['classification']['recovery_path']}, "
        f"triage={cce_result['classification']['requires_human_triage']}"
    )

    claim_id = store.save_claim(claim_data)

    # Link submission to claim
    store.link_submission_to_claim(submission_id, claim_id)

    # Publish events
    store.publish_event("intake.submission.received", {
        "submission_id": submission_id,
        "email": req.email,
        "platform": req.platform_or_company,
        "amount": req.estimated_amount_usd,
    })

    store.publish_event("intake.submission.converted", {
        "submission_id": submission_id,
        "claim_id": claim_id,
    })

    store.publish_event("case.claim.filed", {
        "claim_id": claim_id,
        "respondent": req.platform_or_company,
        "amount": req.estimated_amount_usd,
        "harm_type": claim_data["harm_type"],
    })

    store.publish_event("ilf.case.classified", {
        "claim_id": claim_id,
        "classification": cce_result["classification"],
    })

    store.audit("claim.intake", {
        "claim_id": claim_id,
        "respondent": claim_data.get("respondent_entity", "Unknown"),
        "amount": req.estimated_amount_usd,
        "classification": cce_result.get("classification", {}),
    })

    store.audit("claim.classified", {
        "claim_id": claim_id,
        "value_band": cce_result["classification"].get("value_band", "unknown"),
        "dispute_type": cce_result["classification"].get("dispute_type", "other"),
        "recovery_path": cce_result["classification"].get("recovery_path", "informational_only"),
        "complexity_score": cce_result["classification"].get("complexity_score", 0),
        "requires_human_triage": cce_result["classification"].get("requires_human_triage", False),
        "trigger": "initial_intake",
    })

    logger.info(f"Claim created: {claim_id} from submission {submission_id}")

    # Trigger workflow rules for new claim
    _run_workflow_rules("claim.filed", claim_data)

    # Notification: new claim filed
    try:
        amt = claim_data.get("amount_claimed_usd", 0)
        resp = claim_data.get("respondent_entity", "Unknown")
        sev = "warning" if amt >= 5000 else "info"
        store.create_notification(
            "claim_filed", sev,
            f"New Claim Filed: ${amt:,.0f} vs {resp}",
            f"Claim {claim_id} filed by {claim_data.get('claimant_name','?')} against {resp}.",
            claim_id=claim_id, source="intake",
            action_label="View Claim",
        )
    except Exception:
        pass

    return IntakeResponse(
        submission_id=submission_id,
        claim_id=claim_id,
        status="filed",
        message="Claim received and classified. Review will begin as capacity allows.",
        created_at=datetime.utcnow().isoformat(),
    )


@app.get("/v1/intake/submissions/{submission_id}")
async def get_submission(
    submission_id: str,
    authorization: Optional[str] = Header(None),
):
    """Retrieve a submission by ID."""
    verify_api_key(authorization)
    sub = store.get_submission(submission_id)
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Submission not found"},
        )
    return sub


@app.get("/v1/claims/export")
async def export_claims(
    format: str = "csv",
    status_filter: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """
    Read-only export of claims as CSV or JSON.
    Includes export timestamp and SHA-256 checksum for integrity.
    Sensitive fields (email, phone) are redacted in exports.
    """
    verify_api_key(authorization)
    claims = store.list_claims(status_filter=status_filter)
    export_timestamp = datetime.utcnow().isoformat() + "Z"

    # Redact sensitive fields for export
    safe_claims = []
    for c in claims:
        cc = c.get("classification", {})
        safe_claims.append({
            "claim_id": c.get("claim_id", ""),
            "status": c.get("status", ""),
            "respondent": c.get("respondent_entity", "Unknown"),
            "harm_type": c.get("harm_type", "other"),
            "amount_usd": c.get("amount_claimed_usd", 0),
            "value_band": cc.get("value_band", ""),
            "dispute_type": cc.get("dispute_type", ""),
            "recovery_path": cc.get("recovery_path", ""),
            "complexity_score": cc.get("complexity_score", 0),
            "requires_triage": cc.get("requires_human_triage", False),
            "systemic_flag": cc.get("systemic_flag", False),
            "filed_at": c.get("filed_at", ""),
            "updated_at": c.get("updated_at", ""),
        })

    if format.lower() == "json":
        export_payload = {
            "export_metadata": {
                "format": "json",
                "exported_at": export_timestamp,
                "total_claims": len(safe_claims),
                "filter_applied": status_filter,
                "source": "GhostLedger Claims",
                "note": "Claimant PII has been redacted for compliance",
            },
            "claims": safe_claims,
        }
        raw_bytes = json.dumps(export_payload, indent=2, sort_keys=True).encode("utf-8")
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        export_payload["export_metadata"]["sha256_checksum"] = checksum
        final_bytes = json.dumps(export_payload, indent=2, sort_keys=True).encode("utf-8")
        filename = f"ghostledger_claims_{export_timestamp[:10].replace('-', '')}.json"
        store.audit("export.claims", {
            "format": "json",
            "claims_exported": len(safe_claims),
            "filter": status_filter,
            "checksum": checksum,
        }, actor="operator")
        return Response(
            content=final_bytes,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Export-Timestamp": export_timestamp,
                "X-Export-Checksum": checksum,
            },
        )
    else:
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        headers = ["claim_id", "status", "respondent", "harm_type", "amount_usd",
                    "value_band", "dispute_type", "recovery_path", "complexity_score",
                    "requires_triage", "systemic_flag", "filed_at", "updated_at"]
        writer.writerow(headers)
        for c in safe_claims:
            writer.writerow([c.get(h, "") for h in headers])
        csv_content = output.getvalue()
        raw_bytes = csv_content.encode("utf-8")
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        csv_content += f"\n# Export: {export_timestamp} | Claims: {len(safe_claims)} | SHA-256: {checksum}\n"
        final_bytes = csv_content.encode("utf-8")
        filename = f"ghostledger_claims_{export_timestamp[:10].replace('-', '')}.csv"
        store.audit("export.claims", {
            "format": "csv",
            "claims_exported": len(safe_claims),
            "filter": status_filter,
            "checksum": checksum,
        }, actor="operator")
        return Response(
            content=final_bytes,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Export-Timestamp": export_timestamp,
                "X-Export-Checksum": checksum,
            },
        )


@app.get("/v1/claims/{claim_id}")
async def get_claim(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Retrieve a claim by ID."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Claim not found"},
        )
    return claim


@app.get("/v1/transitions")
async def get_transition_rules(
    authorization: Optional[str] = Header(None),
):
    """Return the full status transition rule map for reference."""
    verify_api_key(authorization)
    return {
        "rules": {k: sorted(v) for k, v in VALID_STATUS_TRANSITIONS.items()},
        "statuses": [s.value for s in CaseStatus],
    }


@app.get("/v1/claims/{claim_id}/transitions")
async def get_valid_transitions(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get valid status transitions for a claim's current status."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Claim not found"},
        )
    current = claim.get("status", "filed")
    allowed = sorted(VALID_STATUS_TRANSITIONS.get(current, set()))
    return {
        "claim_id": claim_id,
        "current_status": current,
        "allowed_transitions": allowed,
        "respondent": claim.get("respondent_entity", "Unknown"),
        "amount": claim.get("amount_claimed_usd", 0),
    }


@app.patch("/v1/claims/{claim_id}/status")
async def update_claim_status(
    claim_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Update a claim's status with transition validation and reason tracking.
    Body: {"status": "under_review", "reason": "Initial review complete"}
    The reason field is required for status transitions.
    """
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Claim not found"},
        )
    new_status = str(body.get("status", "")).lower()
    reason = str(body.get("reason", "")).strip()
    valid = {s.value for s in CaseStatus}
    if new_status not in valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_STATUS", "message": f"Must be one of: {', '.join(valid)}"},
        )

    old_status = claim.get("status", "filed")

    # Validate transition
    allowed = VALID_STATUS_TRANSITIONS.get(old_status, set())
    if new_status not in allowed and new_status != old_status:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "INVALID_TRANSITION",
                "message": f"Cannot transition from '{old_status}' to '{new_status}'. Allowed: {', '.join(sorted(allowed)) if allowed else 'none'}",
                "current_status": old_status,
                "allowed_transitions": sorted(allowed),
            },
        )

    # Skip if no actual change
    if new_status == old_status:
        return {"claim_id": claim_id, "status": old_status, "message": "No change"}

    store.update_claim_status(claim_id, new_status)
    store.publish_event("case.status.changed", {
        "claim_id": claim_id,
        "old_status": old_status,
        "new_status": new_status,
    })
    store.audit("status.changed", {
        "claim_id": claim_id,
        "old_status": old_status,
        "new_status": new_status,
        "respondent": claim.get("respondent_entity", "Unknown"),
        "reason": reason if reason else "—",
    }, actor="operator")

    # Handoff tracking: log when a case transitions to escalation or resolution
    handoff_stages = {"escalated", "in_resolution"}
    if new_status in handoff_stages and old_status not in handoff_stages:
        classification = claim.get("classification", {})
        store.audit("handoff.initiated", {
            "claim_id": claim_id,
            "respondent": claim.get("respondent_entity", "Unknown"),
            "amount": claim.get("amount_claimed_usd", 0),
            "from_status": old_status,
            "to_status": new_status,
            "recovery_path": classification.get("recovery_path", "unknown"),
            "value_band": classification.get("value_band", "unknown"),
            "requires_human_triage": classification.get("requires_human_triage", False),
            "reason": reason if reason else "—",
        }, actor="operator")

    logger.info(f"Claim {claim_id}: {old_status} → {new_status} (reason: {reason or '—'})")

    # Trigger workflow rules for status change
    updated_claim = store.get_claim(claim_id) or claim
    _run_workflow_rules("status.changed", updated_claim)

    # Notification: status changed
    try:
        resp = claim.get("respondent_entity", "Unknown")
        sev = "warning" if new_status == "escalated" else "info"
        store.create_notification(
            "status_changed", sev,
            f"Status → {new_status.replace('_',' ').title()}: {claim_id[:16]}",
            f"Claim against {resp} moved from {old_status} to {new_status}." + (f" Reason: {reason}" if reason else ""),
            claim_id=claim_id, source="status_engine",
            action_label="View Claim",
        )
    except Exception:
        pass

    return {"claim_id": claim_id, "status": new_status, "message": "Status updated"}


@app.post("/v1/claims/{claim_id}/reclassify")
async def reclassify_claim(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Re-run CCE on an existing claim. Useful for pre-CCE claims or after edits."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Claim not found"},
        )
    cce_result = run_cce(claim)
    store.reclassify_claim(claim_id, cce_result["classification"])
    store.publish_event("ilf.case.classified", {
        "claim_id": claim_id,
        "classification": cce_result["classification"],
        "reclassified": True,
    })
    store.audit("claim.classified", {
        "claim_id": claim_id,
        "value_band": cce_result["classification"].get("value_band", "unknown"),
        "dispute_type": cce_result["classification"].get("dispute_type", "other"),
        "recovery_path": cce_result["classification"].get("recovery_path", "informational_only"),
        "complexity_score": cce_result["classification"].get("complexity_score", 0),
        "requires_human_triage": cce_result["classification"].get("requires_human_triage", False),
        "trigger": "manual_reclassify",
    }, actor="operator")
    logger.info(f"Reclassified {claim_id}: {cce_result['classification']}")
    return {
        "claim_id": claim_id,
        "classification": cce_result["classification"],
        "message": "Claim reclassified",
    }


@app.post("/v1/reclassify-all")
async def reclassify_all(
    authorization: Optional[str] = Header(None),
):
    """Re-run CCE on all claims. Backfills any unclassified claims."""
    verify_api_key(authorization)
    claims = store.list_claims()
    updated = 0
    for claim in claims:
        cce_result = run_cce(claim)
        store.reclassify_claim(claim["claim_id"], cce_result["classification"])
        store.audit("claim.classified", {
            "claim_id": claim["claim_id"],
            "value_band": cce_result["classification"].get("value_band", "unknown"),
            "dispute_type": cce_result["classification"].get("dispute_type", "other"),
            "recovery_path": cce_result["classification"].get("recovery_path", "informational_only"),
            "trigger": "batch_reclassify",
        })
        updated += 1
    logger.info(f"Reclassified {updated} claims")
    return {"reclassified": updated, "message": f"All {updated} claims reclassified"}


@app.get("/v1/claims/{claim_id}/notes")
async def get_notes(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get all notes for a claim."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Claim not found"},
        )
    notes = store.get_notes(claim_id)
    return {"claim_id": claim_id, "notes": notes, "total": len(notes)}


@app.post("/v1/claims/{claim_id}/notes")
async def add_note(
    claim_id: str,
    body: Dict[str, str],
    authorization: Optional[str] = Header(None),
):
    """Add a note to a claim. Body: {"content": "...", "author": "operator"}"""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Claim not found"},
        )
    content = body.get("content", "").strip()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "EMPTY_NOTE", "message": "Note content is required"},
        )
    author = body.get("author", "operator")
    note_id = store.add_note(claim_id, content, author)
    store.publish_event("case.note.added", {
        "claim_id": claim_id,
        "note_id": note_id,
        "author": author,
    })
    store.audit("case.note.added", {
        "claim_id": claim_id,
        "note_id": note_id,
        "author": author,
        "respondent": claim.get("respondent_entity", "Unknown"),
        "content_length": len(content),
    }, actor=author)
    return {"note_id": note_id, "message": "Note added"}


@app.get("/v1/claims")
async def list_claims(
    status_filter: Optional[str] = None,
    respondent: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List all claims with optional filters."""
    verify_api_key(authorization)
    claims = store.list_claims(status_filter=status_filter, respondent=respondent)

    # Enrich with recovery totals
    conn = _get_db()
    recovery_totals = {}
    for row in conn.execute(
        "SELECT claim_id, SUM(amount_recovered) as total FROM recoveries GROUP BY claim_id"
    ).fetchall():
        recovery_totals[row["claim_id"]] = round(row["total"], 2)
    conn.close()

    # Enrich with SLA data
    now = datetime.utcnow()
    last_status_change = {}
    conn2 = _get_db()
    for row in conn2.execute(
        "SELECT detail, timestamp FROM audit_log WHERE action = 'status.changed' ORDER BY timestamp ASC"
    ).fetchall():
        try:
            d = json.loads(row["detail"])
            cid2 = d.get("claim_id", "")
            if cid2:
                last_status_change[cid2] = row["timestamp"]
        except (json.JSONDecodeError, KeyError):
            pass
    conn2.close()

    for c in claims:
        cid = c.get("claim_id", "")
        rec_total = recovery_totals.get(cid, 0)
        c["amount_recovered_usd"] = rec_total
        claimed = c.get("amount_claimed_usd", 0)
        c["recovery_pct"] = round((rec_total / claimed * 100), 1) if claimed > 0 and rec_total > 0 else 0.0

        # SLA info
        status = c.get("status", "draft")
        rule = SLA_RULES.get(status)
        if rule:
            entered_str = last_status_change.get(cid, c.get("filed_at", ""))
            try:
                entered_at = datetime.fromisoformat(entered_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except (ValueError, AttributeError):
                entered_at = now
            days_in = (now - entered_at).total_seconds() / 86400
            max_d = rule["max_days"]
            if days_in > max_d:
                c["sla_status"] = "breached"
            elif days_in >= max_d * rule["warn_pct"]:
                c["sla_status"] = "at_risk"
            else:
                c["sla_status"] = "on_track"
            c["sla_days_remaining"] = round(max_d - days_in, 1)
            c["sla_max_days"] = max_d
        else:
            c["sla_status"] = "n/a"
            c["sla_days_remaining"] = None
            c["sla_max_days"] = None

    # Outreach count enrichment
    conn3 = _get_db()
    outreach_counts = {}
    for row in conn3.execute("SELECT claim_id, COUNT(*) as cnt FROM outreach_log GROUP BY claim_id").fetchall():
        outreach_counts[row["claim_id"]] = row["cnt"]
    # Assignment enrichment
    assignment_map = {}
    for row in conn3.execute(
        "SELECT a.claim_id, a.operator_id, o.name as operator_name FROM assignments a JOIN operators o ON a.operator_id = o.operator_id"
    ).fetchall():
        assignment_map[row["claim_id"]] = {"operator_id": row["operator_id"], "operator_name": row["operator_name"]}
    conn3.close()
    # Resolution enrichment
    conn4 = _get_db()
    resolution_map = {}
    for row in conn4.execute("SELECT claim_id, resolution_type, amount_settled, settlement_ratio FROM resolutions").fetchall():
        resolution_map[row["claim_id"]] = {
            "resolution_type": row["resolution_type"],
            "amount_settled": row["amount_settled"],
            "settlement_ratio": row["settlement_ratio"],
        }
    pending_settlements = {}
    for row in conn4.execute("SELECT claim_id, COUNT(*) as c FROM settlements WHERE status = 'pending' GROUP BY claim_id").fetchall():
        pending_settlements[row["claim_id"]] = row["c"]
    conn4.close()

    # Document count enrichment
    conn5 = _get_db()
    doc_counts = {}
    for row in conn5.execute("SELECT claim_id, COUNT(*) as c FROM documents GROUP BY claim_id").fetchall():
        doc_counts[row["claim_id"]] = row["c"]
    # Case group count enrichment
    group_counts = {}
    for row in conn5.execute("SELECT claim_id, COUNT(*) as c FROM claim_links GROUP BY claim_id").fetchall():
        group_counts[row["claim_id"]] = row["c"]
    # Tag count enrichment
    tag_counts = {}
    for row in conn5.execute("SELECT claim_id, COUNT(*) as c FROM claim_tags GROUP BY claim_id").fetchall():
        tag_counts[row["claim_id"]] = row["c"]
    conn5.close()

    for c in claims:
        cid = c.get("claim_id", "")
        c["outreach_count"] = outreach_counts.get(cid, 0)
        asgn = assignment_map.get(cid)
        c["assigned_to"] = asgn["operator_id"] if asgn else None
        c["assigned_name"] = asgn["operator_name"] if asgn else None
        res = resolution_map.get(cid)
        c["resolution_type"] = res["resolution_type"] if res else None
        c["amount_settled"] = res["amount_settled"] if res else None
        c["settlement_ratio"] = res["settlement_ratio"] if res else None
        c["pending_settlements"] = pending_settlements.get(cid, 0)
        c["document_count"] = doc_counts.get(cid, 0)
        c["group_count"] = group_counts.get(cid, 0)
        c["tag_count"] = tag_counts.get(cid, 0)

    return {
        "claims": claims,
        "total": len(claims),
    }


@app.get("/v1/search")
async def global_search(
    q: str = "",
    authorization: Optional[str] = Header(None),
):
    """
    Global search across claims, ILF professionals, and referrals.
    Searches by: claim ID, respondent, claimant name, harm type,
    professional name, jurisdiction, referral ID.
    Returns categorized results with context for quick navigation.
    """
    verify_api_key(authorization)
    query = q.strip().lower()
    if not query or len(query) < 2:
        return {"results": [], "total": 0, "query": q}

    results = []

    # ── Search Claims ──
    claims = store.list_claims()
    for c in claims:
        cc = c.get("classification", {})
        searchable = " ".join([
            c.get("claim_id", ""),
            c.get("respondent_entity", ""),
            c.get("claimant_name", ""),
            c.get("harm_type", ""),
            c.get("status", ""),
            cc.get("value_band", ""),
            cc.get("dispute_type", ""),
            cc.get("recovery_path", ""),
            c.get("description", ""),
        ]).lower()
        if query in searchable:
            results.append({
                "type": "claim",
                "id": c["claim_id"],
                "title": f"{c.get('respondent_entity', 'Unknown')} — ${c.get('amount_claimed_usd', 0):,.0f}",
                "subtitle": f"{c.get('status', 'filed')} · {cc.get('value_band', '')} · {c.get('harm_type', '')}".replace("_", " "),
                "meta": {
                    "claim_id": c["claim_id"],
                    "respondent": c.get("respondent_entity", "Unknown"),
                    "amount": c.get("amount_claimed_usd", 0),
                    "status": c.get("status", "filed"),
                },
            })

    # ── Search ILF Professionals ──
    lawyers = store.list_lawyers()
    for l in lawyers:
        searchable = " ".join([
            l.get("lawyer_id", ""),
            l.get("full_name", ""),
            l.get("email", ""),
            l.get("jurisdiction", ""),
            l.get("bar_number", ""),
            " ".join(l.get("specializations", [])),
            l.get("status", ""),
        ]).lower()
        if query in searchable:
            results.append({
                "type": "professional",
                "id": l["lawyer_id"],
                "title": l.get("full_name", "Unknown"),
                "subtitle": f"{l.get('jurisdiction', '')} · {', '.join(l.get('specializations', [])[:2])} · {l.get('status', '')}",
                "meta": {
                    "lawyer_id": l["lawyer_id"],
                    "jurisdiction": l.get("jurisdiction", ""),
                    "status": l.get("status", ""),
                },
            })

    # ── Search Referrals ──
    referrals = store.list_referrals()
    for r in referrals:
        claim = store.get_claim(r["claim_id"])
        lawyer = store.get_lawyer(r["lawyer_id"])
        searchable = " ".join([
            r.get("referral_id", ""),
            r.get("claim_id", ""),
            r.get("lawyer_id", ""),
            r.get("status", ""),
            claim.get("respondent_entity", "") if claim else "",
            lawyer.get("full_name", "") if lawyer else "",
        ]).lower()
        if query in searchable:
            results.append({
                "type": "referral",
                "id": r["referral_id"],
                "title": f"Referral: {claim.get('respondent_entity', '?') if claim else '?'} → {lawyer.get('full_name', '?') if lawyer else '?'}",
                "subtitle": f"{r.get('status', 'pending')} · {r.get('referred_at', '')[:10]}",
                "meta": {
                    "referral_id": r["referral_id"],
                    "claim_id": r["claim_id"],
                    "lawyer_id": r["lawyer_id"],
                    "status": r.get("status", "pending"),
                },
            })

    # Limit results
    results = results[:20]

    return {
        "results": results,
        "total": len(results),
        "query": q,
    }


@app.get("/v1/stats")
async def get_stats(
    authorization: Optional[str] = Header(None),
):
    """Aggregate dashboard statistics — claim counts, value bands, dispute types, recovery paths."""
    verify_api_key(authorization)
    return store.get_stats()


@app.get("/v1/followups")
async def get_followups(
    authorization: Optional[str] = Header(None),
):
    """Get prioritized follow-up actions for all active claims."""
    verify_api_key(authorization)
    followups = store.get_followups()
    return {
        "followups": followups,
        "total": len(followups),
        "critical": len([f for f in followups if f["urgency"] == "critical"]),
        "high": len([f for f in followups if f["urgency"] == "high"]),
    }


@app.get("/v1/signals")
async def get_signals(
    authorization: Optional[str] = Header(None),
):
    """
    Signal Scouts — Run pattern detection across all claims.
    Returns detected signals (clusters, anomalies, velocity spikes, etc.)
    sorted by severity.
    """
    verify_api_key(authorization)
    claims = store.list_claims()
    report = run_signal_scouts(claims)

    # Auto-flag systemic claims in the database
    flagged_ids = []
    for cid in report["summary"].get("systemic_claim_ids", []):
        claim = store.get_claim(cid)
        if claim:
            cc = claim.get("classification", {})
            if not cc.get("systemic_flag", False):
                cc["systemic_flag"] = True
                cc["requires_human_triage"] = True
                store.reclassify_claim(cid, cc)
                store.publish_event("signal.systemic_flagged", {
                    "claim_id": cid,
                    "reason": "Detected by Signal Scouts pattern analysis",
                })
                flagged_ids.append(cid)
                logger.info(f"Signal Scouts: flagged {cid} as systemic")

    # Audit: log every scan
    store.audit("signal.scan", {
        "claims_scanned": report.get("claims_scanned", 0),
        "total_signals": report["summary"].get("total_signals", 0),
        "critical": report["summary"].get("critical", 0),
        "alerts": report["summary"].get("alerts", 0),
        "warnings": report["summary"].get("warnings", 0),
        "stale_signals": report["summary"].get("stale_signals", 0),
        "decayed_signals": report["summary"].get("decayed_signals", 0),
        "systemic_flagged": flagged_ids,
        "top_sources": [t["respondent"] for t in report.get("top_threats", [])],
    })

    return report


@app.get("/v1/signals/respondent/{respondent_name}")
async def get_respondent_signals(
    respondent_name: str,
    authorization: Optional[str] = Header(None),
):
    """Get all signals related to a specific respondent."""
    verify_api_key(authorization)
    claims = store.list_claims(respondent=respondent_name)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"No claims found for respondent: {respondent_name}"},
        )
    # Get full report but filter signals to this respondent
    all_claims = store.list_claims()
    report = run_signal_scouts(all_claims)
    resp_lower = respondent_name.lower()
    filtered_signals = [
        s for s in report["signals"]
        if resp_lower in s.get("respondent", "").lower()
    ]
    return {
        "respondent": respondent_name,
        "claims": len(claims),
        "total_claimed": round(sum(c.get("amount_claimed_usd", 0) for c in claims), 2),
        "signals": filtered_signals,
        "signal_count": len(filtered_signals),
    }


# ── Document Generation ──

@app.get("/v1/claims/{claim_id}/letter/{template}")
async def generate_claim_letter(
    claim_id: str,
    template: str,
    authorization: Optional[str] = Header(None),
):
    """
    Generate a PDF demand letter for a claim.

    Templates: initial, second, compliance
    Returns: application/pdf
    """
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Claim not found"},
        )

    try:
        from ghostledger_docs import generate_letter, list_templates
        pdf_bytes = generate_letter(claim, template=template)
    except ValueError as e:
        valid = [t["key"] for t in list_templates()]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_TEMPLATE", "message": str(e), "valid_templates": valid},
        )
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "MISSING_DEPENDENCY", "message": "reportlab not installed. Run: pip install reportlab"},
        )

    respondent = (claim.get("respondent_entity") or "platform").replace(" ", "_")
    filename = f"GhostLedger_{template}_{respondent}_{claim_id[:12]}.pdf"

    store.publish_event("doc.letter.generated", {
        "claim_id": claim_id,
        "template": template,
        "filename": filename,
    })
    store.audit("letter.generated", {
        "claim_id": claim_id,
        "template": template,
        "respondent": claim.get("respondent_entity", "Unknown"),
        "amount": claim.get("amount_claimed_usd", 0),
    }, actor="operator")
    logger.info(f"Generated {template} letter for {claim_id}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/v1/templates")
async def get_templates(
    authorization: Optional[str] = Header(None),
):
    """List available letter templates."""
    verify_api_key(authorization)
    try:
        from ghostledger_docs import list_templates
        return {"templates": list_templates()}
    except ImportError:
        return {"templates": [], "error": "ghostledger_docs module not available"}


# ── Claimant Portal ──

@app.get("/v1/portal/lookup")
async def portal_lookup(email: str):
    """
    Public endpoint for claimants to check their case status.
    No API key required — returns sanitized claim data (no internal fields).
    """
    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_EMAIL", "message": "Please provide a valid email address"},
        )

    claims = store.lookup_by_email(email)
    if not claims:
        return {"claims": [], "total": 0}

    # Sanitize: strip internal fields, add timeline
    sanitized = []
    for c in claims:
        # Get timeline events for this claim
        events = store.get_claim_events(c.get("claim_id", ""))

        safe = {
            "claim_id": c.get("claim_id"),
            "respondent_entity": c.get("respondent_entity"),
            "amount_claimed_usd": c.get("amount_claimed_usd", 0),
            "harm_type": c.get("harm_type"),
            "status": c.get("status"),
            "description": c.get("description"),
            "filed_at": c.get("filed_at"),
            "updated_at": c.get("updated_at"),
            "classification": {
                "value_band": c.get("classification", {}).get("value_band"),
                "recovery_path": c.get("classification", {}).get("recovery_path"),
                "dispute_type": c.get("classification", {}).get("dispute_type"),
            } if c.get("classification") else None,
            "_timeline": events,
        }
        sanitized.append(safe)

    return {"claims": sanitized, "total": len(sanitized)}


@app.get("/v1/intake/events")
async def list_events(
    topic: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List published events."""
    verify_api_key(authorization)
    events = store.list_events(topic=topic)
    return {
        "events": events,
        "total": len(events),
    }


@app.get("/v1/audit-log")
async def get_audit_log(
    action: Optional[str] = None,
    limit: int = 100,
    authorization: Optional[str] = Header(None),
):
    """
    Retrieve the immutable audit log. Supports filtering by action type.
    Actions: signal.scan, letter.generated, status.changed, claim.intake,
             claim.classified, handoff.initiated
    """
    verify_api_key(authorization)
    entries = store.get_audit_log(action=action, limit=min(limit, 500))
    return {
        "entries": entries,
        "total": len(entries),
        "filtered_by": action,
    }


@app.get("/v1/audit-log/export")
async def export_audit_log(
    format: str = "csv",
    action: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """
    Read-only export of the audit log as CSV or JSON.
    Includes export timestamp and SHA-256 checksum for integrity verification.
    Query params:
        format: 'csv' (default) or 'json'
        action: optional action filter
    """
    verify_api_key(authorization)
    entries = store.get_audit_log(action=action, limit=5000)
    export_timestamp = datetime.utcnow().isoformat() + "Z"

    if format.lower() == "json":
        # ── JSON export with metadata envelope ──
        export_payload = {
            "export_metadata": {
                "format": "json",
                "exported_at": export_timestamp,
                "total_entries": len(entries),
                "filter_applied": action,
                "source": "GhostLedger Audit Log",
            },
            "entries": entries,
        }
        raw_bytes = json.dumps(export_payload, indent=2, sort_keys=True).encode("utf-8")
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        export_payload["export_metadata"]["sha256_checksum"] = checksum
        final_bytes = json.dumps(export_payload, indent=2, sort_keys=True).encode("utf-8")
        filename = f"ghostledger_audit_{export_timestamp[:10].replace('-', '')}.json"
        store.audit("export.audit_log", {
            "format": "json",
            "entries_exported": len(entries),
            "filter": action,
            "checksum": checksum,
        }, actor="operator")
        return Response(
            content=final_bytes,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Export-Timestamp": export_timestamp,
                "X-Export-Checksum": checksum,
            },
        )
    else:
        # ── CSV export ──
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["audit_id", "timestamp", "action", "actor", "detail"])
        for e in entries:
            detail_str = json.dumps(e.get("detail", {})) if isinstance(e.get("detail"), dict) else str(e.get("detail", ""))
            writer.writerow([
                e.get("audit_id", ""),
                e.get("timestamp", ""),
                e.get("action", ""),
                e.get("actor", ""),
                detail_str,
            ])
        csv_content = output.getvalue()
        raw_bytes = csv_content.encode("utf-8")
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        # Append checksum footer
        csv_content += f"\n# Export: {export_timestamp} | Entries: {len(entries)} | SHA-256: {checksum}\n"
        final_bytes = csv_content.encode("utf-8")
        filename = f"ghostledger_audit_{export_timestamp[:10].replace('-', '')}.csv"
        store.audit("export.audit_log", {
            "format": "csv",
            "entries_exported": len(entries),
            "filter": action,
            "checksum": checksum,
        }, actor="operator")
        return Response(
            content=final_bytes,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Export-Timestamp": export_timestamp,
                "X-Export-Checksum": checksum,
            },
        )


@app.get("/v1/stats/trends")
async def get_trends(
    authorization: Optional[str] = Header(None),
):
    """
    Time-series analytics: claims filed per day, resolutions over time,
    average case age, and status flow breakdown.
    """
    verify_api_key(authorization)
    claims = store.list_claims()
    now = datetime.utcnow()

    # ── Claims filed per day (last 30 days) ──
    filed_per_day: Dict[str, int] = {}
    resolved_per_day: Dict[str, int] = {}
    for i in range(30):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        filed_per_day[day] = 0
        resolved_per_day[day] = 0

    # ── Status breakdown, age metrics ──
    status_counts: Dict[str, int] = {}
    respondent_amounts: Dict[str, float] = {}
    ages: List[float] = []
    value_band_amounts: Dict[str, float] = {}

    for c in claims:
        # Filed per day
        filed_date = c.get("filed_at", "")[:10]
        if filed_date in filed_per_day:
            filed_per_day[filed_date] += 1

        # Resolved per day
        if c.get("status") in ("resolved", "closed"):
            updated_date = c.get("updated_at", "")[:10]
            if updated_date in resolved_per_day:
                resolved_per_day[updated_date] += 1

        # Status counts
        st = c.get("status", "filed")
        status_counts[st] = status_counts.get(st, 0) + 1

        # Age calculation
        try:
            filed_dt = datetime.fromisoformat(c.get("filed_at", now.isoformat()))
            age_days = (now - filed_dt).days
            ages.append(age_days)
        except (ValueError, TypeError):
            pass

        # Respondent total amounts
        resp = c.get("respondent_entity", "Unknown")
        amt = c.get("amount_claimed_usd", 0)
        respondent_amounts[resp] = respondent_amounts.get(resp, 0) + amt

        # Value band amounts
        vb = c.get("classification", {}).get("value_band", "unclassified")
        value_band_amounts[vb] = value_band_amounts.get(vb, 0) + amt

    # Sort time series chronologically
    filed_series = [{"date": d, "count": filed_per_day[d]} for d in sorted(filed_per_day.keys())]
    resolved_series = [{"date": d, "count": resolved_per_day[d]} for d in sorted(resolved_per_day.keys())]

    # Top respondents by total amount
    top_by_amount = sorted(respondent_amounts.items(), key=lambda x: x[1], reverse=True)[:10]

    avg_age = round(sum(ages) / len(ages), 1) if ages else 0
    oldest_age = max(ages) if ages else 0

    return {
        "period": "last_30_days",
        "filed_per_day": filed_series,
        "resolved_per_day": resolved_series,
        "status_breakdown": status_counts,
        "top_respondents_by_amount": [{"respondent": r, "total_usd": round(a, 2)} for r, a in top_by_amount],
        "value_band_amounts": value_band_amounts,
        "age_metrics": {
            "average_days": avg_age,
            "oldest_days": oldest_age,
            "total_tracked": len(ages),
        },
        "total_claims": len(claims),
    }


# ============================================================================
# ILF — Independent Legal Fellowship Endpoints
# ============================================================================
# The ILF network connects escalated cases with independent legal professionals.
# This is a referral coordination system, not a law firm. GhostLedger does not
# provide legal advice or representation — it facilitates introductions between
# claimants and willing attorneys who may choose to assist independently.
# ============================================================================


class LawyerRegistration(BaseModel):
    """Registration payload for a new ILF lawyer."""
    full_name: str = Field(..., min_length=2, max_length=200)
    email: str = Field(..., min_length=5, max_length=254)
    bar_number: str = ""
    jurisdiction: str = "US-General"
    specializations: List[str] = []
    max_caseload: int = Field(default=10, ge=1, le=50)


class ReferralAction(BaseModel):
    """Accept or decline a referral."""
    action: str = Field(..., pattern="^(accepted|declined|engaged|completed)$")
    notes: str = ""


@app.get("/v1/ilf/stats")
async def ilf_stats(authorization: Optional[str] = Header(None)):
    """ILF network statistics overview."""
    verify_api_key(authorization)
    return store.get_ilf_stats()


@app.get("/v1/ilf/lawyers")
async def list_lawyers(
    status: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List all registered ILF lawyers."""
    verify_api_key(authorization)
    lawyers = store.list_lawyers(status_filter=status)
    # Enrich with current caseload
    for law in lawyers:
        law["current_caseload"] = store.get_lawyer_caseload(law["lawyer_id"])
    return {"lawyers": lawyers, "total": len(lawyers)}


@app.post("/v1/ilf/lawyers", status_code=status.HTTP_201_CREATED)
async def register_lawyer(
    req: LawyerRegistration,
    authorization: Optional[str] = Header(None),
):
    """Register a new lawyer in the ILF network."""
    verify_api_key(authorization)
    try:
        lid = store.register_lawyer(
            name=req.full_name,
            email=req.email,
            bar_number=req.bar_number,
            jurisdiction=req.jurisdiction,
            specializations=req.specializations,
            max_caseload=req.max_caseload,
        )
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "DUPLICATE_EMAIL", "message": "A lawyer with this email is already registered"},
            )
        raise
    store.audit("ilf.lawyer.registered", {
        "lawyer_id": lid,
        "name": req.full_name,
        "jurisdiction": req.jurisdiction,
        "specializations": req.specializations,
    }, actor="operator")
    logger.info(f"ILF: Registered lawyer {lid} ({req.full_name})")
    return {"lawyer_id": lid, "message": "Lawyer registered in ILF network"}


@app.patch("/v1/ilf/lawyers/{lawyer_id}/status")
async def update_lawyer_availability(
    lawyer_id: str,
    body: Dict[str, str],
    authorization: Optional[str] = Header(None),
):
    """Update a lawyer's availability status (active, inactive, on_leave)."""
    verify_api_key(authorization)
    lawyer = store.get_lawyer(lawyer_id)
    if not lawyer:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Lawyer not found"})
    new_status = body.get("status", "").lower()
    valid = {"active", "inactive", "on_leave"}
    if new_status not in valid:
        raise HTTPException(status_code=400, detail={"code": "INVALID_STATUS", "message": f"Must be one of: {', '.join(valid)}"})
    old_status = lawyer.get("status")
    store.update_lawyer_status(lawyer_id, new_status)
    store.audit("ilf.lawyer.status_changed", {
        "lawyer_id": lawyer_id,
        "name": lawyer["full_name"],
        "old_status": old_status,
        "new_status": new_status,
    }, actor="operator")
    return {"lawyer_id": lawyer_id, "status": new_status, "message": "Status updated"}


@app.post("/v1/ilf/referrals", status_code=status.HTTP_201_CREATED)
async def create_referral(
    body: Dict[str, str],
    authorization: Optional[str] = Header(None),
):
    """Create a case referral from a claim to a lawyer."""
    verify_api_key(authorization)
    claim_id = body.get("claim_id", "")
    lawyer_id = body.get("lawyer_id", "")
    claimant_consent = body.get("claimant_consent", False)
    if not claim_id or not lawyer_id:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "message": "claim_id and lawyer_id required"})
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Claim not found"})
    lawyer = store.get_lawyer(lawyer_id)
    if not lawyer:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Lawyer not found"})
    if lawyer.get("status") != "active":
        raise HTTPException(status_code=400, detail={"code": "LAWYER_UNAVAILABLE", "message": "Lawyer is not currently active"})
    # Check caseload
    current = store.get_lawyer_caseload(lawyer_id)
    if current >= lawyer.get("max_caseload", 10):
        raise HTTPException(status_code=400, detail={"code": "CASELOAD_FULL", "message": f"Lawyer has reached max caseload ({lawyer['max_caseload']})"})
    # Check for duplicate referral
    existing = store.list_referrals(lawyer_id=lawyer_id, claim_id=claim_id)
    active_existing = [r for r in existing if r["status"] in ("pending", "accepted")]
    if active_existing:
        raise HTTPException(status_code=409, detail={"code": "DUPLICATE_REFERRAL", "message": "An active referral already exists for this claim and lawyer"})
    # Validate consent
    if not claimant_consent:
        raise HTTPException(status_code=400, detail={"code": "CONSENT_REQUIRED", "message": "Claimant consent to share case details with an independent professional is required"})
    rid = store.create_referral(claim_id, lawyer_id)
    # Record consent timestamp
    conn = _get_db()
    conn.execute("UPDATE ilf_referrals SET claimant_consent_at = ?, consent_version = '1.0' WHERE referral_id = ?", (datetime.utcnow().isoformat(), rid))
    conn.commit()
    conn.close()
    classification = claim.get("classification", {})
    store.audit("handoff.initiated", {
        "referral_id": rid,
        "claim_id": claim_id,
        "lawyer_id": lawyer_id,
        "lawyer_name": lawyer["full_name"],
        "respondent": claim.get("respondent_entity", "Unknown"),
        "amount": claim.get("amount_claimed_usd", 0),
        "recovery_path": classification.get("recovery_path", "unknown"),
        "value_band": classification.get("value_band", "unknown"),
    }, actor="operator")
    store.publish_event("ilf.referral.created", {
        "referral_id": rid,
        "claim_id": claim_id,
        "lawyer_id": lawyer_id,
    })
    logger.info(f"ILF: Referral {rid} — {claim_id} → {lawyer['full_name']}")
    return {"referral_id": rid, "message": "Referral created"}


@app.get("/v1/ilf/referrals")
async def list_referrals(
    lawyer_id: Optional[str] = None,
    claim_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List referrals with optional filters."""
    verify_api_key(authorization)
    referrals = store.list_referrals(lawyer_id=lawyer_id, claim_id=claim_id, status_filter=status_filter)
    # Enrich with claim and lawyer context
    for ref in referrals:
        claim = store.get_claim(ref["claim_id"])
        if claim:
            ref["claim_summary"] = {
                "respondent": claim.get("respondent_entity", "Unknown"),
                "amount": claim.get("amount_claimed_usd", 0),
                "harm_type": claim.get("harm_type", "other"),
                "status": claim.get("status", "filed"),
                "value_band": claim.get("classification", {}).get("value_band", "unknown"),
                "recovery_path": claim.get("classification", {}).get("recovery_path", "unknown"),
            }
        lawyer = store.get_lawyer(ref["lawyer_id"])
        if lawyer:
            ref["lawyer_name"] = lawyer.get("full_name", "Unknown")
    return {"referrals": referrals, "total": len(referrals)}


@app.patch("/v1/ilf/referrals/{referral_id}")
async def update_referral(
    referral_id: str,
    req: ReferralAction,
    authorization: Optional[str] = Header(None),
):
    """Accept, decline, or complete a referral."""
    verify_api_key(authorization)
    referral = store.get_referral(referral_id)
    if not referral:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Referral not found"})
    old_status = referral["status"]
    # Validate transitions
    valid_transitions = {
        "pending": {"accepted", "declined"},
        "accepted": {"engaged", "declined"},
        "engaged": {"completed"},
    }
    allowed = valid_transitions.get(old_status, set())
    if req.action not in allowed:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_TRANSITION",
            "message": f"Cannot transition from '{old_status}' to '{req.action}'. Allowed: {', '.join(allowed) if allowed else 'none'}",
        })
    store.update_referral_status(referral_id, req.action, notes=req.notes)
    store.audit("ilf.referral.updated", {
        "referral_id": referral_id,
        "claim_id": referral["claim_id"],
        "lawyer_id": referral["lawyer_id"],
        "old_status": old_status,
        "new_status": req.action,
        "notes": req.notes,
    }, actor="operator")
    store.publish_event("ilf.referral.updated", {
        "referral_id": referral_id,
        "new_status": req.action,
    })
    logger.info(f"ILF: Referral {referral_id} — {old_status} → {req.action}")
    return {"referral_id": referral_id, "status": req.action, "message": f"Referral {req.action}"}


# ============================================================================
# RECOVERY TRACKING
# ============================================================================


@app.post("/v1/claims/{claim_id}/recovery")
async def record_recovery(
    claim_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Record a recovery event against a claim.
    Body: {"amount": 500.00, "method": "direct_refund", "notes": "Refund processed by Stripe"}
    Methods: direct_refund, chargeback, mediation_settlement, legal_settlement, platform_credit, partial_refund, other
    """
    verify_api_key(authorization)
    amount = body.get("amount", 0)
    method = str(body.get("method", "direct_refund")).strip()
    notes = str(body.get("notes", "")).strip()

    if not amount or float(amount) <= 0:
        raise HTTPException(status_code=400, detail="Recovery amount must be positive")

    valid_methods = {"direct_refund", "chargeback", "mediation_settlement", "legal_settlement", "platform_credit", "partial_refund", "other"}
    if method not in valid_methods:
        method = "other"

    result = store.record_recovery(claim_id, float(amount), method, "operator", notes)
    if not result:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Publish event and audit
    store.publish_event("recovery.recorded", {
        "claim_id": claim_id,
        "recovery_id": result["recovery_id"],
        "amount": result["amount_recovered"],
        "method": method,
    })
    store.audit("recovery.recorded", {
        "claim_id": claim_id,
        "recovery_id": result["recovery_id"],
        "amount": result["amount_recovered"],
        "method": method,
        "notes": notes,
    }, actor="operator")

    logger.info(f"Recovery recorded: {result['recovery_id']} — ${result['amount_recovered']} via {method} for claim {claim_id}")
    return result


@app.get("/v1/claims/{claim_id}/recoveries")
async def get_claim_recoveries(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get all recovery records for a specific claim."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    recoveries = store.get_claim_recoveries(claim_id)
    total_recovered = sum(r["amount_recovered"] for r in recoveries)
    claimed = claim.get("amount_claimed_usd", 0)

    return {
        "claim_id": claim_id,
        "amount_claimed": claimed,
        "total_recovered": round(total_recovered, 2),
        "recovery_pct": round((total_recovered / claimed * 100), 1) if claimed > 0 else 0.0,
        "recoveries": recoveries,
    }


@app.get("/v1/stats/recovery")
async def get_recovery_stats(
    authorization: Optional[str] = Header(None),
):
    """Aggregate recovery metrics across all claims."""
    verify_api_key(authorization)
    stats = store.get_recovery_stats()
    store.audit("recovery.stats_viewed", {
        "total_recovered": stats["total_recovered_usd"],
        "recovery_rate": stats["recovery_rate_usd"],
    }, actor="operator")
    return stats


# ============================================================================
# SLA ENGINE
# ============================================================================


@app.get("/v1/sla/status")
async def get_sla_status(
    authorization: Optional[str] = Header(None),
):
    """
    SLA compliance report for all active claims.
    Returns per-claim SLA status (on_track/at_risk/breached) and aggregate metrics.
    """
    verify_api_key(authorization)
    sla = store.check_sla()
    store.audit("sla.status_checked", {
        "total_active": sla["total_active"],
        "on_track": sla["on_track"],
        "at_risk": sla["at_risk"],
        "breached": sla["breached"],
        "compliance_rate": sla["compliance_rate"],
    }, actor="operator")
    return sla


@app.get("/v1/sla/rules")
async def get_sla_rules(
    authorization: Optional[str] = Header(None),
):
    """Return the current SLA rule configuration."""
    verify_api_key(authorization)
    return {
        "rules": {s: {"max_days": r["max_days"], "label": r["label"], "warn_pct": r["warn_pct"]} for s, r in SLA_RULES.items()},
    }


# ============================================================================
# SAVED VIEWS
# ============================================================================


@app.get("/v1/views")
async def list_saved_views(authorization: Optional[str] = Header(None)):
    """List all saved filter views."""
    verify_api_key(authorization)
    return {"views": store.list_saved_views()}


@app.post("/v1/views")
async def create_saved_view(body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """
    Save a filter preset.
    Body: {"name": "My View", "filters": {...}, "sort_by": "amount_claimed_usd", "sort_dir": "desc"}
    """
    verify_api_key(authorization)
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="View name is required")
    filters = body.get("filters", {})
    sort_by = str(body.get("sort_by", "filed_at"))
    sort_dir = str(body.get("sort_dir", "desc"))
    view = store.save_view(name, filters, sort_by, sort_dir)
    store.audit("view.saved", {"view_id": view["view_id"], "name": name}, actor="operator")
    return view


@app.delete("/v1/views/{view_id}")
async def delete_saved_view(view_id: str, authorization: Optional[str] = Header(None)):
    """Delete a saved view."""
    verify_api_key(authorization)
    if not store.delete_saved_view(view_id):
        raise HTTPException(status_code=404, detail="View not found")
    store.audit("view.deleted", {"view_id": view_id}, actor="operator")
    return {"deleted": True, "view_id": view_id}


# ============================================================================
# AUTOMATED ESCALATION ENGINE
# ============================================================================


@app.get("/v1/escalation/rules")
async def list_escalation_rules(authorization: Optional[str] = Header(None)):
    """Return all escalation rules and their status."""
    verify_api_key(authorization)
    return {
        "rules": [
            {
                "rule_id": r["rule_id"],
                "name": r["name"],
                "description": r["description"],
                "condition": r["condition"],
                "action": r["action"],
                "priority": r["priority"],
                "enabled": r.get("enabled", True),
            }
            for r in ESCALATION_RULES
        ],
        "total": len(ESCALATION_RULES),
        "active": sum(1 for r in ESCALATION_RULES if r.get("enabled", True)),
    }


@app.post("/v1/escalation/evaluate")
async def evaluate_escalation(authorization: Optional[str] = Header(None)):
    """
    Evaluate all active claims against escalation rules.
    Returns recommended actions without executing them.
    """
    verify_api_key(authorization)
    result = store.evaluate_escalation_rules()
    store.audit("escalation.evaluated", {
        "claims_evaluated": result["total_evaluated"],
        "recommendations": result["total_recommendations"],
        "by_priority": result["by_priority"],
    }, actor="system")
    return result


@app.post("/v1/escalation/execute")
async def execute_escalation(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Execute a specific escalation recommendation.
    Body: {"claim_id": "clm_xxx", "rule_id": "sla_breach_auto_escalate", "action": {"type": "status_change", "target_status": "under_review"}}
    """
    verify_api_key(authorization)
    claim_id = body.get("claim_id", "")
    rule_id = body.get("rule_id", "")
    action = body.get("action", {})

    if not claim_id or not rule_id:
        raise HTTPException(status_code=400, detail="claim_id and rule_id are required")

    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    old_status = claim.get("status", "filed")

    if action.get("type") == "status_change":
        new_status = action.get("target_status", "")
        allowed = VALID_STATUS_TRANSITIONS.get(old_status, set())
        if new_status not in allowed:
            raise HTTPException(status_code=400, detail={
                "code": "INVALID_TRANSITION",
                "message": f"Cannot transition from '{old_status}' to '{new_status}'",
            })

        store.update_claim_status(claim_id, new_status)
        store.publish_event("case.status.changed", {
            "claim_id": claim_id,
            "old_status": old_status,
            "new_status": new_status,
        })
        store.audit("escalation.executed", {
            "claim_id": claim_id,
            "rule_id": rule_id,
            "old_status": old_status,
            "new_status": new_status,
            "respondent": claim.get("respondent_entity", "Unknown"),
            "amount": claim.get("amount_claimed_usd", 0),
            "reason": f"[AUTO] Rule: {rule_id}",
        }, actor="escalation_engine")

        return {
            "executed": True,
            "claim_id": claim_id,
            "rule_id": rule_id,
            "old_status": old_status,
            "new_status": new_status,
        }

    elif action.get("type") == "flag":
        flag = action.get("flag", "flagged")
        store.audit("escalation.flagged", {
            "claim_id": claim_id,
            "rule_id": rule_id,
            "flag": flag,
            "respondent": claim.get("respondent_entity", "Unknown"),
        }, actor="escalation_engine")

        return {
            "executed": True,
            "claim_id": claim_id,
            "rule_id": rule_id,
            "flag": flag,
        }

    raise HTTPException(status_code=400, detail="Unknown action type")


@app.post("/v1/escalation/execute-all")
async def execute_all_escalations(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Execute all (or selected) pending escalation recommendations.
    Body: {"recommendation_ids": ["clm_xxx"]} or {} for all pending.
    """
    verify_api_key(authorization)
    result = store.evaluate_escalation_rules()
    recs = result.get("recommendations", [])

    selected_ids = body.get("recommendation_ids")
    if selected_ids:
        recs = [r for r in recs if r["claim_id"] in selected_ids]

    executed = []
    skipped = []

    for rec in recs:
        action = rec["action"]
        claim_id = rec["claim_id"]
        claim = store.get_claim(claim_id)
        if not claim:
            skipped.append({"claim_id": claim_id, "reason": "not_found"})
            continue

        old_status = claim.get("status", "filed")

        if action.get("type") == "status_change":
            new_status = action.get("target_status", "")
            allowed = VALID_STATUS_TRANSITIONS.get(old_status, set())
            if new_status not in allowed:
                skipped.append({"claim_id": claim_id, "reason": "invalid_transition"})
                continue

            store.update_claim_status(claim_id, new_status)
            store.publish_event("case.status.changed", {
                "claim_id": claim_id,
                "old_status": old_status,
                "new_status": new_status,
            })
            store.audit("escalation.executed", {
                "claim_id": claim_id,
                "rule_id": rec["rule_id"],
                "old_status": old_status,
                "new_status": new_status,
                "reason": f"[AUTO-BATCH] Rule: {rec['rule_id']}",
            }, actor="escalation_engine")
            executed.append({"claim_id": claim_id, "rule_id": rec["rule_id"], "new_status": new_status})

        elif action.get("type") == "flag":
            store.audit("escalation.flagged", {
                "claim_id": claim_id,
                "rule_id": rec["rule_id"],
                "flag": action.get("flag", "flagged"),
            }, actor="escalation_engine")
            executed.append({"claim_id": claim_id, "rule_id": rec["rule_id"], "flag": action.get("flag")})

    store.audit("escalation.batch_executed", {
        "total": len(recs),
        "executed": len(executed),
        "skipped": len(skipped),
    }, actor="escalation_engine")

    return {
        "executed": executed,
        "skipped": skipped,
        "summary": {"total": len(recs), "executed": len(executed), "skipped": len(skipped)},
    }


# ============================================================================
# BATCH IMPORT ENGINE
# ============================================================================


@app.post("/v1/import/batch")
async def batch_import(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Batch import claims from JSON array.
    Body: {
      "claims": [
        {"full_name": "...", "email": "...", "platform": "...", "amount": 500, "reason": "...", "contacted_support": "yes_no_resolution"},
        ...
      ],
      "skip_duplicates": true  // optional, default true
    }
    Each claim goes through: validation → harm classification → CCE → save.
    Returns per-row results with import summary.
    Max 100 claims per batch.
    """
    verify_api_key(authorization)
    raw_claims = body.get("claims", [])
    skip_dupes = body.get("skip_duplicates", True)

    if not raw_claims:
        raise HTTPException(status_code=400, detail="No claims provided in 'claims' array")
    if len(raw_claims) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 claims per batch. Got " + str(len(raw_claims)))

    # Pre-load existing claims for duplicate detection
    existing_claims = store.list_claims()
    existing_keys = set()
    for ec in existing_claims:
        # Dedup key: (claimant_email, respondent_entity, amount) normalized
        key = (
            (ec.get("claimant_email") or "").lower().strip(),
            (ec.get("respondent_entity") or "").lower().strip(),
            round(ec.get("amount_claimed_usd", 0), 2),
        )
        existing_keys.add(key)

    results = []
    imported = 0
    skipped = 0
    failed = 0
    import_id = f"imp_{uuid.uuid4().hex[:12]}"
    now = datetime.utcnow()

    for idx, raw in enumerate(raw_claims):
        row_num = idx + 1
        try:
            # Extract and validate required fields
            full_name = str(raw.get("full_name") or raw.get("name") or "").strip()
            email = str(raw.get("email") or raw.get("claimant_email") or raw.get("email_address") or raw.get("consumer_email") or "").strip()
            platform = str(raw.get("platform") or raw.get("platform_or_company") or raw.get("respondent") or raw.get("respondent_name") or raw.get("respondent_entity") or raw.get("company") or "").strip()
            amount = raw.get("amount") or raw.get("estimated_amount_usd") or raw.get("amount_claimed_usd") or raw.get("claimed_amount") or raw.get("claim_amount") or raw.get("amount_usd") or 0
            reason = str(raw.get("reason") or raw.get("platform_reason") or raw.get("description") or raw.get("claim_reason") or raw.get("narrative") or "").strip()
            contacted = str(raw.get("contacted_support") or "no_not_yet").strip()
            referral = str(raw.get("referral_source") or "other").strip()

            try:
                amount = round(float(amount), 2)
            except (ValueError, TypeError):
                amount = 0

            errors = []
            if not full_name:
                errors.append("full_name is required")
            if not email or "@" not in email:
                errors.append("valid email is required")
            if not platform:
                errors.append("platform/respondent is required")
            if amount <= 0:
                errors.append("amount must be positive")
            if not reason:
                errors.append("reason/description is required")

            if errors:
                results.append({"row": row_num, "result": "failed", "errors": errors})
                failed += 1
                continue

            # Normalize and classify
            harm_type = classify_harm_type(platform, reason)
            resp_norm = normalize_respondent(platform)

            # Duplicate detection (uses normalized respondent to match existing claims)
            dedup_key = (email.lower(), resp_norm["display_name"].lower(), amount)
            if skip_dupes and dedup_key in existing_keys:
                results.append({"row": row_num, "result": "skipped", "reason": "Duplicate (same email, respondent, amount)"})
                skipped += 1
                continue
            canonical_name = normalize_claimant_name(full_name)

            claim_data = {
                "vertical": "platform_dispute",
                "status": CaseStatus.FILED.value,
                "claimant_name": canonical_name,
                "claimant_email": email,
                "respondent_entity": resp_norm["display_name"],
                "respondent_normalized_id": resp_norm["normalized_id"],
                "respondent_original": resp_norm["original"],
                "harm_type": harm_type.value,
                "amount_claimed_usd": amount,
                "description": reason,
                "contacted_support": normalize_support_status(contacted).value,
                "referral_source": normalize_referral(referral).value,
                "execution_score": 0.0,
                "import_id": import_id,
                "import_row": row_num,
                "evidence": [],
                "escalation_history": [],
            }

            # Run CCE classification
            classified = run_cce(claim_data)
            claim_data.update(classified)

            # Save
            claim_id = store.save_claim(claim_data)

            # Publish events
            store.publish_event("claim.intake", {
                "claim_id": claim_id,
                "respondent": resp_norm["display_name"],
                "amount": amount,
                "source": "batch_import",
                "import_id": import_id,
            })

            # Track for dedup within same batch
            existing_keys.add(dedup_key)

            results.append({
                "row": row_num,
                "result": "imported",
                "claim_id": claim_id,
                "respondent": resp_norm["display_name"],
                "amount": amount,
            })
            imported += 1

        except Exception as e:
            results.append({"row": row_num, "result": "failed", "errors": [str(e)]})
            failed += 1

    # Audit the import
    store.audit("batch.import", {
        "import_id": import_id,
        "total_rows": len(raw_claims),
        "imported": imported,
        "skipped": skipped,
        "failed": failed,
    }, actor="operator")

    logger.info(f"Batch import {import_id}: {imported} imported, {skipped} skipped, {failed} failed out of {len(raw_claims)} rows")

    return {
        "import_id": import_id,
        "results": results,
        "summary": {
            "total": len(raw_claims),
            "imported": imported,
            "skipped": skipped,
            "failed": failed,
        },
    }


@app.post("/v1/import/csv")
async def csv_import(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Import claims from CSV text content.
    Body: {"csv_content": "full_name,email,platform,amount,reason\\n...", "skip_duplicates": true}
    Expected columns: full_name, email, platform, amount, reason, contacted_support (optional)
    """
    verify_api_key(authorization)
    csv_content = body.get("csv_content", "").strip()
    if not csv_content:
        raise HTTPException(status_code=400, detail="csv_content is required")

    import csv as csv_module
    import io

    reader = csv_module.DictReader(io.StringIO(csv_content))
    claims = []
    for row in reader:
        # Map common CSV column name variants
        claim = {
            "full_name": row.get("full_name") or row.get("name") or row.get("claimant_name") or row.get("claimant") or "",
            "email": row.get("email") or row.get("claimant_email") or "",
            "platform": row.get("platform") or row.get("platform_or_company") or row.get("respondent") or row.get("respondent_entity") or "",
            "amount": row.get("amount") or row.get("estimated_amount_usd") or row.get("amount_claimed_usd") or "0",
            "reason": row.get("reason") or row.get("platform_reason") or row.get("description") or "",
            "contacted_support": row.get("contacted_support") or "no_not_yet",
            "referral_source": row.get("referral_source") or "other",
        }
        claims.append(claim)

    if not claims:
        raise HTTPException(status_code=400, detail="No valid rows found in CSV")
    if len(claims) > 100:
        raise HTTPException(status_code=400, detail=f"Maximum 100 rows per import. CSV has {len(claims)} rows")

    # Delegate to batch import logic
    body_for_batch = {"claims": claims, "skip_duplicates": body.get("skip_duplicates", True)}
    return await batch_import(body_for_batch, authorization)


# ============================================================================
# GOOGLE APPS SCRIPT (for the live Google Form)
# ============================================================================
#
# Paste this into your Google Form's Apps Script editor:
#
# function onFormSubmit(e) {
#   var responses = e.namedValues;
#   var payload = {
#     full_name: responses["Full Name"][0],
#     email: responses["Email Address"][0],
#     phone: responses["Phone Number (optional)"][0] || null,
#     platform_or_company: responses["Platform or Company Owing You Money"][0],
#     estimated_amount_usd: parseFloat(
#       responses["Estimated Amount Owed ($)"][0].replace(/[^0-9.]/g, "")
#     ),
#     last_expected_payment: responses["Date of Last Expected Payment"][0],
#     platform_reason:
#       responses["What reason did the platform give (if any)?"][0],
#     contacted_support:
#       responses["Have you already contacted support?"][0],
#     referral_source:
#       responses["How did you hear about GhostLedger?"][0] || "other",
#     authorization: true  // checkbox was required to submit
#   };
#
#   var options = {
#     method: "post",
#     contentType: "application/json",
#     headers: {
#       "Authorization": "Bearer " + PropertiesService
#         .getScriptProperties().getProperty("GL_API_KEY")
#     },
#     payload: JSON.stringify(payload),
#     muteHttpExceptions: true
#   };
#
#   var response = UrlFetchApp.fetch(
#     "https://api.ghostledger.io/v1/intake/submissions",
#     options
#   );
#
#   Logger.log("GhostLedger response: " + response.getContentText());
# }
#
# Setup:
# 1. Open Google Form > three dots > Script Editor
# 2. Paste this function
# 3. Go to Project Settings > Script Properties
# 4. Add GL_API_KEY = your intake API key
# 5. Go to Triggers > Add Trigger > onFormSubmit > On form submit
# ============================================================================


# ============================================================================
# BULK OPERATIONS
# ============================================================================

@app.post("/v1/claims/bulk/status")
async def bulk_status_change(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Batch status change with transition validation per claim.
    Body: {"claim_ids": ["clm_xxx", ...], "status": "under_review", "reason": "Batch review"}
    Returns per-claim results: success or failure with details.
    """
    verify_api_key(authorization)
    claim_ids = body.get("claim_ids", [])
    new_status = str(body.get("status", "")).lower()
    reason = str(body.get("reason", "")).strip()

    if not claim_ids:
        raise HTTPException(status_code=400, detail={"code": "NO_CLAIMS", "message": "No claim IDs provided"})
    if not new_status:
        raise HTTPException(status_code=400, detail={"code": "NO_STATUS", "message": "Target status required"})
    if not reason:
        raise HTTPException(status_code=400, detail={"code": "NO_REASON", "message": "Reason required for bulk operations"})

    valid_statuses = {s.value for s in CaseStatus}
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail={"code": "INVALID_STATUS", "message": f"Must be one of: {', '.join(valid_statuses)}"})

    results = []
    success_count = 0
    skip_count = 0
    fail_count = 0

    for cid in claim_ids[:50]:  # Cap at 50 per batch
        claim = store.get_claim(cid)
        if not claim:
            results.append({"claim_id": cid, "result": "error", "message": "Claim not found"})
            fail_count += 1
            continue

        old_status = claim.get("status", "filed")
        if old_status == new_status:
            results.append({"claim_id": cid, "result": "skipped", "message": "Already in target status"})
            skip_count += 1
            continue

        # Validate transition
        allowed = VALID_STATUS_TRANSITIONS.get(old_status, set())
        if new_status not in allowed:
            results.append({
                "claim_id": cid,
                "result": "error",
                "message": f"Invalid transition: {old_status} → {new_status}. Allowed: {', '.join(sorted(allowed))}",
            })
            fail_count += 1
            continue

        store.update_claim_status(cid, new_status)
        store.publish_event("case.status.changed", {
            "claim_id": cid,
            "old_status": old_status,
            "new_status": new_status,
        })
        store.audit("status.changed", {
            "claim_id": cid,
            "old_status": old_status,
            "new_status": new_status,
            "respondent": claim.get("respondent_entity", "Unknown"),
            "reason": f"[BATCH] {reason}",
        }, actor="operator")

        # Handoff tracking
        handoff_stages = {"escalated", "in_resolution"}
        if new_status in handoff_stages and old_status not in handoff_stages:
            classification = claim.get("classification", {})
            store.audit("handoff.initiated", {
                "claim_id": cid,
                "respondent": claim.get("respondent_entity", "Unknown"),
                "amount": claim.get("amount_claimed_usd", 0),
                "from_status": old_status,
                "to_status": new_status,
                "recovery_path": classification.get("recovery_path", "unknown"),
                "value_band": classification.get("value_band", "unknown"),
                "reason": f"[BATCH] {reason}",
            }, actor="operator")

        results.append({"claim_id": cid, "result": "success", "old_status": old_status, "new_status": new_status})
        success_count += 1

    store.audit("bulk.status_change", {
        "target_status": new_status,
        "total_requested": len(claim_ids),
        "success": success_count,
        "skipped": skip_count,
        "failed": fail_count,
        "reason": reason,
    }, actor="operator")

    return {
        "results": results,
        "summary": {
            "total": len(claim_ids),
            "success": success_count,
            "skipped": skip_count,
            "failed": fail_count,
        },
    }


# ============================================================================
# SYSTEM HEALTH & DATA INTEGRITY
# ============================================================================

@app.get("/v1/health/integrity")
async def check_system_integrity(
    authorization: Optional[str] = Header(None),
):
    """
    Comprehensive system health and data integrity check.
    Runs 8 automated checks: audit coverage, classification coverage,
    field completeness, referential integrity, SLA adherence,
    consent compliance, audit ordering, and database size.
    Returns per-check pass/warn/fail with overall health score.
    """
    verify_api_key(authorization)
    result = store.check_integrity()
    store.audit("system.integrity_check", {
        "overall": result["overall"],
        "score": result["score"],
        "pass": result["summary"]["pass"],
        "warn": result["summary"]["warn"],
        "fail": result["summary"]["fail"],
    }, actor="operator")
    return result


# ============================================================================
# RESPONDENT INTELLIGENCE
# ============================================================================

@app.get("/v1/respondents")
async def list_respondent_profiles(
    authorization: Optional[str] = Header(None),
):
    """
    Respondent Intelligence: aggregated dossier-style profiles for every
    respondent entity in the system. Each profile includes claim volume,
    amounts, resolution rate, risk score, harm-type distribution, and
    associated claims. Sorted by risk score descending.
    """
    verify_api_key(authorization)
    profiles = store.get_respondent_profiles()

    # Summary stats
    total_respondents = len(profiles)
    total_claims_across = sum(p["total_claims"] for p in profiles)
    critical_count = sum(1 for p in profiles if p["risk_level"] == "critical")
    high_count = sum(1 for p in profiles if p["risk_level"] == "high")

    store.audit("intel.respondents.viewed", {
        "total_respondents": total_respondents,
        "critical": critical_count,
        "high": high_count,
    }, actor="operator")

    return {
        "profiles": profiles,
        "summary": {
            "total_respondents": total_respondents,
            "total_claims": total_claims_across,
            "critical_risk": critical_count,
            "high_risk": high_count,
        },
    }


@app.get("/v1/respondents/{entity_name}")
async def get_respondent_profile(
    entity_name: str,
    authorization: Optional[str] = Header(None),
):
    """
    Single respondent deep-dive dossier. Returns full profile with
    all associated claims, status breakdown, harm types, and timeline.
    """
    verify_api_key(authorization)
    # URL-decode the entity name (spaces come as %20 or +)
    import urllib.parse
    decoded_name = urllib.parse.unquote(entity_name)
    profile = store.get_respondent_detail(decoded_name)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"No claims found for respondent: {decoded_name}"},
        )
    return {"profile": profile}


@app.get("/v1/activity")
async def get_activity_feed(
    limit: int = 30,
    authorization: Optional[str] = Header(None),
):
    """
    Activity feed aggregating recent system events across all entity types.
    Combines audit log, events, and referral changes into a unified timeline.
    Each entry includes: type, title, detail, icon hint, timestamp, and
    optional entity reference (claim_id, lawyer_id, referral_id) for navigation.
    """
    verify_api_key(authorization)
    feed = []

    # ── Pull from audit log (most comprehensive) ──
    entries = store.get_audit_log(limit=min(limit * 2, 200))
    for e in entries:
        detail = e.get("detail", {})
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except Exception:
                detail = {}

        action = e.get("action", "unknown")
        ts = e.get("timestamp", "")
        actor = e.get("actor", "system")

        # Map action to human-readable feed item
        item = {"action": action, "timestamp": ts, "actor": actor, "ref": {}}

        if action == "claim.intake":
            item["title"] = "New claim filed"
            item["detail"] = f"{detail.get('respondent', 'Unknown')} — ${detail.get('amount', 0):,.0f}"
            item["icon"] = "intake"
            item["ref"] = {"type": "claim", "id": detail.get("claim_id", "")}
        elif action == "status.changed":
            old_s = detail.get("old_status", "?")
            new_s = detail.get("new_status", "?")
            item["title"] = f"Status changed: {old_s} → {new_s}"
            item["detail"] = detail.get("respondent", "")
            item["icon"] = "status"
            item["ref"] = {"type": "claim", "id": detail.get("claim_id", "")}
        elif action == "claim.classified":
            item["title"] = "Claim classified"
            item["detail"] = f"{detail.get('value_band', '')} · {detail.get('dispute_type', '')} · {detail.get('recovery_path', '')}"
            item["icon"] = "classify"
            item["ref"] = {"type": "claim", "id": detail.get("claim_id", "")}
        elif action == "handoff.initiated":
            item["title"] = "Handoff initiated → ILF referral queue"
            item["detail"] = f"{detail.get('respondent', '')} ({detail.get('value_band', '')})"
            item["icon"] = "handoff"
            item["ref"] = {"type": "claim", "id": detail.get("claim_id", "")}
        elif action == "letter.generated":
            tpl = detail.get("template", "unknown")
            item["title"] = f"Letter generated ({tpl})"
            item["detail"] = detail.get("respondent", "")
            item["icon"] = "letter"
            item["ref"] = {"type": "claim", "id": detail.get("claim_id", "")}
        elif action == "signal.scan":
            item["title"] = "Signal scan completed"
            item["detail"] = f"{detail.get('total_signals', 0)} signals detected"
            item["icon"] = "scan"
        elif action == "ilf.lawyer.registered":
            item["title"] = "Professional registered"
            name = detail.get("full_name", "")
            lid = detail.get("lawyer_id", "")
            if name and name != "Unknown":
                item["detail"] = name
            elif lid:
                item["detail"] = f"{lid[:4]}****{lid[-4:]} (verification pending)"
            else:
                item["detail"] = "New professional (verification pending)"
            item["icon"] = "professional"
            item["ref"] = {"type": "professional", "id": lid}
        elif action == "ilf.lawyer.status_changed":
            item["title"] = f"Professional {detail.get('new_status', 'updated')}"
            lid = detail.get("lawyer_id", "")
            item["detail"] = f"{lid[:4]}****{lid[-4:]}" if lid else ""
            item["icon"] = "professional"
            item["ref"] = {"type": "professional", "id": lid}
        elif action == "ilf.referral.updated":
            item["title"] = f"Referral {detail.get('new_status', 'updated')}"
            item["detail"] = f"Claim: {detail.get('claim_id', '')} → ILF network"
            item["icon"] = "referral"
            item["ref"] = {"type": "referral", "id": detail.get("referral_id", "")}
        elif action == "case.note.added":
            item["title"] = "Note added"
            item["detail"] = f"{detail.get('respondent', '')} ({detail.get('content_length', 0)} chars)"
            item["icon"] = "note"
            item["ref"] = {"type": "claim", "id": detail.get("claim_id", "")}
        elif action.startswith("export."):
            item["title"] = f"Export: {action.split('.')[-1]}"
            item["detail"] = f"Format: {detail.get('format', 'unknown')}"
            item["icon"] = "export"
        else:
            item["title"] = action.replace(".", " ").replace("_", " ").title()
            item["detail"] = str(detail)[:100] if detail else ""
            item["icon"] = "system"

        feed.append(item)

    # Sort by timestamp descending and limit
    feed.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    feed = feed[:limit]

    # Add sequence indicators for same-timestamp groups
    # Groups events that share the same second, adds seq "1/3", "2/3", etc.
    from collections import Counter
    ts_seconds = [f.get("timestamp", "")[:19] for f in feed]
    ts_counts = Counter(ts_seconds)
    ts_seen: Dict[str, int] = {}
    for item in feed:
        ts_key = item.get("timestamp", "")[:19]
        if ts_counts.get(ts_key, 0) > 1:
            ts_seen[ts_key] = ts_seen.get(ts_key, 0) + 1
            item["seq"] = f"{ts_seen[ts_key]}/{ts_counts[ts_key]}"

    return {"feed": feed, "total": len(feed)}


# ============================================================================
# OUTREACH TEMPLATES & COMMUNICATION ENGINE
# ============================================================================

@app.get("/v1/outreach/templates")
async def list_outreach_templates(
    authorization: Optional[str] = Header(None),
):
    """List all outreach templates."""
    verify_api_key(authorization)
    templates = store.list_templates()
    categories = {}
    for t in templates:
        cat = t["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(t)
    return {"templates": templates, "total": len(templates), "categories": categories}


@app.get("/v1/outreach/templates/{template_id}")
async def get_outreach_template(
    template_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get a single template by ID."""
    verify_api_key(authorization)
    tpl = store.get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return tpl


@app.post("/v1/outreach/templates")
async def save_outreach_template(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """Create or update an outreach template."""
    verify_api_key(authorization)
    template_id = body.get("template_id") or f"tpl_{uuid.uuid4().hex[:12]}"
    name = body.get("name", "").strip()
    category = body.get("category", "demand_letter").strip()
    subject = body.get("subject", "").strip()
    tpl_body = body.get("body", "").strip()
    variables = body.get("variables", [])

    if not name:
        raise HTTPException(status_code=400, detail="Template name is required")
    if not tpl_body:
        raise HTTPException(status_code=400, detail="Template body is required")

    result = store.save_template(template_id, name, category, subject, tpl_body, variables)
    store.audit("outreach.template.saved", {"template_id": template_id, "name": name, "category": category}, actor="operator")
    return result


@app.delete("/v1/outreach/templates/{template_id}")
async def delete_outreach_template(
    template_id: str,
    authorization: Optional[str] = Header(None),
):
    """Delete an outreach template."""
    verify_api_key(authorization)
    if not store.delete_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found")
    store.audit("outreach.template.deleted", {"template_id": template_id}, actor="operator")
    return {"deleted": True, "template_id": template_id}


@app.post("/v1/outreach/render")
async def render_outreach(
    body: Dict[str, str],
    authorization: Optional[str] = Header(None),
):
    """Render a template with claim data. Body: {"template_id": "...", "claim_id": "..."}"""
    verify_api_key(authorization)
    template_id = body.get("template_id", "")
    claim_id = body.get("claim_id", "")
    if not template_id or not claim_id:
        raise HTTPException(status_code=400, detail="template_id and claim_id are required")
    result = store.render_template(template_id, claim_id)
    if not result:
        raise HTTPException(status_code=404, detail="Template or claim not found")
    return result


@app.post("/v1/outreach/send")
async def send_outreach(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Log an outreach communication (drafted or sent).
    Body: {"claim_id": "...", "template_id": "...", "channel": "email", "recipient": "...", "subject": "...", "body": "...", "status": "sent"}
    """
    verify_api_key(authorization)
    claim_id = body.get("claim_id", "").strip()
    template_id = body.get("template_id")
    channel = body.get("channel", "email").strip()
    recipient = body.get("recipient", "").strip()
    subject = body.get("subject", "").strip()
    out_body = body.get("body", "").strip()
    out_status = body.get("status", "drafted").strip()

    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    if not out_body:
        raise HTTPException(status_code=400, detail="body content is required")

    outreach_id = store.log_outreach(claim_id, template_id, channel, recipient, subject, out_body, out_status)
    store.publish_event("outreach.logged", {
        "outreach_id": outreach_id,
        "claim_id": claim_id,
        "channel": channel,
        "status": out_status,
    })
    store.audit("outreach.logged", {
        "outreach_id": outreach_id,
        "claim_id": claim_id,
        "template_id": template_id,
        "channel": channel,
        "recipient": recipient,
        "status": out_status,
    }, actor="operator")
    return {"outreach_id": outreach_id, "status": out_status, "message": "Outreach logged"}


@app.get("/v1/claims/{claim_id}/outreach")
async def get_claim_outreach(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get all outreach communications for a claim."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    outreach = store.get_claim_outreach(claim_id)
    return {"claim_id": claim_id, "outreach": outreach, "total": len(outreach)}


@app.patch("/v1/outreach/{outreach_id}/status")
async def update_outreach_status(
    outreach_id: str,
    body: Dict[str, str],
    authorization: Optional[str] = Header(None),
):
    """Update outreach status. Body: {"status": "sent"}"""
    verify_api_key(authorization)
    new_status = body.get("status", "").strip()
    if new_status not in ("drafted", "sent", "responded", "no_response", "bounced"):
        raise HTTPException(status_code=400, detail="Invalid status. Use: drafted, sent, responded, no_response, bounced")
    if not store.update_outreach_status(outreach_id, new_status):
        raise HTTPException(status_code=404, detail="Outreach record not found")
    store.audit("outreach.status.updated", {"outreach_id": outreach_id, "new_status": new_status}, actor="operator")
    return {"outreach_id": outreach_id, "status": new_status}


@app.get("/v1/outreach/stats")
async def get_outreach_stats(
    authorization: Optional[str] = Header(None),
):
    """Get outreach communication statistics."""
    verify_api_key(authorization)
    return store.get_outreach_stats()


# ============================================================================
# REPORTING & EXPORT ENGINE
# ============================================================================

@app.get("/v1/reports/executive")
async def executive_report(
    authorization: Optional[str] = Header(None),
):
    """
    Generate a comprehensive executive summary report with all key metrics,
    trends, risk highlights, and operational KPIs.
    """
    verify_api_key(authorization)
    now = datetime.utcnow()
    now_str = now.isoformat() + "Z"

    # Pull all data sources
    stats = store.get_stats()
    sla_data = store.check_sla()
    recovery_stats = store.get_recovery_stats()
    respondent_profiles = store.get_respondent_profiles()
    outreach_stats = store.get_outreach_stats()
    escalation_data = store.evaluate_escalation_rules()

    # Claims breakdown
    claims = store.list_claims()
    total_claims = len(claims)

    # Age distribution
    age_buckets = {"0-7d": 0, "8-14d": 0, "15-30d": 0, "31-60d": 0, "60d+": 0}
    for c in claims:
        filed = c.get("filed_at", "")
        if filed:
            try:
                d = datetime.fromisoformat(filed.replace("Z", "+00:00")).replace(tzinfo=None)
                age = (now - d).days
                if age <= 7: age_buckets["0-7d"] += 1
                elif age <= 14: age_buckets["8-14d"] += 1
                elif age <= 30: age_buckets["15-30d"] += 1
                elif age <= 60: age_buckets["31-60d"] += 1
                else: age_buckets["60d+"] += 1
            except (ValueError, TypeError):
                pass

    # Status distribution
    status_dist = {}
    for c in claims:
        st = c.get("status", "filed")
        status_dist[st] = status_dist.get(st, 0) + 1

    # Value distribution
    value_dist = {"under_100": 0, "100_500": 0, "500_1k": 0, "1k_5k": 0, "5k_10k": 0, "10k_plus": 0}
    for c in claims:
        amt = c.get("amount_claimed_usd", 0)
        if amt < 100: value_dist["under_100"] += 1
        elif amt < 500: value_dist["100_500"] += 1
        elif amt < 1000: value_dist["500_1k"] += 1
        elif amt < 5000: value_dist["1k_5k"] += 1
        elif amt < 10000: value_dist["5k_10k"] += 1
        else: value_dist["10k_plus"] += 1

    # Top respondents by risk
    top_risk = sorted(respondent_profiles, key=lambda p: p["risk_score"], reverse=True)[:5]
    top_risk_summary = [
        {
            "entity": p["entity"],
            "risk_score": p["risk_score"],
            "risk_level": p["risk_level"],
            "total_claims": p["total_claims"],
            "total_amount": p["total_amount"],
            "resolution_rate": p["resolution_rate"],
        }
        for p in top_risk
    ]

    # SLA summary
    sla_summary = {
        "total_active": sla_data.get("total_active", 0),
        "on_track": sla_data.get("on_track", 0),
        "at_risk": sla_data.get("at_risk", 0),
        "breached": sla_data.get("breached", 0),
        "compliance_rate": sla_data.get("compliance_rate", 100),
    }

    # Recovery summary
    rec_summary = {
        "total_recovered": recovery_stats.get("total_recovered", 0),
        "total_claimed": recovery_stats.get("total_claimed", 0),
        "recovery_rate": recovery_stats.get("recovery_rate_usd", 0),
        "claims_with_recovery": recovery_stats.get("claims_with_recovery", 0),
        "by_method": recovery_stats.get("by_method", {}),
    }

    # Escalation summary
    esc_recommendations = escalation_data.get("recommendations", [])
    esc_summary = {
        "total_recommendations": len(esc_recommendations),
        "critical": sum(1 for r in esc_recommendations if r.get("priority") == "critical"),
        "high": sum(1 for r in esc_recommendations if r.get("priority") == "high"),
        "medium": sum(1 for r in esc_recommendations if r.get("priority") == "medium"),
    }

    # Outreach summary
    out_summary = {
        "total": outreach_stats.get("total", 0),
        "sent": outreach_stats.get("sent", 0),
        "drafted": outreach_stats.get("drafted", 0),
    }

    return {
        "report_type": "executive_summary",
        "generated_at": now_str,
        "period": "all_time",
        "overview": {
            "total_claims": total_claims,
            "total_claimed_usd": stats.get("total_claimed_usd", 0),
            "active_claims": stats.get("active", 0),
            "resolved_claims": stats.get("resolved", 0),
            "resolution_rate": stats.get("resolution_rate", 0),
            "total_respondents": len(respondent_profiles),
        },
        "status_distribution": status_dist,
        "age_distribution": age_buckets,
        "value_distribution": value_dist,
        "sla_compliance": sla_summary,
        "recovery_performance": rec_summary,
        "escalation_status": esc_summary,
        "outreach_activity": out_summary,
        "top_risk_respondents": top_risk_summary,
        "respondent_count_by_risk": {
            "critical": sum(1 for p in respondent_profiles if p["risk_level"] == "critical"),
            "high": sum(1 for p in respondent_profiles if p["risk_level"] == "high"),
            "medium": sum(1 for p in respondent_profiles if p["risk_level"] == "medium"),
            "low": sum(1 for p in respondent_profiles if p["risk_level"] == "low"),
        },
    }


@app.get("/v1/reports/respondent-accountability")
async def respondent_accountability_report(
    authorization: Optional[str] = Header(None),
):
    """Per-respondent accountability scorecards with compliance grades."""
    verify_api_key(authorization)
    now = datetime.utcnow()
    profiles = store.get_respondent_profiles()
    sla_data = store.check_sla()
    recovery_stats = store.get_recovery_stats()

    # Build SLA compliance per respondent
    sla_by_respondent = {}
    for item in sla_data.get("claims", []):
        resp = item.get("respondent", "Unknown")
        if resp not in sla_by_respondent:
            sla_by_respondent[resp] = {"total": 0, "on_track": 0, "at_risk": 0, "breached": 0}
        sla_by_respondent[resp]["total"] += 1
        sla_by_respondent[resp][item.get("sla_status", "on_track")] += 1

    # Recovery per respondent
    rec_by_respondent = {}
    for r in recovery_stats.get("by_respondent", []):
        rec_by_respondent[r["respondent"]] = {
            "recovered": r.get("total_recovered", 0),
            "claimed": r.get("total_claimed", 0),
            "rate": r.get("recovery_rate", 0),
        }

    # Outreach per respondent
    conn = _get_db()
    outreach_by_resp = {}
    for row in conn.execute("""
        SELECT c.data, COUNT(o.outreach_id) as cnt
        FROM outreach_log o
        JOIN claims c ON o.claim_id = json_extract(c.data, '$.claim_id')
        GROUP BY json_extract(c.data, '$.respondent_entity')
    """).fetchall():
        try:
            claim_data = json.loads(row["data"])
            resp = claim_data.get("respondent_entity", "Unknown")
            outreach_by_resp[resp] = row["cnt"]
        except (json.JSONDecodeError, TypeError):
            pass
    conn.close()

    scorecards = []
    for p in profiles:
        entity = p["entity"]
        total = p["total_claims"]
        resolved = p["resolved_claims"]
        res_rate = p["resolution_rate"]

        # SLA compliance rate for this respondent
        sla_info = sla_by_respondent.get(entity, {})
        sla_total = sla_info.get("total", 0)
        sla_compliant = sla_info.get("on_track", 0) + sla_info.get("at_risk", 0)
        sla_rate = round((sla_compliant / sla_total * 100), 1) if sla_total > 0 else 100.0

        # Recovery rate for this respondent
        rec_info = rec_by_respondent.get(entity, {})
        rec_rate = rec_info.get("rate", 0)

        # Outreach volume
        outreach_count = outreach_by_resp.get(entity, 0)

        # Composite compliance grade (A-F)
        # Factors: resolution rate (40%), SLA compliance (30%), recovery rate (20%), responsiveness (10%)
        score = (res_rate * 0.4) + (sla_rate * 0.3) + (rec_rate * 0.2) + (min(outreach_count * 10, 100) * 0.1 if total > 0 else 50 * 0.1)
        if score >= 90: grade = "A"
        elif score >= 75: grade = "B"
        elif score >= 60: grade = "C"
        elif score >= 40: grade = "D"
        else: grade = "F"

        scorecards.append({
            "entity": entity,
            "grade": grade,
            "composite_score": round(score, 1),
            "total_claims": total,
            "active_claims": p["active_claims"],
            "resolved_claims": resolved,
            "total_amount": p["total_amount"],
            "resolution_rate": res_rate,
            "sla_compliance_rate": sla_rate,
            "sla_breached": sla_info.get("breached", 0),
            "recovery_rate": rec_rate,
            "outreach_count": outreach_count,
            "risk_score": p["risk_score"],
            "risk_level": p["risk_level"],
            "avg_age_days": p["avg_age_days"],
            "top_harm_type": p["top_harm_type"],
            "first_claim": p["first_claim"],
            "last_claim": p["last_claim"],
        })

    scorecards.sort(key=lambda s: s["composite_score"])  # Worst first

    return {
        "report_type": "respondent_accountability",
        "generated_at": now.isoformat() + "Z",
        "total_respondents": len(scorecards),
        "grade_distribution": {
            g: sum(1 for s in scorecards if s["grade"] == g)
            for g in ["A", "B", "C", "D", "F"]
        },
        "scorecards": scorecards,
    }


@app.get("/v1/reports/export/claims")
async def export_claims_csv(
    format: str = "csv",
    authorization: Optional[str] = Header(None),
):
    """Export all claims data as CSV or JSON for external analysis."""
    verify_api_key(authorization)
    claims = store.list_claims()

    if format == "json":
        return {"claims": claims, "total": len(claims), "exported_at": datetime.utcnow().isoformat() + "Z"}

    # Build CSV
    if not claims:
        return Response(content="No claims to export", media_type="text/plain")

    headers = [
        "claim_id", "status", "claimant_name", "claimant_email",
        "respondent_entity", "amount_claimed_usd", "harm_type",
        "filed_at", "value_band", "dispute_type", "recovery_path",
        "sla_status", "outreach_count"
    ]
    lines = [",".join(headers)]
    for c in claims:
        cc = c.get("classification", {})
        row = [
            c.get("claim_id", ""),
            c.get("status", ""),
            f'"{c.get("claimant_name", "")}"',
            c.get("claimant_email", ""),
            f'"{c.get("respondent_entity", "")}"',
            str(c.get("amount_claimed_usd", 0)),
            c.get("harm_type", ""),
            c.get("filed_at", ""),
            cc.get("value_band", ""),
            cc.get("dispute_type", ""),
            cc.get("recovery_path", ""),
            c.get("sla_status", "n/a"),
            str(c.get("outreach_count", 0)),
        ]
        lines.append(",".join(row))

    csv_content = "\n".join(lines)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ghostledger_claims_export.csv"},
    )


# ============================================================================
# CASE ASSIGNMENT & WORKLOAD DISTRIBUTION
# ============================================================================

@app.get("/v1/operators")
async def list_operators(authorization: Optional[str] = Header(None)):
    """List all operators/team members."""
    verify_api_key(authorization)
    operators = store.list_operators()
    return {"operators": operators, "total": len(operators)}


@app.post("/v1/operators")
async def save_operator(body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Create or update an operator."""
    verify_api_key(authorization)
    operator_id = body.get("operator_id") or f"op_{uuid.uuid4().hex[:12]}"
    name = body.get("name", "").strip()
    email = body.get("email", "").strip()
    role = body.get("role", "analyst").strip()
    max_caseload = int(body.get("max_caseload", 25))
    if not name:
        raise HTTPException(status_code=400, detail="Operator name is required")
    result = store.save_operator(operator_id, name, email, role, max_caseload)
    store.audit("operator.saved", {"operator_id": operator_id, "name": name, "role": role}, actor="operator")
    return result


@app.delete("/v1/operators/{operator_id}")
async def delete_operator(operator_id: str, authorization: Optional[str] = Header(None)):
    """Remove an operator and unassign their claims."""
    verify_api_key(authorization)
    if not store.delete_operator(operator_id):
        raise HTTPException(status_code=404, detail="Operator not found")
    store.audit("operator.deleted", {"operator_id": operator_id}, actor="operator")
    return {"deleted": True}


@app.post("/v1/claims/bulk/assign")
async def bulk_assign_claims(request: Request, authorization: Optional[str] = Header(None)):
    """Bulk assign claims to an operator. Body: {"claim_ids": [...], "operator_id": "..."}"""
    verify_api_key(authorization)
    body = await request.json()
    claim_ids = body.get("claim_ids", [])
    operator_id = body.get("operator_id", "").strip()
    if not claim_ids:
        raise HTTPException(status_code=400, detail="claim_ids array is required")
    if not operator_id:
        raise HTTPException(status_code=400, detail="operator_id is required")
    op = store.get_operator(operator_id)
    if not op:
        raise HTTPException(status_code=404, detail="Operator not found")
    result = store.bulk_assign(claim_ids, operator_id)
    store.audit("claims.bulk_assigned", {
        "count": result["assigned"],
        "operator_id": operator_id,
        "operator_name": op["name"],
    }, actor="operator")
    return result


@app.post("/v1/claims/{claim_id}/assign")
async def assign_claim(claim_id: str, body: Dict[str, str], authorization: Optional[str] = Header(None)):
    """Assign a claim to an operator. Body: {"operator_id": "..."}"""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    operator_id = body.get("operator_id", "").strip()
    if not operator_id:
        raise HTTPException(status_code=400, detail="operator_id is required")
    op = store.get_operator(operator_id)
    if not op:
        raise HTTPException(status_code=404, detail="Operator not found")
    result = store.assign_claim(claim_id, operator_id)
    store.publish_event("claim.assigned", {"claim_id": claim_id, "operator_id": operator_id, "operator_name": op["name"]})
    store.audit("claim.assigned", {
        "claim_id": claim_id,
        "operator_id": operator_id,
        "operator_name": op["name"],
        "respondent": claim.get("respondent_entity", "Unknown"),
    }, actor="operator")
    return result


@app.delete("/v1/claims/{claim_id}/assign")
async def unassign_claim(claim_id: str, authorization: Optional[str] = Header(None)):
    """Unassign a claim."""
    verify_api_key(authorization)
    store.unassign_claim(claim_id)
    store.audit("claim.unassigned", {"claim_id": claim_id}, actor="operator")
    return {"claim_id": claim_id, "unassigned": True}


@app.post("/v1/claims/{claim_id}/auto-assign")
async def auto_assign_claim(claim_id: str, authorization: Optional[str] = Header(None)):
    """Auto-assign a claim to the operator with most available capacity."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    result = store.auto_assign(claim_id)
    if not result:
        raise HTTPException(status_code=409, detail="No operators with available capacity")
    op = store.get_operator(result["operator_id"])
    store.publish_event("claim.auto_assigned", {
        "claim_id": claim_id,
        "operator_id": result["operator_id"],
        "operator_name": op["name"] if op else "Unknown",
    })
    store.audit("claim.auto_assigned", {
        "claim_id": claim_id,
        "operator_id": result["operator_id"],
    }, actor="system")
    return result


# bulk assign moved above {claim_id}/assign to prevent route shadowing


@app.get("/v1/workload")
async def get_workload(authorization: Optional[str] = Header(None)):
    """Get workload distribution across all operators."""
    verify_api_key(authorization)
    return store.get_workload_stats()


# ============================================================================
# SETTLEMENT & RESOLUTION TRACKER
# ============================================================================

@app.get("/v1/claims/{claim_id}/settlements")
async def get_claim_settlements(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all settlement offers/counteroffers for a claim."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    settlements = store.get_claim_settlements(claim_id)
    resolution = store.get_resolution(claim_id)
    return {
        "claim_id": claim_id,
        "settlements": settlements,
        "resolution": resolution,
        "total_offers": len(settlements),
    }


@app.post("/v1/claims/{claim_id}/settlements")
async def create_settlement_offer(claim_id: str, body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Create a settlement offer or counteroffer."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    offer_type = body.get("offer_type", "initial_offer").strip()
    if offer_type not in ("initial_offer", "counteroffer", "final_offer"):
        raise HTTPException(status_code=400, detail="offer_type must be initial_offer, counteroffer, or final_offer")
    offered_by = body.get("offered_by", "respondent").strip()
    amount = float(body.get("amount_offered", 0))
    terms = body.get("terms", "").strip()
    deadline = body.get("response_deadline")
    result = store.create_settlement_offer(claim_id, offer_type, offered_by, amount, terms, deadline)
    store.audit("settlement.offer_created", {
        "claim_id": claim_id,
        "settlement_id": result["settlement_id"],
        "offer_type": offer_type,
        "offered_by": offered_by,
        "amount_offered": amount,
        "respondent": claim.get("respondent_entity", "Unknown"),
    }, actor="operator")

    # Notification: settlement offer created
    try:
        store.create_notification(
            "settlement_response", "info",
            f"New {offer_type.replace('_',' ').title()}: ${amount:,.2f}",
            f"{offered_by.title()} made a ${amount:,.2f} {offer_type.replace('_',' ')} for claim against {claim.get('respondent_entity','Unknown')}.",
            claim_id=claim_id, source="settlement_engine",
            action_label="Review Offer",
        )
    except Exception:
        pass

    return result


@app.patch("/v1/settlements/{settlement_id}")
async def update_settlement(settlement_id: str, body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Update a settlement status: accept, reject, expire, or withdraw."""
    verify_api_key(authorization)
    settlement = store.get_settlement(settlement_id)
    if not settlement:
        raise HTTPException(status_code=404, detail="Settlement not found")
    new_status = body.get("status", "").strip()
    if new_status not in ("accepted", "rejected", "expired", "withdrawn"):
        raise HTTPException(status_code=400, detail="Status must be accepted, rejected, expired, or withdrawn")
    if settlement["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"Settlement is already {settlement['status']}")
    result = store.update_settlement_status(settlement_id, new_status)
    store.audit("settlement.status_changed", {
        "settlement_id": settlement_id,
        "claim_id": settlement["claim_id"],
        "old_status": "pending",
        "new_status": new_status,
        "amount_offered": settlement["amount_offered"],
    }, actor="operator")

    # If accepted, auto-create resolution and update claim status
    if new_status == "accepted":
        claim = store.get_claim(settlement["claim_id"])
        amount_claimed = claim.get("amount_claimed_usd", 0) if claim else 0
        ratio = settlement["amount_offered"] / amount_claimed if amount_claimed > 0 else 0
        res_type = "full_settlement" if ratio >= 0.95 else "partial_settlement"
        resolution = store.create_resolution(
            claim_id=settlement["claim_id"],
            settlement_id=settlement_id,
            resolution_type=res_type,
            amount_settled=settlement["amount_offered"],
            amount_claimed=amount_claimed,
            terms_summary=settlement.get("terms", ""),
        )
        # Update claim status to resolved
        if claim:
            conn = _get_db()
            claim_data = claim.copy()
            claim_data["status"] = "resolved"
            conn.execute("UPDATE claims SET data = ? WHERE claim_id = ?",
                         (json.dumps(claim_data), settlement["claim_id"]))
            conn.commit()
            conn.close()
            store.audit("status.changed", {
                "claim_id": settlement["claim_id"],
                "old_status": claim.get("status", "unknown"),
                "new_status": "resolved",
                "reason": f"Settlement accepted: ${settlement['amount_offered']:.2f} ({res_type})",
                "respondent": claim.get("respondent_entity", "Unknown"),
            }, actor="system")
        result["resolution"] = resolution

    # Notification: settlement accepted/resolved
    try:
        sev = "info" if new_status in ("rejected", "withdrawn") else "warning"
        store.create_notification(
            "settlement_response", sev,
            f"Settlement {new_status.title()}: ${settlement['amount_offered']:,.2f}",
            f"Settlement for claim {settlement['claim_id'][:16]} was {new_status}." +
            (f" Claim auto-resolved as {res_type.replace('_',' ')}." if new_status == "accepted" else ""),
            claim_id=settlement["claim_id"], source="settlement_engine",
            action_label="View Details",
        )
    except Exception:
        pass

    return result


@app.post("/v1/claims/{claim_id}/resolve")
async def resolve_claim(claim_id: str, body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Directly resolve a claim without a formal settlement (mediation, arbitration, withdrawal, etc.)."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    existing = store.get_resolution(claim_id)
    if existing:
        raise HTTPException(status_code=409, detail="Claim already has a resolution")
    res_type = body.get("resolution_type", "full_settlement").strip()
    valid_types = ("full_settlement", "partial_settlement", "mediated", "arbitrated", "withdrawn", "dismissed")
    if res_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"resolution_type must be one of: {', '.join(valid_types)}")
    amount_settled = float(body.get("amount_settled", 0))
    amount_claimed = float(body.get("amount_claimed", claim.get("amount_claimed_usd", 0)))
    resolution = store.create_resolution(
        claim_id=claim_id,
        resolution_type=res_type,
        amount_settled=amount_settled,
        amount_claimed=amount_claimed,
        terms_summary=body.get("terms_summary", ""),
        resolution_notes=body.get("resolution_notes", ""),
    )
    # Update claim status
    new_status = "resolved" if res_type not in ("withdrawn", "dismissed") else "closed"
    conn = _get_db()
    claim_data = claim.copy()
    claim_data["status"] = new_status
    conn.execute("UPDATE claims SET data = ? WHERE claim_id = ?", (json.dumps(claim_data), claim_id))
    conn.commit()
    conn.close()
    store.audit("claim.resolved", {
        "claim_id": claim_id,
        "resolution_type": res_type,
        "amount_settled": amount_settled,
        "amount_claimed": amount_claimed,
        "ratio": resolution["settlement_ratio"],
        "respondent": claim.get("respondent_entity", "Unknown"),
    }, actor="operator")
    store.audit("status.changed", {
        "claim_id": claim_id,
        "old_status": claim.get("status", "unknown"),
        "new_status": new_status,
        "reason": f"Resolved via {res_type}: ${amount_settled:.2f}",
        "respondent": claim.get("respondent_entity", "Unknown"),
    }, actor="system")
    resolution["new_status"] = new_status
    return resolution


@app.get("/v1/resolution-dashboard")
async def resolution_dashboard(authorization: Optional[str] = Header(None)):
    """Get aggregated resolution statistics."""
    verify_api_key(authorization)
    return store.get_resolution_dashboard()


# ============================================================================
# AUTOMATED WORKFLOW RULES ENGINE
# ============================================================================

@app.get("/v1/workflow/rules")
async def list_workflow_rules(authorization: Optional[str] = Header(None)):
    """List all workflow rules."""
    verify_api_key(authorization)
    rules = store.list_workflow_rules()
    return {"rules": rules, "total": len(rules)}


@app.post("/v1/workflow/rules")
async def save_workflow_rule(body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Create or update a workflow rule."""
    verify_api_key(authorization)
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Rule name is required")
    rule = store.save_workflow_rule(
        rule_id=body.get("rule_id"),
        name=name,
        description=body.get("description", ""),
        trigger_event=body.get("trigger_event", "claim.filed"),
        conditions=body.get("conditions", {}),
        actions=body.get("actions", []),
        enabled=body.get("enabled", True),
        priority=int(body.get("priority", 50)),
    )
    store.audit("workflow.rule_saved", {"rule_id": rule["rule_id"], "name": name}, actor="operator")
    return rule


@app.patch("/v1/workflow/rules/{rule_id}/toggle")
async def toggle_workflow_rule(rule_id: str, body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Enable or disable a workflow rule."""
    verify_api_key(authorization)
    enabled = body.get("enabled", True)
    rule = store.toggle_workflow_rule(rule_id, enabled)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    store.audit("workflow.rule_toggled", {"rule_id": rule_id, "enabled": enabled}, actor="operator")
    return rule


@app.delete("/v1/workflow/rules/{rule_id}")
async def delete_workflow_rule(rule_id: str, authorization: Optional[str] = Header(None)):
    """Delete a workflow rule."""
    verify_api_key(authorization)
    if not store.delete_workflow_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    store.audit("workflow.rule_deleted", {"rule_id": rule_id}, actor="operator")
    return {"deleted": True}


@app.post("/v1/workflow/evaluate")
async def evaluate_workflow_rules(body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Manually evaluate workflow rules for a specific claim or trigger event. Dry run — shows matches but doesn't execute."""
    verify_api_key(authorization)
    trigger = body.get("trigger_event", "claim.filed")
    claim_id = body.get("claim_id", "")
    if claim_id:
        claim_data = store.get_claim(claim_id)
        if not claim_data:
            raise HTTPException(status_code=404, detail="Claim not found")
    else:
        claim_data = body.get("claim_data", {})
    matches = store.evaluate_workflow_rules(trigger, claim_data)
    return {"trigger_event": trigger, "claim_id": claim_id, "matches": matches, "total_matches": len(matches)}


@app.post("/v1/workflow/execute")
async def execute_workflow_rules(body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Execute workflow rules for a specific claim and trigger event."""
    verify_api_key(authorization)
    trigger = body.get("trigger_event", "claim.filed")
    claim_id = body.get("claim_id", "")
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    claim_data = store.get_claim(claim_id)
    if not claim_data:
        raise HTTPException(status_code=404, detail="Claim not found")

    matches = store.evaluate_workflow_rules(trigger, claim_data)
    results = []
    for m in matches:
        result = store.execute_workflow_actions(
            m["rule_id"], m["rule_name"], claim_id, claim_data, m["actions"], trigger
        )
        results.append(result)

    return {"trigger_event": trigger, "claim_id": claim_id, "rules_matched": len(matches), "executions": results}


@app.get("/v1/workflow/executions")
async def get_workflow_executions(
    rule_id: Optional[str] = None,
    claim_id: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """Get workflow execution history."""
    verify_api_key(authorization)
    executions = store.get_workflow_executions(rule_id=rule_id, claim_id=claim_id, limit=limit)
    return {"executions": executions, "total": len(executions)}


@app.post("/v1/workflow/run-scheduled")
async def run_scheduled_rules(authorization: Optional[str] = Header(None)):
    """Run all scheduled.daily rules against eligible claims. Called manually or by cron."""
    verify_api_key(authorization)
    rules = store.list_workflow_rules()
    scheduled = [r for r in rules if r["trigger_event"] == "scheduled.daily" and r["enabled"]]
    if not scheduled:
        return {"message": "No scheduled rules enabled", "executions": []}

    conn = _get_db()
    all_claims = []
    for row in conn.execute("SELECT claim_id, data FROM claims").fetchall():
        d = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
        d["claim_id"] = row["claim_id"]
        all_claims.append(d)
    conn.close()

    all_results = []
    for claim_data in all_claims:
        matches = store.evaluate_workflow_rules("scheduled.daily", claim_data)
        for m in matches:
            result = store.execute_workflow_actions(
                m["rule_id"], m["rule_name"], claim_data["claim_id"], claim_data, m["actions"], "scheduled.daily"
            )
            all_results.append(result)

    store.audit("workflow.scheduled_run", {
        "rules_checked": len(scheduled),
        "claims_checked": len(all_claims),
        "actions_executed": len(all_results),
    }, actor="system")

    return {
        "rules_checked": len(scheduled),
        "claims_checked": len(all_claims),
        "total_executions": len(all_results),
        "executions": all_results,
    }


# Helper: evaluate and execute workflow rules for a claim event
def _run_workflow_rules(trigger_event: str, claim_data: Dict[str, Any]):
    """Background evaluation of workflow rules after a claim event."""
    try:
        matches = store.evaluate_workflow_rules(trigger_event, claim_data)
        for m in matches:
            store.execute_workflow_actions(
                m["rule_id"], m["rule_name"], claim_data.get("claim_id", ""),
                claim_data, m["actions"], trigger_event
            )
    except Exception as e:
        logger.warning(f"Workflow rule evaluation failed for {trigger_event}: {e}")


# ============================================================================
# DOCUMENT / EVIDENCE MANAGEMENT
# ============================================================================
# Attach files and evidence to claims. Supports metadata tracking, categorization,
# base64 content storage, SHA-256 integrity hashing, and search.
# ============================================================================

@app.get("/v1/claims/{claim_id}/documents")
async def list_claim_documents(
    claim_id: str,
    category: Optional[str] = None,
    file_type: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List all documents attached to a claim, optionally filtered by category or file_type."""
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    docs = store.get_claim_documents(claim_id, category=category, file_type=file_type)
    return {"claim_id": claim_id, "documents": docs, "total": len(docs)}


@app.post("/v1/claims/{claim_id}/documents")
async def upload_document(claim_id: str, body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """
    Upload/attach a document to a claim.
    Body: {
        "filename": "receipt.pdf",
        "category": "receipt",           # evidence|correspondence|screenshot|receipt|contract|identification|legal|financial|communication_log|other
        "description": "Payment receipt from platform",
        "mime_type": "application/pdf",
        "content_b64": "<base64-encoded-file>",  # Optional — can store content inline
        "file_size_bytes": 12345,
        "tags": ["payment", "proof"],
        "metadata": {"source": "email"},
        "uploaded_by": "operator"
    }
    """
    verify_api_key(authorization)
    claim = store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    filename = body.get("filename", "").strip()
    if not filename:
        raise HTTPException(status_code=400, detail="filename is required")

    # Max inline content size: 10MB base64
    content_b64 = body.get("content_b64")
    if content_b64 and len(content_b64) > 10 * 1024 * 1024 * 1.37:  # ~10MB raw → ~13.7MB b64
        raise HTTPException(status_code=400, detail="File content exceeds maximum size (10MB)")

    doc = store.add_document(
        claim_id=claim_id,
        filename=filename,
        category=body.get("category", "evidence"),
        description=body.get("description", ""),
        file_size_bytes=int(body.get("file_size_bytes", 0)),
        mime_type=body.get("mime_type", "application/octet-stream"),
        content_b64=content_b64,
        uploaded_by=body.get("uploaded_by", "operator"),
        tags=body.get("tags", []),
        metadata=body.get("metadata", {}),
    )
    return doc


@app.get("/v1/documents/stats/overview")
async def document_stats(authorization: Optional[str] = Header(None)):
    """Get aggregate document/evidence statistics across all claims."""
    verify_api_key(authorization)
    return store.get_document_stats()


@app.get("/v1/documents/search")
async def search_documents(
    q: str = "",
    claim_id: Optional[str] = None,
    category: Optional[str] = None,
    file_type: Optional[str] = None,
    uploaded_by: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """Search documents across all claims by filename, description, tags, or filters."""
    verify_api_key(authorization)
    docs = store.search_documents(query=q, claim_id=claim_id, category=category,
                                  file_type=file_type, uploaded_by=uploaded_by, limit=limit)
    return {"documents": docs, "total": len(docs), "query": q}


@app.get("/v1/documents/{document_id}")
async def get_document(document_id: str, include_content: bool = False,
                       authorization: Optional[str] = Header(None)):
    """Get a single document by ID. Pass ?include_content=true to include base64 content."""
    verify_api_key(authorization)
    doc = store.get_document(document_id, include_content=include_content)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


@app.patch("/v1/documents/{document_id}")
async def update_document(document_id: str, body: Dict[str, Any],
                          authorization: Optional[str] = Header(None)):
    """Update document metadata (description, category, tags, metadata)."""
    verify_api_key(authorization)
    updated = store.update_document(document_id, body)
    if not updated:
        raise HTTPException(status_code=404, detail="Document not found")
    return updated


@app.delete("/v1/documents/{document_id}")
async def delete_document(document_id: str, authorization: Optional[str] = Header(None)):
    """Delete a document record."""
    verify_api_key(authorization)
    if not store.delete_document(document_id):
        raise HTTPException(status_code=404, detail="Document not found")
    return {"deleted": True}


# ============================================================================
# MULTI-CLAIM LINKING & CASE GROUPS
# ============================================================================
# Link related claims for coordinated action: respondent clusters, incident
# groups, pattern-based linking, and class-action-style coordination.
# ============================================================================

@app.get("/v1/case-groups/analytics")
async def case_group_analytics(authorization: Optional[str] = Header(None)):
    """Get analytics across all case groups."""
    verify_api_key(authorization)
    return store.get_group_analytics()


@app.get("/v1/case-groups/suggest")
async def suggest_case_groups(authorization: Optional[str] = Header(None)):
    """Auto-detect potential case groups from unlinked claims sharing respondents."""
    verify_api_key(authorization)
    suggestions = store.auto_detect_groups()
    return {"suggestions": suggestions, "total": len(suggestions)}


@app.get("/v1/case-groups")
async def list_case_groups(
    status: Optional[str] = None,
    group_type: Optional[str] = None,
    respondent_key: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """List all case groups with summary stats."""
    verify_api_key(authorization)
    groups = store.list_case_groups(status=status, group_type=group_type,
                                    respondent_key=respondent_key, limit=limit)
    return {"groups": groups, "total": len(groups)}


@app.post("/v1/case-groups")
async def create_case_group(body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """
    Create a new case group.
    Body: {"name": "...", "group_type": "respondent|incident|pattern|class_action|geographic|custom",
           "description": "...", "respondent_key": "...", "tags": [...], "strategy_notes": "..."}
    """
    verify_api_key(authorization)
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    group = store.create_case_group(
        name=name,
        group_type=body.get("group_type", "respondent"),
        description=body.get("description", ""),
        respondent_key=body.get("respondent_key"),
        tags=body.get("tags", []),
        strategy_notes=body.get("strategy_notes", ""),
        created_by=body.get("created_by", "operator"),
    )
    return group


@app.get("/v1/case-groups/{group_id}")
async def get_case_group(group_id: str, authorization: Optional[str] = Header(None)):
    """Get a case group with all linked claims and aggregate stats."""
    verify_api_key(authorization)
    group = store.get_case_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Case group not found")
    return group


@app.patch("/v1/case-groups/{group_id}")
async def update_case_group(group_id: str, body: Dict[str, Any],
                            authorization: Optional[str] = Header(None)):
    """Update case group metadata (name, description, status, tags, strategy_notes)."""
    verify_api_key(authorization)
    updated = store.update_case_group(group_id, body)
    if not updated:
        raise HTTPException(status_code=404, detail="Case group not found")
    return updated


@app.delete("/v1/case-groups/{group_id}")
async def delete_case_group(group_id: str, authorization: Optional[str] = Header(None)):
    """Delete a case group and all its claim links."""
    verify_api_key(authorization)
    if not store.delete_case_group(group_id):
        raise HTTPException(status_code=404, detail="Case group not found")
    return {"deleted": True}


@app.post("/v1/case-groups/{group_id}/claims")
async def link_claim(group_id: str, body: Dict[str, Any],
                     authorization: Optional[str] = Header(None)):
    """
    Link a claim to a case group.
    Body: {"claim_id": "clm_xxx", "role": "lead|member|supporting|related", "notes": "..."}
    """
    verify_api_key(authorization)
    claim_id = body.get("claim_id", "").strip()
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    result = store.link_claim_to_group(
        group_id=group_id,
        claim_id=claim_id,
        role=body.get("role", "member"),
        notes=body.get("notes", ""),
        linked_by=body.get("linked_by", "operator"),
    )
    if not result:
        raise HTTPException(status_code=404, detail="Case group or claim not found")
    return result


@app.delete("/v1/case-groups/{group_id}/claims/{claim_id}")
async def unlink_claim(group_id: str, claim_id: str,
                       authorization: Optional[str] = Header(None)):
    """Remove a claim from a case group."""
    verify_api_key(authorization)
    if not store.unlink_claim_from_group(group_id, claim_id):
        raise HTTPException(status_code=404, detail="Link not found")
    return {"unlinked": True}


@app.get("/v1/claims/{claim_id}/groups")
async def get_claim_groups(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all case groups a specific claim belongs to."""
    verify_api_key(authorization)
    groups = store.get_claim_groups(claim_id)
    return {"claim_id": claim_id, "groups": groups, "total": len(groups)}


@app.post("/v1/case-groups/auto-create")
async def auto_create_groups(body: Dict[str, Any] = None,
                             authorization: Optional[str] = Header(None)):
    """
    Auto-create case groups from detected respondent clusters.
    Optional body: {"min_claims": 2} to set minimum cluster size.
    """
    verify_api_key(authorization)
    min_claims = 2
    if body:
        min_claims = int(body.get("min_claims", 2))
    suggestions = store.auto_detect_groups()
    created = []
    for s in suggestions:
        if s["claim_count"] < min_claims:
            continue
        group = store.create_case_group(
            name=s["suggested_name"],
            group_type="respondent",
            description=f"Auto-generated group: {s['claim_count']} claims totaling ${s['total_amount']:,.2f} against {s['respondent']}",
            respondent_key=s["respondent"],
            tags=["auto-detected"],
            created_by="system",
        )
        for cid in s["claim_ids"]:
            store.link_claim_to_group(group["group_id"], cid, role="member", linked_by="system")
        group["claims_linked"] = len(s["claim_ids"])
        created.append(group)

    store.audit("case_groups.auto_created", {
        "groups_created": len(created),
        "total_claims_linked": sum(g.get("claims_linked", 0) for g in created),
    }, actor="system")

    return {"created": len(created), "groups": created}


# ============================================================================
# NOTIFICATION CENTER
# ============================================================================
# Unified alert system for SLA breaches, escalations, settlement deadlines,
# workflow triggers, new claims, and status changes.
# ============================================================================

@app.get("/v1/notifications")
async def list_notifications(
    unread_only: bool = False,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    claim_id: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """List notifications with optional filters."""
    verify_api_key(authorization)
    notifs = store.get_notifications(
        unread_only=unread_only, severity=severity,
        ntype=type, claim_id=claim_id, limit=limit,
    )
    summary = store.get_notification_summary()
    return {"notifications": notifs, "total": len(notifs), **summary}


@app.get("/v1/notifications/summary")
async def notification_summary(authorization: Optional[str] = Header(None)):
    """Get notification badge data: unread count, severity breakdown."""
    verify_api_key(authorization)
    return store.get_notification_summary()


@app.post("/v1/notifications")
async def create_notification(body: Dict[str, Any], authorization: Optional[str] = Header(None)):
    """Manually create a notification."""
    verify_api_key(authorization)
    title = body.get("title", "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    n = store.create_notification(
        ntype=body.get("type", "system"),
        severity=body.get("severity", "info"),
        title=title,
        message=body.get("message", ""),
        claim_id=body.get("claim_id"),
        source=body.get("source", "manual"),
        action_url=body.get("action_url", ""),
        action_label=body.get("action_label", ""),
    )
    return n


@app.patch("/v1/notifications/{notification_id}/read")
async def mark_read(notification_id: str, authorization: Optional[str] = Header(None)):
    """Mark a single notification as read."""
    verify_api_key(authorization)
    if not store.mark_notification_read(notification_id):
        raise HTTPException(status_code=404, detail="Notification not found or already read")
    return {"marked_read": True}


@app.post("/v1/notifications/read-all")
async def mark_all_read(authorization: Optional[str] = Header(None)):
    """Mark all notifications as read."""
    verify_api_key(authorization)
    count = store.mark_all_notifications_read()
    return {"marked_read": count}


@app.delete("/v1/notifications/{notification_id}")
async def dismiss_notification(notification_id: str, authorization: Optional[str] = Header(None)):
    """Dismiss (soft-delete) a notification."""
    verify_api_key(authorization)
    if not store.dismiss_notification(notification_id):
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"dismissed": True}


@app.post("/v1/notifications/dismiss-all")
async def dismiss_all(authorization: Optional[str] = Header(None)):
    """Dismiss all notifications."""
    verify_api_key(authorization)
    count = store.dismiss_all_notifications()
    return {"dismissed": count}


@app.post("/v1/notifications/scan")
async def scan_notifications(authorization: Optional[str] = Header(None)):
    """
    Run notification scanners: check SLA status and settlement deadlines,
    generate new notifications as needed. Call this periodically or on-demand.
    """
    verify_api_key(authorization)
    sla_notifs = store.generate_sla_notifications()
    settle_notifs = store.generate_settlement_deadline_notifications()
    total = len(sla_notifs) + len(settle_notifs)
    store.audit("notifications.scan", {
        "sla_notifications": len(sla_notifs),
        "settlement_notifications": len(settle_notifs),
        "total_generated": total,
    }, actor="system")
    return {
        "scanned": True,
        "sla_notifications": len(sla_notifs),
        "settlement_notifications": len(settle_notifs),
        "total_generated": total,
        "notifications": sla_notifs + settle_notifs,
    }


# ============================================================================
# CLAIMANT LOOKUP PORTAL — Public-facing claim status endpoint
# ============================================================================
# NO API key required — verified by claim_id + claimant_email match.
# Returns ONLY sanitized, claimant-safe data (no internal notes, operators, audit).

@app.post("/v1/lookup")
async def claimant_lookup(body: Dict[str, Any]):
    """
    Public claimant lookup. Body: {"claim_id": "clm_xxx", "email": "claimant@email.com"}
    Returns sanitized claim status visible to the claimant.
    """
    claim_id = str(body.get("claim_id", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    if not claim_id or not email:
        raise HTTPException(status_code=400, detail="Both claim_id and email are required")

    claim = store.get_claim(claim_id)
    if not claim:
        # Deliberately vague to prevent enumeration
        raise HTTPException(status_code=404, detail="No claim found matching that ID and email combination")
    if (claim.get("claimant_email", "").lower() != email):
        raise HTTPException(status_code=404, detail="No claim found matching that ID and email combination")

    # Build sanitized response — NO internal data
    status = claim.get("status", "draft")
    filed_at = claim.get("filed_at") or claim.get("timestamp")

    # Status progress mapping
    status_steps = ["filed", "under_review", "in_resolution", "resolved"]
    current_step = status_steps.index(status) if status in status_steps else -1
    if status in ("escalated", "awaiting_review"):
        current_step = 1  # Treat as under_review equivalent for claimant
    if status == "closed":
        current_step = 3  # Treat as resolved

    # Friendly status labels
    status_labels = {
        "draft": "Draft — Your claim has been saved but not yet submitted.",
        "filed": "Filed — Your claim has been received and is awaiting review by our coordination team.",
        "under_review": "Under Review — Your claim is being evaluated by a claims professional.",
        "awaiting_review": "Awaiting Review — Your claim is queued for independent assessment.",
        "escalated": "Escalated — Your claim has been elevated for specialized follow-up.",
        "in_resolution": "In Resolution — Active negotiation or resolution process is underway.",
        "resolved": "Resolved — An outcome has been reached and documented.",
        "closed": "Closed — Your case has been finalized.",
        "appealed": "Appealed — Your case outcome is being re-evaluated.",
    }

    # SLA info (sanitized — just show expected timeline, not internal metrics)
    sla_info = None
    try:
        sla_data = store.check_sla_status(claim_id)
        if sla_data and sla_data.get("sla_status") != "n/a":
            days_remaining = sla_data.get("days_remaining", 0)
            sla_info = {
                "status": "on_track" if days_remaining > 3 else ("at_risk" if days_remaining > 0 else "extended"),
                "message": f"Expected processing within {max(int(days_remaining), 1)} days" if days_remaining > 0 else "Processing is taking longer than expected — our team is actively working on your case",
            }
    except Exception:
        pass

    # Settlement/resolution info (sanitized)
    resolution_info = None
    resolution = store.get_resolution(claim_id)
    if resolution:
        res_type_labels = {
            "full_settlement": "Full Settlement",
            "partial_settlement": "Partial Settlement",
            "mediated": "Mediated Resolution",
            "arbitrated": "Arbitrated Decision",
            "withdrawn": "Withdrawn",
            "dismissed": "Dismissed",
        }
        resolution_info = {
            "type": res_type_labels.get(resolution["resolution_type"], resolution["resolution_type"]),
            "amount_settled": resolution["amount_settled"],
            "resolved_at": resolution["resolved_at"],
            "terms": resolution.get("terms_summary", ""),
        }

    # Pending settlement offers visible to claimant
    pending_offers = []
    settlements = store.get_claim_settlements(claim_id)
    for s in settlements:
        if s["status"] == "pending":
            pending_offers.append({
                "offer_type": s["offer_type"].replace("_", " ").title(),
                "amount_offered": s["amount_offered"],
                "offered_by": s["offered_by"].title(),
                "terms": s.get("terms", ""),
                "created_at": s["created_at"],
                "response_deadline": s.get("response_deadline"),
            })

    # Recovery info (sanitized)
    recovery_info = None
    try:
        conn = _get_db()
        rec = conn.execute(
            "SELECT SUM(amount_recovered_usd) as total FROM recovery_ledger WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        conn.close()
        if rec and rec["total"]:
            recovery_info = {"amount_recovered": round(rec["total"], 2)}
    except Exception:
        pass

    # Next steps guidance
    next_steps = []
    if status == "filed":
        next_steps = ["Your claim is in the review queue.", "A coordinator will evaluate your case within the standard processing window.", "No action is required from you at this time."]
    elif status in ("under_review", "awaiting_review"):
        next_steps = ["A claims professional is reviewing your case.", "You may be contacted for additional information.", "Check back for updates on your claim status."]
    elif status == "escalated":
        next_steps = ["Your case has been elevated for specialized attention.", "This may involve additional review or referral to a professional advocate.", "We'll update your status as the process moves forward."]
    elif status == "in_resolution":
        next_steps = ["Resolution proceedings are active.", "Review any pending settlement offers below.", "Contact us if you have questions about the process."]
    elif status in ("resolved", "closed"):
        next_steps = ["Your case has been concluded.", "Review the resolution details below.", "If you believe the outcome is incorrect, you may appeal."]
    elif pending_offers:
        next_steps.append("You have pending settlement offers to review.")

    store.audit("claimant.lookup", {"claim_id": claim_id, "status": status}, actor="claimant")

    return {
        "claim_id": claim_id,
        "claimant_name": claim.get("claimant_name", ""),
        "respondent": claim.get("respondent_entity", "Unknown"),
        "amount_claimed_usd": claim.get("amount_claimed_usd", 0),
        "status": status,
        "status_label": status_labels.get(status, f"Status: {status}"),
        "status_progress": {
            "steps": ["Filed", "Under Review", "In Resolution", "Resolved"],
            "current": max(current_step, 0),
        },
        "filed_at": filed_at,
        "sla": sla_info,
        "resolution": resolution_info,
        "pending_offers": pending_offers,
        "recovery": recovery_info,
        "next_steps": next_steps,
        "support_contact": "support@ghostledger.io",
        "disclaimer": "This information reflects the current state of your claim in our coordination system. Status descriptions are for informational purposes only and do not constitute legal advice or guarantee any particular outcome.",
    }


# ── Financial Reconciliation Endpoints ──


@app.get("/v1/financial/summary")
async def financial_summary(authorization: Optional[str] = Header(None)):
    """Comprehensive financial reconciliation summary."""
    verify_api_key(authorization)
    return store.get_financial_summary()


@app.get("/v1/financial/by-respondent")
async def financial_by_respondent(limit: int = 20, authorization: Optional[str] = Header(None)):
    """Financial breakdown by respondent entity."""
    verify_api_key(authorization)
    return store.get_financial_by_respondent(limit=limit)


@app.get("/v1/financial/trends")
async def financial_trends(days: int = 90, authorization: Optional[str] = Header(None)):
    """Financial trends over time."""
    verify_api_key(authorization)
    return store.get_financial_trends(days=days)


@app.get("/v1/financial/gaps")
async def financial_gaps(min_gap: float = 0, authorization: Optional[str] = Header(None)):
    """Claims with largest outstanding financial gaps."""
    verify_api_key(authorization)
    return store.get_financial_gaps(min_gap=min_gap)


# ── Claim Scoring & Risk Assessment Endpoints ──


@app.get("/v1/risk/dashboard")
async def risk_dashboard(authorization: Optional[str] = Header(None)):
    """Get full risk assessment dashboard — tier distribution, top risks."""
    verify_api_key(authorization)
    return store.get_risk_dashboard()


@app.get("/v1/risk/by-respondent")
async def risk_by_respondent(limit: int = 15, authorization: Optional[str] = Header(None)):
    """Get average risk scores per respondent entity."""
    verify_api_key(authorization)
    return store.get_risk_by_respondent(limit=limit)


@app.get("/v1/risk/claim/{claim_id}")
async def risk_claim(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get risk assessment for a single claim with factor breakdown."""
    verify_api_key(authorization)
    return store.get_claim_risk(claim_id)


# ── Settlement Negotiation Tracker Endpoints ──


@app.get("/v1/negotiations/stats")
async def negotiation_stats(authorization: Optional[str] = Header(None)):
    """Get negotiation statistics overview."""
    verify_api_key(authorization)
    return store.get_negotiation_stats()


@app.get("/v1/negotiations/claim/{claim_id}")
async def claim_negotiations(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all negotiation rounds for a claim."""
    verify_api_key(authorization)
    return store.get_claim_negotiations(claim_id)


@app.post("/v1/negotiations")
async def create_negotiation(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new negotiation round."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id", "").strip()
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    offer = body.get("offer_amount")
    if offer is None:
        raise HTTPException(status_code=400, detail="offer_amount is required")
    return store.create_negotiation_round(
        claim_id=claim_id,
        offer_amount=float(offer),
        initiated_by=body.get("initiated_by", "claimant"),
        terms=body.get("terms", ""),
        deadline=body.get("deadline"),
        created_by=body.get("created_by", "operator"),
    )


@app.post("/v1/negotiations/{negotiation_id}/counter")
async def counter_negotiation(negotiation_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Counter an existing negotiation offer."""
    verify_api_key(authorization)
    body = await request.json()
    counter = body.get("counter_amount")
    if counter is None:
        raise HTTPException(status_code=400, detail="counter_amount is required")
    return store.counter_negotiation(
        negotiation_id=negotiation_id,
        counter_amount=float(counter),
        response_note=body.get("response_note", ""),
        responded_by=body.get("responded_by", "respondent"),
    )


@app.post("/v1/negotiations/{negotiation_id}/resolve")
async def resolve_negotiation(negotiation_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Accept, reject, expire, or withdraw a negotiation."""
    verify_api_key(authorization)
    body = await request.json()
    status = body.get("status", "").strip()
    if not status:
        raise HTTPException(status_code=400, detail="status is required")
    return store.resolve_negotiation(
        negotiation_id=negotiation_id,
        status=status,
        response_note=body.get("response_note", ""),
        responded_by=body.get("responded_by", "operator"),
    )


# ── Claim Watchlist & Operator Bookmarks Endpoints ──


@app.get("/v1/watchlist/stats")
async def watchlist_stats(operator_id: Optional[str] = None, authorization: Optional[str] = Header(None)):
    """Get watchlist statistics."""
    verify_api_key(authorization)
    return store.get_watchlist_stats(operator_id=operator_id)


@app.get("/v1/watchlist/colors")
async def watchlist_colors(authorization: Optional[str] = Header(None)):
    """List available watchlist colors."""
    verify_api_key(authorization)
    return {"colors": store.WATCH_COLORS}


@app.get("/v1/watchlist/check/{claim_id}")
async def watchlist_check(claim_id: str, operator_id: str = "operator", authorization: Optional[str] = Header(None)):
    """Check if operator is watching a claim."""
    verify_api_key(authorization)
    return store.is_watching(claim_id, operator_id)


@app.get("/v1/watchlist/{operator_id}")
async def get_watchlist(operator_id: str, priority: Optional[str] = None, authorization: Optional[str] = Header(None)):
    """Get an operator's watchlist."""
    verify_api_key(authorization)
    return store.get_watchlist(operator_id, priority=priority)


@app.post("/v1/watchlist")
async def add_to_watchlist(request: Request, authorization: Optional[str] = Header(None)):
    """Add a claim to the watchlist."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id", "").strip()
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    operator_id = body.get("operator_id", "operator")
    return store.add_to_watchlist(
        claim_id=claim_id,
        operator_id=operator_id,
        label=body.get("label", ""),
        notes=body.get("notes", ""),
        priority=body.get("priority", "normal"),
        color=body.get("color", "#58a6ff"),
        notify=body.get("notify", True),
    )


@app.get("/v1/watchlist/item/{watch_id}")
async def get_watchlist_item(watch_id: str, authorization: Optional[str] = Header(None)):
    """Get a single watchlist item."""
    verify_api_key(authorization)
    return store.get_watchlist_item(watch_id)


@app.patch("/v1/watchlist/item/{watch_id}")
async def update_watchlist_item(watch_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a watchlist item."""
    verify_api_key(authorization)
    body = await request.json()
    return store.update_watchlist_item(watch_id, body)


@app.delete("/v1/watchlist/item/{watch_id}")
async def remove_from_watchlist(watch_id: str, authorization: Optional[str] = Header(None)):
    """Remove a claim from the watchlist."""
    verify_api_key(authorization)
    return store.remove_from_watchlist(watch_id)


# ── Task Queue & Operator Assignments Endpoints ──


@app.get("/v1/tasks/stats")
async def task_stats(assigned_to: Optional[str] = None, authorization: Optional[str] = Header(None)):
    """Get task queue statistics."""
    verify_api_key(authorization)
    return store.get_task_stats(assigned_to=assigned_to)


@app.get("/v1/tasks/types")
async def task_types(authorization: Optional[str] = Header(None)):
    """List available task types, priorities, and statuses."""
    verify_api_key(authorization)
    return {"types": store.TASK_TYPES, "priorities": store.TASK_PRIORITIES,
            "statuses": store.TASK_STATUSES}


@app.get("/v1/tasks")
async def list_tasks(
    claim_id: Optional[str] = None,
    assigned_to: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    task_type: Optional[str] = None,
    overdue: bool = False,
    limit: int = 100,
    authorization: Optional[str] = Header(None),
):
    """List tasks with optional filters."""
    verify_api_key(authorization)
    tasks = store.list_tasks(claim_id=claim_id, assigned_to=assigned_to,
                             status=status, priority=priority, task_type=task_type,
                             overdue_only=overdue, limit=limit)
    return {"tasks": tasks, "total": len(tasks)}


@app.post("/v1/tasks")
async def create_task(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new task."""
    verify_api_key(authorization)
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    return store.create_task(
        title=title,
        claim_id=body.get("claim_id"),
        description=body.get("description", ""),
        task_type=body.get("task_type", "manual"),
        priority=body.get("priority", "normal"),
        assigned_to=body.get("assigned_to"),
        due_at=body.get("due_at"),
        estimated_minutes=body.get("estimated_minutes"),
        tags=body.get("tags"),
        parent_task_id=body.get("parent_task_id"),
        depends_on=body.get("depends_on"),
        metadata=body.get("metadata"),
        created_by=body.get("created_by", "operator"),
    )


@app.get("/v1/tasks/claim/{claim_id}")
async def get_claim_tasks(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all tasks for a specific claim."""
    verify_api_key(authorization)
    return store.get_claim_tasks(claim_id)


@app.get("/v1/tasks/{task_id}")
async def get_task(task_id: str, authorization: Optional[str] = Header(None)):
    """Get a single task by ID."""
    verify_api_key(authorization)
    task = store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.patch("/v1/tasks/{task_id}")
async def update_task(task_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update task metadata."""
    verify_api_key(authorization)
    body = await request.json()
    updated = store.update_task(task_id, body)
    if not updated:
        raise HTTPException(status_code=404, detail="Task not found")
    return updated


@app.post("/v1/tasks/{task_id}/transition")
async def transition_task(task_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Transition a task's status."""
    verify_api_key(authorization)
    body = await request.json()
    new_status = body.get("status", "").strip()
    if not new_status:
        raise HTTPException(status_code=400, detail="status is required")
    return store.transition_task(task_id, new_status, actor=body.get("actor", "operator"))


@app.post("/v1/tasks/{task_id}/assign")
async def assign_task(task_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Assign or reassign a task to an operator."""
    verify_api_key(authorization)
    body = await request.json()
    assigned_to = body.get("assigned_to", "").strip()
    if not assigned_to:
        raise HTTPException(status_code=400, detail="assigned_to is required")
    result = store.assign_task(task_id, assigned_to, actor=body.get("actor", "operator"))
    if not result:
        raise HTTPException(status_code=404, detail="Task not found")
    return result


@app.delete("/v1/tasks/{task_id}")
async def delete_task(task_id: str, authorization: Optional[str] = Header(None)):
    """Delete a task (open/cancelled/deferred only)."""
    verify_api_key(authorization)
    if not store.delete_task(task_id):
        raise HTTPException(status_code=404, detail="Task not found")
    return {"deleted": True, "task_id": task_id}


# ── Operator Performance Scorecards Endpoints ──


@app.get("/v1/scorecards")
async def all_scorecards(authorization: Optional[str] = Header(None)):
    """Get performance scorecards for all operators."""
    verify_api_key(authorization)
    return store.get_all_scorecards()


@app.get("/v1/scorecards/{operator_id}")
async def operator_scorecard(operator_id: str, authorization: Optional[str] = Header(None)):
    """Get detailed scorecard for a specific operator."""
    verify_api_key(authorization)
    return store.get_operator_scorecard(operator_id)


@app.get("/v1/scorecards/{operator_id}/timeline")
async def operator_timeline(operator_id: str, days: int = 30, authorization: Optional[str] = Header(None)):
    """Get daily activity timeline for an operator."""
    verify_api_key(authorization)
    return store.get_operator_activity_timeline(operator_id, days=days)


# ── Export & Download Center Endpoints ──


@app.get("/v1/exports/stats")
async def export_stats(authorization: Optional[str] = Header(None)):
    """Get export statistics."""
    verify_api_key(authorization)
    return store.get_export_stats()


@app.get("/v1/exports/types")
async def export_types(authorization: Optional[str] = Header(None)):
    """List available export types and formats."""
    verify_api_key(authorization)
    return {"types": store.EXPORT_TYPES, "formats": store.EXPORT_FORMATS}


@app.get("/v1/exports/history")
async def export_history(limit: int = 50, authorization: Optional[str] = Header(None)):
    """Get recent export history."""
    verify_api_key(authorization)
    return {"exports": store.get_export_history(limit=limit)}


@app.post("/v1/exports")
async def create_export(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new data export."""
    verify_api_key(authorization)
    body = await request.json()
    export_type = body.get("export_type", "claims").strip()
    if export_type not in store.EXPORT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid export type. Available: {store.EXPORT_TYPES}")
    fmt = body.get("format", "json").strip()
    if fmt not in store.EXPORT_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format. Available: {store.EXPORT_FORMATS}")
    result = store.export_data(
        export_type=export_type,
        format=fmt,
        filters=body.get("filters"),
        created_by=body.get("created_by", "operator"),
    )
    # For CSV, return as plain text response
    if fmt == "csv":
        from starlette.responses import Response
        return Response(
            content=result["csv_content"],
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={export_type}_{result['export_id']}.csv"},
        )
    return result


# ── Case Milestones & Progress Tracking Endpoints ──


@app.get("/v1/milestones/stats")
async def milestone_stats(authorization: Optional[str] = Header(None)):
    """Get milestone statistics."""
    verify_api_key(authorization)
    return store.get_milestone_stats()


@app.get("/v1/milestones/categories")
async def milestone_categories(authorization: Optional[str] = Header(None)):
    """List milestone categories and statuses."""
    verify_api_key(authorization)
    return {"categories": store.MILESTONE_CATEGORIES, "statuses": store.MILESTONE_STATUSES,
            "default_milestones": store.DEFAULT_MILESTONES}


@app.get("/v1/milestones/claim/{claim_id}")
async def get_claim_milestones(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all milestones for a claim with progress."""
    verify_api_key(authorization)
    return store.get_claim_milestones(claim_id)


@app.post("/v1/milestones/initialize/{claim_id}")
async def initialize_milestones(claim_id: str, authorization: Optional[str] = Header(None)):
    """Initialize default milestones for a claim."""
    verify_api_key(authorization)
    return {"milestones": store.initialize_claim_milestones(claim_id)}


@app.post("/v1/milestones")
async def create_milestone(request: Request, authorization: Optional[str] = Header(None)):
    """Create a custom milestone."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id", "").strip()
    title = body.get("title", "").strip()
    if not claim_id or not title:
        raise HTTPException(status_code=400, detail="claim_id and title are required")
    return store.create_milestone(
        claim_id=claim_id, title=title,
        description=body.get("description", ""),
        category=body.get("category", "general"),
        sequence_order=body.get("sequence_order", 0),
        target_date=body.get("target_date"),
        auto_trigger=body.get("auto_trigger"),
        created_by=body.get("created_by", "operator"),
    )


@app.post("/v1/milestones/{milestone_id}/complete")
async def complete_milestone(milestone_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Mark a milestone as completed."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.complete_milestone(
        milestone_id, completed_by=body.get("completed_by", "operator"),
        notes=body.get("notes", ""),
    )
    if not result:
        raise HTTPException(status_code=404, detail="Milestone not found")
    return result


@app.patch("/v1/milestones/{milestone_id}")
async def update_milestone(milestone_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update milestone metadata."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.update_milestone(milestone_id, body)
    if not result:
        raise HTTPException(status_code=404, detail="Milestone not found")
    return result


@app.delete("/v1/milestones/{milestone_id}")
async def delete_milestone(milestone_id: str, authorization: Optional[str] = Header(None)):
    """Delete a milestone."""
    verify_api_key(authorization)
    if not store.delete_milestone(milestone_id):
        raise HTTPException(status_code=404, detail="Milestone not found")
    return {"deleted": True, "milestone_id": milestone_id}


# ── Respondent Profile & History Endpoints ──


@app.get("/v1/respondent-profiles")
async def list_respondent_profiles(limit: int = 50, authorization: Optional[str] = Header(None)):
    """List all respondents with summary metrics."""
    verify_api_key(authorization)
    return store.list_respondent_profiles(limit=limit)


@app.get("/v1/respondent-profiles/{respondent_entity}")
async def get_respondent_profile(respondent_entity: str, authorization: Optional[str] = Header(None)):
    """Get detailed profile for a respondent."""
    verify_api_key(authorization)
    return store.get_respondent_profile(respondent_entity)


@app.get("/v1/respondent-profiles/{respondent_entity}/timeline")
async def respondent_timeline(respondent_entity: str, authorization: Optional[str] = Header(None)):
    """Get chronological activity timeline for a respondent."""
    verify_api_key(authorization)
    return store.get_respondent_timeline(respondent_entity)


# ── Correspondence & Communication Log Endpoints ──


@app.get("/v1/correspondence/stats")
async def correspondence_stats(authorization: Optional[str] = Header(None)):
    """Get correspondence statistics overview."""
    verify_api_key(authorization)
    return store.get_correspondence_stats()


@app.get("/v1/correspondence/channels")
async def correspondence_channels(authorization: Optional[str] = Header(None)):
    """List available correspondence channels and statuses."""
    verify_api_key(authorization)
    return {"channels": store.CORR_CHANNELS, "statuses": store.CORR_STATUSES,
            "directions": store.CORR_DIRECTIONS}


@app.get("/v1/correspondence/messages")
async def list_correspondence(
    claim_id: Optional[str] = None,
    direction: Optional[str] = None,
    channel: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """List correspondence messages with filters."""
    verify_api_key(authorization)
    return store.list_correspondence(claim_id=claim_id, direction=direction,
                                     channel=channel, status=status, limit=limit)


@app.post("/v1/correspondence/messages")
async def create_correspondence(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new correspondence message."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id", "").strip()
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    return store.create_correspondence(
        claim_id=claim_id,
        direction=body.get("direction", "outbound"),
        channel=body.get("channel", "email"),
        subject=body.get("subject", ""),
        body=body.get("body", ""),
        sender=body.get("sender", ""),
        recipient=body.get("recipient", ""),
        status=body.get("status", "draft"),
        priority=body.get("priority", "normal"),
        template_used=body.get("template_used"),
        related_to=body.get("related_to"),
        created_by=body.get("created_by", "operator"),
    )


@app.get("/v1/correspondence/messages/{message_id}")
async def get_correspondence(message_id: str, authorization: Optional[str] = Header(None)):
    """Get a single correspondence message."""
    verify_api_key(authorization)
    return store.get_correspondence(message_id)


@app.patch("/v1/correspondence/messages/{message_id}")
async def update_correspondence(message_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a correspondence message."""
    verify_api_key(authorization)
    body = await request.json()
    return store.update_correspondence(message_id, body)


@app.delete("/v1/correspondence/messages/{message_id}")
async def delete_correspondence(message_id: str, authorization: Optional[str] = Header(None)):
    """Delete a draft correspondence message."""
    verify_api_key(authorization)
    return store.delete_correspondence(message_id)


@app.post("/v1/correspondence/messages/{message_id}/send")
async def send_correspondence(message_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Mark a correspondence message as sent."""
    verify_api_key(authorization)
    body = await request.json()
    return store.send_correspondence(message_id, sent_by=body.get("sent_by", "operator"))


@app.get("/v1/correspondence/claim/{claim_id}")
async def claim_correspondence(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get full correspondence timeline for a claim."""
    verify_api_key(authorization)
    return store.get_claim_correspondence(claim_id)


# ── Compliance & Regulatory Framework Endpoints ──


@app.get("/v1/compliance/stats")
async def compliance_stats(authorization: Optional[str] = Header(None)):
    """Get compliance statistics overview."""
    verify_api_key(authorization)
    return store.get_compliance_stats()


@app.get("/v1/compliance/categories")
async def compliance_categories(authorization: Optional[str] = Header(None)):
    """List compliance categories."""
    verify_api_key(authorization)
    return {"categories": store.COMPLIANCE_CATEGORIES,
            "severities": store.COMPLIANCE_SEVERITIES,
            "jurisdictions": store.COMPLIANCE_JURISDICTIONS}


@app.get("/v1/compliance/overdue")
async def compliance_overdue(authorization: Optional[str] = Header(None)):
    """Get overdue compliance checks."""
    verify_api_key(authorization)
    return store.get_overdue_checks()


@app.get("/v1/compliance/rules")
async def list_compliance_rules(
    category: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    status: Optional[str] = "active",
    authorization: Optional[str] = Header(None),
):
    """List compliance rules with optional filters."""
    verify_api_key(authorization)
    return store.list_compliance_rules(category=category, jurisdiction=jurisdiction, status=status)


@app.post("/v1/compliance/rules")
async def create_compliance_rule(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new compliance rule."""
    verify_api_key(authorization)
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    return store.create_compliance_rule(
        name=name,
        description=body.get("description", ""),
        category=body.get("category", "general"),
        jurisdiction=body.get("jurisdiction", "global"),
        applies_to=body.get("applies_to", "all_claims"),
        conditions=body.get("conditions", {}),
        deadline_days=body.get("deadline_days"),
        severity=body.get("severity", "medium"),
        auto_flag=body.get("auto_flag", False),
        created_by=body.get("created_by", "operator"),
    )


@app.get("/v1/compliance/rules/{rule_id}")
async def get_compliance_rule(rule_id: str, authorization: Optional[str] = Header(None)):
    """Get a single compliance rule."""
    verify_api_key(authorization)
    return store.get_compliance_rule(rule_id)


@app.patch("/v1/compliance/rules/{rule_id}")
async def update_compliance_rule(rule_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a compliance rule."""
    verify_api_key(authorization)
    body = await request.json()
    return store.update_compliance_rule(rule_id, body)


@app.delete("/v1/compliance/rules/{rule_id}")
async def delete_compliance_rule(rule_id: str, authorization: Optional[str] = Header(None)):
    """Soft-delete a compliance rule."""
    verify_api_key(authorization)
    return store.delete_compliance_rule(rule_id)


@app.post("/v1/compliance/check/{claim_id}")
async def run_compliance_check(claim_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Run compliance checks against a claim."""
    verify_api_key(authorization)
    body = await request.json()
    return store.run_compliance_check(
        claim_id=claim_id,
        rule_ids=body.get("rule_ids"),
        checked_by=body.get("checked_by", "system"),
    )


@app.get("/v1/compliance/claim/{claim_id}")
async def get_claim_compliance(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all compliance checks for a claim."""
    verify_api_key(authorization)
    return store.get_claim_compliance(claim_id)


@app.patch("/v1/compliance/checks/{check_id}")
async def resolve_compliance_check(check_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Resolve a compliance check (pass/fail/waived)."""
    verify_api_key(authorization)
    body = await request.json()
    status = body.get("status", "").strip()
    if not status:
        raise HTTPException(status_code=400, detail="status is required")
    return store.resolve_compliance_check(
        check_id=check_id,
        status=status,
        notes=body.get("notes", ""),
        resolved_by=body.get("resolved_by", "operator"),
    )


# ── Knowledge Base & SOPs Endpoints ──


@app.get("/v1/kb/stats")
async def kb_stats(authorization: Optional[str] = Header(None)):
    """Knowledge base statistics."""
    verify_api_key(authorization)
    return store.get_kb_stats()


@app.get("/v1/kb/categories")
async def kb_categories(authorization: Optional[str] = Header(None)):
    """List KB categories."""
    verify_api_key(authorization)
    return {"categories": store.KB_CATEGORIES}


@app.get("/v1/kb/search")
async def kb_search(q: str = "", authorization: Optional[str] = Header(None)):
    """Search knowledge base articles."""
    verify_api_key(authorization)
    if not q.strip():
        raise HTTPException(status_code=400, detail="Search query 'q' is required")
    return store.list_articles(search_query=q.strip())


@app.get("/v1/kb/articles")
async def list_kb_articles(
    category: Optional[str] = None,
    status: Optional[str] = "published",
    authorization: Optional[str] = Header(None),
):
    """List knowledge base articles."""
    verify_api_key(authorization)
    return store.list_articles(category=category, status=status)


@app.post("/v1/kb/articles")
async def create_kb_article(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new knowledge base article."""
    verify_api_key(authorization)
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    content = body.get("content", "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="content is required")
    return store.create_article(
        title=title, content=content,
        category=body.get("category", "general"),
        tags=body.get("tags", []),
        author=body.get("author", "operator"),
        priority=body.get("priority", 0),
    )


@app.get("/v1/kb/articles/{article_id}")
async def get_kb_article(article_id: str, authorization: Optional[str] = Header(None)):
    """Get a single KB article (increments view count)."""
    verify_api_key(authorization)
    result = store.get_article(article_id)
    if not result:
        raise HTTPException(status_code=404, detail="Article not found")
    return result


@app.patch("/v1/kb/articles/{article_id}")
async def update_kb_article(article_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a KB article."""
    verify_api_key(authorization)
    body = await request.json()
    try:
        return store.update_article(article_id, body)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/v1/kb/articles/{article_id}")
async def delete_kb_article(article_id: str, authorization: Optional[str] = Header(None)):
    """Delete a KB article."""
    verify_api_key(authorization)
    if not store.delete_article(article_id):
        raise HTTPException(status_code=404, detail="Article not found")
    return {"deleted": True, "article_id": article_id}


@app.post("/v1/kb/articles/{article_id}/vote")
async def vote_kb_article(article_id: str, authorization: Optional[str] = Header(None)):
    """Upvote an article as helpful."""
    verify_api_key(authorization)
    try:
        return store.vote_article(article_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Claim Templates Endpoints ──


@app.get("/v1/templates/stats")
async def template_stats(authorization: Optional[str] = Header(None)):
    """Claim template statistics."""
    verify_api_key(authorization)
    return store.get_template_stats()


@app.get("/v1/templates/categories")
async def template_categories(authorization: Optional[str] = Header(None)):
    """List available template categories."""
    verify_api_key(authorization)
    return {"categories": store.TEMPLATE_CATEGORIES}


@app.get("/v1/templates")
async def list_templates(
    category: Optional[str] = None,
    active_only: Optional[bool] = True,
    authorization: Optional[str] = Header(None),
):
    """List claim templates."""
    verify_api_key(authorization)
    return store.list_templates(category=category, active_only=active_only)


@app.post("/v1/templates")
async def create_template(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new claim template."""
    verify_api_key(authorization)
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    return store.create_template(
        name=name,
        category=body.get("category", "general"),
        vertical=body.get("vertical", "platform_dispute"),
        harm_type=body.get("harm_type", ""),
        description=body.get("description", ""),
        default_fields=body.get("default_fields", {}),
        field_prompts=body.get("field_prompts", {}),
        created_by=body.get("created_by", "operator"),
    )


@app.get("/v1/templates/{template_id}")
async def get_template(template_id: str, authorization: Optional[str] = Header(None)):
    """Get a single claim template."""
    verify_api_key(authorization)
    result = store.get_template(template_id)
    if not result:
        raise HTTPException(status_code=404, detail="Template not found")
    return result


@app.patch("/v1/templates/{template_id}")
async def update_template(template_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a claim template."""
    verify_api_key(authorization)
    body = await request.json()
    try:
        return store.update_template(template_id, body)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/v1/templates/{template_id}")
async def delete_template(template_id: str, authorization: Optional[str] = Header(None)):
    """Delete a claim template."""
    verify_api_key(authorization)
    if not store.delete_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found")
    return {"deleted": True, "template_id": template_id}


@app.post("/v1/templates/{template_id}/instantiate")
async def instantiate_template(template_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Create a new claim from a template."""
    verify_api_key(authorization)
    body = await request.json()
    overrides = body.get("overrides", {})
    try:
        return store.instantiate_template(template_id, overrides=overrides)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Reminders & Follow-up Scheduler Endpoints ──


@app.get("/v1/reminders/stats")
async def reminder_stats(authorization: Optional[str] = Header(None)):
    """Reminder system dashboard statistics."""
    verify_api_key(authorization)
    return store.get_reminder_stats()


@app.get("/v1/reminders/due")
async def due_reminders(
    hours: int = 24,
    authorization: Optional[str] = Header(None),
):
    """Get overdue and upcoming reminders."""
    verify_api_key(authorization)
    return store.get_due_reminders(look_ahead_hours=hours)


@app.post("/v1/reminders/generate-idle")
async def generate_idle_reminders(request: Request, authorization: Optional[str] = Header(None)):
    """Auto-generate reminders for idle claims."""
    verify_api_key(authorization)
    body = await request.json()
    idle_days = body.get("idle_days", 14)
    return store.generate_idle_reminders(idle_days=idle_days)


@app.get("/v1/reminders")
async def list_reminders(
    status_filter: Optional[str] = None,
    claim_id: Optional[str] = None,
    assigned_to: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List reminders with optional filters."""
    verify_api_key(authorization)
    return store.list_reminders(status_filter=status_filter, claim_id=claim_id, assigned_to=assigned_to)


@app.post("/v1/reminders")
async def create_reminder(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new reminder."""
    verify_api_key(authorization)
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    due_at = body.get("due_at", "")
    if not due_at:
        raise HTTPException(status_code=400, detail="due_at is required")
    return store.create_reminder(
        title=title, due_at=due_at,
        claim_id=body.get("claim_id"),
        description=body.get("description", ""),
        reminder_type=body.get("reminder_type", "manual"),
        priority=body.get("priority", "normal"),
        assigned_to=body.get("assigned_to", "operator"),
        created_by=body.get("created_by", "operator"),
        recurrence=body.get("recurrence"),
    )


@app.get("/v1/reminders/{reminder_id}")
async def get_reminder(reminder_id: str, authorization: Optional[str] = Header(None)):
    """Get a single reminder."""
    verify_api_key(authorization)
    result = store.get_reminder(reminder_id)
    if not result:
        raise HTTPException(status_code=404, detail="Reminder not found")
    return result


@app.patch("/v1/reminders/{reminder_id}")
async def update_reminder(reminder_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a reminder."""
    verify_api_key(authorization)
    body = await request.json()
    try:
        return store.update_reminder(reminder_id, body)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/v1/reminders/{reminder_id}/complete")
async def complete_reminder(reminder_id: str, authorization: Optional[str] = Header(None)):
    """Mark a reminder as completed."""
    verify_api_key(authorization)
    try:
        return store.complete_reminder(reminder_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/v1/reminders/{reminder_id}/snooze")
async def snooze_reminder(reminder_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Snooze a reminder until a future time."""
    verify_api_key(authorization)
    body = await request.json()
    snooze_until = body.get("snooze_until", "")
    if not snooze_until:
        raise HTTPException(status_code=400, detail="snooze_until is required")
    try:
        return store.snooze_reminder(reminder_id, snooze_until)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/v1/reminders/{reminder_id}/dismiss")
async def dismiss_reminder(reminder_id: str, authorization: Optional[str] = Header(None)):
    """Dismiss a reminder."""
    verify_api_key(authorization)
    if not store.dismiss_reminder(reminder_id):
        raise HTTPException(status_code=404, detail="Reminder not found")
    return {"dismissed": True, "reminder_id": reminder_id}


# ── Saved Searches & Smart Filters Endpoints ──


@app.get("/v1/saved-searches")
async def list_saved_searches(
    created_by: Optional[str] = None,
    pinned_only: Optional[bool] = False,
    authorization: Optional[str] = Header(None),
):
    """List all saved searches."""
    verify_api_key(authorization)
    return store.list_saved_searches(created_by=created_by, pinned_only=pinned_only)


@app.post("/v1/saved-searches")
async def create_saved_search(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new saved search."""
    verify_api_key(authorization)
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    filters = body.get("filters", {})
    description = body.get("description", "")
    sort_by = body.get("sort_by", "filed_at")
    sort_order = body.get("sort_order", "desc")
    created_by = body.get("created_by", "operator")
    return store.create_saved_search(
        name=name, filters=filters, description=description,
        sort_by=sort_by, sort_order=sort_order, created_by=created_by,
    )


@app.get("/v1/saved-searches/{search_id}")
async def get_saved_search(search_id: str, authorization: Optional[str] = Header(None)):
    """Get a single saved search."""
    verify_api_key(authorization)
    result = store.get_saved_search(search_id)
    if not result:
        raise HTTPException(status_code=404, detail="Saved search not found")
    return result


@app.patch("/v1/saved-searches/{search_id}")
async def update_saved_search(search_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a saved search."""
    verify_api_key(authorization)
    body = await request.json()
    try:
        return store.update_saved_search(search_id, body)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/v1/saved-searches/{search_id}")
async def delete_saved_search(search_id: str, authorization: Optional[str] = Header(None)):
    """Delete a saved search."""
    verify_api_key(authorization)
    if not store.delete_saved_search(search_id):
        raise HTTPException(status_code=404, detail="Saved search not found")
    return {"deleted": True, "search_id": search_id}


@app.post("/v1/saved-searches/{search_id}/execute")
async def execute_saved_search(search_id: str, authorization: Optional[str] = Header(None)):
    """Execute a saved search and return matching claims."""
    verify_api_key(authorization)
    try:
        return store.execute_saved_search(search_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/v1/saved-searches/{search_id}/pin")
async def toggle_pin_saved_search(search_id: str, authorization: Optional[str] = Header(None)):
    """Toggle pin status of a saved search."""
    verify_api_key(authorization)
    try:
        return store.toggle_pin_saved_search(search_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Webhook & Integration Endpoints ──


@app.get("/v1/webhooks/stats")
async def webhook_stats(authorization: Optional[str] = Header(None)):
    """Webhook system statistics."""
    verify_api_key(authorization)
    return store.get_webhook_stats()


@app.get("/v1/webhooks/events")
async def webhook_events(authorization: Optional[str] = Header(None)):
    """List all supported webhook event types."""
    verify_api_key(authorization)
    return {"events": store.WEBHOOK_EVENTS}


@app.get("/v1/webhooks")
async def list_webhooks(
    status: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List all registered webhooks."""
    verify_api_key(authorization)
    hooks = store.list_webhooks(status=status)
    return {"webhooks": hooks, "total": len(hooks)}


@app.post("/v1/webhooks")
async def register_webhook(request: Request, authorization: Optional[str] = Header(None)):
    """Register a new webhook endpoint."""
    verify_api_key(authorization)
    body = await request.json()
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(400, "url is required")
    events = body.get("events", ["*"])
    secret = body.get("secret", "")
    description = body.get("description", "")
    created_by = body.get("created_by", "operator")
    result = store.register_webhook(url, events, secret, description, created_by)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@app.get("/v1/webhooks/{webhook_id}")
async def get_webhook(webhook_id: str, authorization: Optional[str] = Header(None)):
    """Get a specific webhook."""
    verify_api_key(authorization)
    wh = store.get_webhook(webhook_id)
    if not wh:
        raise HTTPException(404, "Webhook not found")
    return wh


@app.patch("/v1/webhooks/{webhook_id}")
async def update_webhook(webhook_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update webhook configuration."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.update_webhook(webhook_id, body)
    if isinstance(result, dict) and result.get("error"):
        raise HTTPException(404, result["error"])
    return result


@app.delete("/v1/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, authorization: Optional[str] = Header(None)):
    """Delete a webhook."""
    verify_api_key(authorization)
    result = store.delete_webhook(webhook_id)
    if result.get("error"):
        raise HTTPException(404, result["error"])
    return result


@app.post("/v1/webhooks/test")
async def test_webhook(request: Request, authorization: Optional[str] = Header(None)):
    """Fire a test event to all active webhooks (or a specific one)."""
    verify_api_key(authorization)
    body = await request.json()
    webhook_id = body.get("webhook_id")
    event = body.get("event", "test.ping")
    payload = body.get("payload", {"message": "Test webhook delivery"})
    result = store.fire_webhooks(event, payload)
    return result


@app.get("/v1/webhooks/{webhook_id}/deliveries")
async def webhook_deliveries(
    webhook_id: str,
    event: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """Get delivery history for a webhook."""
    verify_api_key(authorization)
    deliveries = store.get_webhook_deliveries(webhook_id=webhook_id, event=event, limit=limit)
    return {"deliveries": deliveries, "total": len(deliveries)}


# ── Bulk Operations Endpoints ──


@app.post("/v1/bulk/status")
async def bulk_status_update(request: Request, authorization: Optional[str] = Header(None)):
    """Bulk update status for multiple claims."""
    verify_api_key(authorization)
    body = await request.json()
    claim_ids = body.get("claim_ids", [])
    new_status = body.get("status", "").strip()
    if not claim_ids:
        raise HTTPException(400, "claim_ids array is required")
    if not new_status:
        raise HTTPException(400, "status is required")
    performed_by = body.get("performed_by", "operator")
    result = store.bulk_update_status(claim_ids, new_status, performed_by)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@app.post("/v1/bulk/assign")
async def bulk_assign(request: Request, authorization: Optional[str] = Header(None)):
    """Bulk assign multiple claims to an operator."""
    verify_api_key(authorization)
    body = await request.json()
    claim_ids = body.get("claim_ids", [])
    operator_id = body.get("operator_id", "").strip()
    if not claim_ids:
        raise HTTPException(400, "claim_ids array is required")
    if not operator_id:
        raise HTTPException(400, "operator_id is required")
    performed_by = body.get("performed_by", "operator")
    return store.bulk_assign(claim_ids, operator_id, performed_by)


@app.post("/v1/bulk/tag")
async def bulk_tag(request: Request, authorization: Optional[str] = Header(None)):
    """Bulk apply a tag to multiple claims."""
    verify_api_key(authorization)
    body = await request.json()
    claim_ids = body.get("claim_ids", [])
    tag_name = body.get("tag_name", "").strip()
    if not claim_ids:
        raise HTTPException(400, "claim_ids array is required")
    if not tag_name:
        raise HTTPException(400, "tag_name is required")
    performed_by = body.get("performed_by", "operator")
    return store.bulk_tag(claim_ids, tag_name, performed_by)


@app.post("/v1/bulk/escalate")
async def bulk_escalate(request: Request, authorization: Optional[str] = Header(None)):
    """Bulk escalate multiple claims."""
    verify_api_key(authorization)
    body = await request.json()
    claim_ids = body.get("claim_ids", [])
    if not claim_ids:
        raise HTTPException(400, "claim_ids array is required")
    reason = body.get("reason", "")
    performed_by = body.get("performed_by", "operator")
    return store.bulk_escalate(claim_ids, reason, performed_by)


@app.post("/v1/bulk/export")
async def bulk_export(request: Request, authorization: Optional[str] = Header(None)):
    """Export claims as CSV data. Provide claim_ids or status_filter."""
    verify_api_key(authorization)
    body = await request.json()
    claim_ids = body.get("claim_ids", None)
    status_filter = body.get("status_filter", None)
    result = store.bulk_export_csv(claim_ids=claim_ids, status_filter=status_filter)
    return result


@app.get("/v1/bulk/history")
async def bulk_operations_history(authorization: Optional[str] = Header(None)):
    """Get history of recent bulk operations."""
    verify_api_key(authorization)
    return store.get_bulk_operations_summary()


# ── Claim Timeline & Activity Stream Endpoints ──


@app.get("/v1/claims/{claim_id}/timeline")
async def claim_timeline(
    claim_id: str,
    limit: int = 100,
    event_type: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """Unified chronological timeline for a single claim."""
    verify_api_key(authorization)
    result = store.get_claim_timeline(claim_id, limit=limit, event_type=event_type)
    if result.get("error") == "claim_not_found":
        raise HTTPException(404, "Claim not found")
    # Include full claim object for case detail drawer
    claim = store.get_claim(claim_id)
    if claim:
        result["claim"] = claim
    return result


@app.get("/v1/activity/feed")
async def global_activity_feed(
    limit: int = 50,
    event_type: Optional[str] = None,
    hours: int = 72,
    authorization: Optional[str] = Header(None),
):
    """Global activity feed across all claims."""
    verify_api_key(authorization)
    return store.get_global_activity_feed(limit=limit, event_type=event_type, hours=hours)


# ── Data Quality & Deduplication Endpoints ──


@app.post("/v1/data-quality/scan")
async def scan_duplicates(
    request: Request, authorization: Optional[str] = Header(None)
):
    """Scan all claims for potential duplicates using fuzzy matching."""
    verify_api_key(authorization)
    body = await request.json()
    threshold = float(body.get("threshold", 0.7))
    if threshold < 0.1 or threshold > 1.0:
        raise HTTPException(400, "threshold must be between 0.1 and 1.0")
    result = store.scan_duplicates(threshold=threshold)
    return result


@app.get("/v1/data-quality/duplicates")
async def list_duplicates(
    status: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """List detected duplicate pairs with enriched claim info."""
    verify_api_key(authorization)
    pairs = store.get_duplicate_pairs(status=status, limit=limit)
    return {"duplicate_pairs": pairs, "total": len(pairs)}


@app.patch("/v1/data-quality/duplicates/{pair_id}")
async def resolve_duplicate(
    pair_id: str, request: Request, authorization: Optional[str] = Header(None)
):
    """Resolve a duplicate pair: dismiss or confirm."""
    verify_api_key(authorization)
    body = await request.json()
    action = body.get("action", "")
    if action not in ("dismiss", "confirm"):
        raise HTTPException(400, "action must be 'dismiss' or 'confirm'")
    resolved_by = body.get("resolved_by", "operator")
    result = store.resolve_duplicate(pair_id, action, resolved_by)
    return result


@app.post("/v1/data-quality/merge")
async def merge_claims(
    request: Request, authorization: Optional[str] = Header(None)
):
    """Merge two claims: transfer all data from source into target, close source."""
    verify_api_key(authorization)
    body = await request.json()
    source_id = body.get("source_claim_id", "")
    target_id = body.get("target_claim_id", "")
    if not source_id or not target_id:
        raise HTTPException(400, "source_claim_id and target_claim_id required")
    if source_id == target_id:
        raise HTTPException(400, "source and target must be different claims")
    merged_by = body.get("merged_by", "operator")
    result = store.merge_claims(source_id, target_id, merged_by)
    return result


@app.get("/v1/data-quality/report")
async def data_quality_report(authorization: Optional[str] = Header(None)):
    """Comprehensive data quality report: completeness, duplicates, coverage."""
    verify_api_key(authorization)
    report = store.get_data_quality_report()
    return report


@app.get("/v1/data-quality/merge-history")
async def merge_history(
    limit: int = 50, authorization: Optional[str] = Header(None)
):
    """List merge history records."""
    verify_api_key(authorization)
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM merge_history ORDER BY merged_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return {"merges": [dict(r) for r in rows], "total": len(rows)}


# ── Tags & Custom Fields Endpoints ──


@app.get("/v1/tags/stats")
async def tag_stats(authorization: Optional[str] = Header(None)):
    """Tag usage statistics: total tags, coverage, top tags by usage."""
    verify_api_key(authorization)
    return store.get_tag_stats()


@app.get("/v1/tags")
async def list_tags(
    category: Optional[str] = None,
    search: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """List all tags, optionally filtered by category or search term."""
    verify_api_key(authorization)
    return {"tags": store.list_tags(category=category, search=search)}


@app.post("/v1/tags")
async def create_tag(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """Create a new tag. Body: {name, color?, category?, description?}"""
    verify_api_key(authorization)
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Tag name is required")
    result = store.create_tag(
        name=name,
        color=body.get("color", "#58a6ff"),
        category=body.get("category", "general"),
        description=body.get("description", ""),
        created_by=body.get("created_by", "operator"),
    )
    if "error" in result:
        raise HTTPException(status_code=409, detail=result["error"])
    return result


@app.patch("/v1/tags/{tag_id}")
async def update_tag(
    tag_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """Update a tag's name, color, category, or description."""
    verify_api_key(authorization)
    result = store.update_tag(tag_id, body)
    if not result:
        raise HTTPException(status_code=404, detail="Tag not found")
    return result


@app.delete("/v1/tags/{tag_id}")
async def delete_tag(
    tag_id: str,
    authorization: Optional[str] = Header(None),
):
    """Delete a tag and remove all claim associations."""
    verify_api_key(authorization)
    if not store.delete_tag(tag_id):
        raise HTTPException(status_code=404, detail="Tag not found")
    return {"status": "deleted", "tag_id": tag_id}


@app.post("/v1/claims/{claim_id}/tags")
async def tag_claim(
    claim_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """Add a tag to a claim. Body: {tag_id} or {tag_name} (auto-creates if needed)."""
    verify_api_key(authorization)
    tag_id = body.get("tag_id")
    tag_name = body.get("tag_name", "").strip()

    if not tag_id and tag_name:
        # Auto-create or find existing tag
        existing = store.list_tags(search=tag_name)
        exact = [t for t in existing if t["name"].lower() == tag_name.lower()]
        if exact:
            tag_id = exact[0]["tag_id"]
        else:
            new_tag = store.create_tag(name=tag_name, color=body.get("color", "#58a6ff"),
                                        category=body.get("category", "general"))
            tag_id = new_tag.get("tag_id")

    if not tag_id:
        raise HTTPException(status_code=400, detail="tag_id or tag_name is required")

    result = store.tag_claim(claim_id, tag_id, tagged_by=body.get("tagged_by", "operator"))
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.delete("/v1/claims/{claim_id}/tags/{tag_id}")
async def untag_claim(
    claim_id: str,
    tag_id: str,
    authorization: Optional[str] = Header(None),
):
    """Remove a tag from a claim."""
    verify_api_key(authorization)
    if not store.untag_claim(claim_id, tag_id):
        raise HTTPException(status_code=404, detail="Tag association not found")
    return {"status": "untagged", "claim_id": claim_id, "tag_id": tag_id}


@app.get("/v1/claims/{claim_id}/tags")
async def get_claim_tags(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get all tags for a claim."""
    verify_api_key(authorization)
    return {"claim_id": claim_id, "tags": store.get_claim_tags(claim_id)}


@app.get("/v1/tags/{tag_id}/claims")
async def get_tagged_claims(
    tag_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get all claim IDs with a specific tag."""
    verify_api_key(authorization)
    return {"tag_id": tag_id, "claim_ids": store.get_claims_by_tag(tag_id)}


# Custom Fields endpoints
@app.get("/v1/custom-fields")
async def list_custom_fields(authorization: Optional[str] = Header(None)):
    """List all custom field definitions."""
    verify_api_key(authorization)
    return {"fields": store.list_custom_fields()}


@app.post("/v1/custom-fields")
async def create_custom_field(
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """Create a custom field. Body: {name, field_type?, description?, options?, required?}"""
    verify_api_key(authorization)
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Field name is required")
    result = store.create_custom_field(
        name=name,
        field_type=body.get("field_type", "text"),
        description=body.get("description", ""),
        options=body.get("options"),
        required=body.get("required", False),
    )
    if "error" in result:
        raise HTTPException(status_code=409, detail=result["error"])
    return result


@app.delete("/v1/custom-fields/{field_id}")
async def delete_custom_field(
    field_id: str,
    authorization: Optional[str] = Header(None),
):
    """Delete a custom field and all its values."""
    verify_api_key(authorization)
    if not store.delete_custom_field(field_id):
        raise HTTPException(status_code=404, detail="Field not found")
    return {"status": "deleted", "field_id": field_id}


@app.post("/v1/claims/{claim_id}/custom-fields")
async def set_claim_custom_value(
    claim_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """Set a custom field value for a claim. Body: {field_id, value}"""
    verify_api_key(authorization)
    field_id = body.get("field_id", "")
    value = body.get("value", "")
    if not field_id:
        raise HTTPException(status_code=400, detail="field_id is required")
    result = store.set_claim_custom_value(claim_id, field_id, value)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/v1/claims/{claim_id}/custom-fields")
async def get_claim_custom_values(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get all custom field values for a claim."""
    verify_api_key(authorization)
    return {"claim_id": claim_id, "fields": store.get_claim_custom_values(claim_id)}


# ── Priority Queue & Smart Triage Endpoints ──


@app.get("/v1/triage/queue")
async def triage_queue(
    limit: int = 50,
    triage_level: Optional[str] = None,
    status: Optional[str] = None,
    operator_id: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """
    Smart priority queue: all active claims ranked by composite priority score.
    Filter by triage_level (critical/high/medium/low/minimal), status, or operator_id.
    """
    verify_api_key(authorization)
    return store.get_priority_queue(limit=limit, triage_level=triage_level,
                                     status=status, operator_id=operator_id)


@app.get("/v1/triage/summary")
async def triage_summary(
    authorization: Optional[str] = Header(None),
):
    """Triage overview: active claims, overrides, recent actions."""
    verify_api_key(authorization)
    return store.get_triage_summary()


@app.get("/v1/claims/{claim_id}/priority")
async def claim_priority_score(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Compute priority score breakdown for a single claim."""
    verify_api_key(authorization)
    result = store.compute_priority_score(claim_id)
    if not result:
        raise HTTPException(status_code=404, detail="Claim not found")
    return result


@app.post("/v1/claims/{claim_id}/triage")
async def record_triage_action(
    claim_id: str,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
):
    """
    Record a triage action — priority override, manual escalation, etc.
    Body: {"action_type": "priority_override", "new_value": "95", "reason": "VIP claimant"}
    """
    verify_api_key(authorization)
    action_type = body.get("action_type", "priority_override")
    new_value = str(body.get("new_value", ""))
    reason = body.get("reason", "")
    performed_by = body.get("performed_by", "operator")

    if not new_value:
        raise HTTPException(status_code=400, detail="new_value is required")

    result = store.triage_action(claim_id, action_type, new_value, reason, performed_by)
    if not result:
        raise HTTPException(status_code=404, detail="Claim not found")
    return result


@app.get("/v1/claims/{claim_id}/triage/history")
async def claim_triage_history(
    claim_id: str,
    authorization: Optional[str] = Header(None),
):
    """Get triage action history for a claim."""
    verify_api_key(authorization)
    return {"claim_id": claim_id, "actions": store.get_triage_history(claim_id)}


# ── Advanced Analytics & Performance Endpoints ──


@app.get("/v1/analytics/operators")
async def analytics_operator_performance(
    operator_id: Optional[str] = None,
    days: int = 90,
    authorization: Optional[str] = Header(None),
):
    """
    Operator performance KPIs: resolution rate, average handle time, recovery effectiveness,
    efficiency score, and team rankings.
    """
    verify_api_key(authorization)
    return store.get_operator_performance(operator_id=operator_id, days=days)


@app.get("/v1/analytics/respondent-scorecards")
async def analytics_respondent_scorecards(
    limit: int = 20,
    authorization: Optional[str] = Header(None),
):
    """
    Respondent behavior scorecards: cooperation score, settlement acceptance rate,
    recovery rate, and overall rating (cooperative / mixed / uncooperative).
    """
    verify_api_key(authorization)
    return store.get_respondent_scorecards(limit=limit)


@app.get("/v1/analytics/pipeline")
async def analytics_pipeline_funnel(
    authorization: Optional[str] = Header(None),
):
    """
    Pipeline funnel showing claims at each status stage,
    with conversion rates between stages.
    """
    verify_api_key(authorization)
    return store.get_pipeline_funnel()


@app.get("/v1/analytics/trends")
async def analytics_trends(
    days: int = 30,
    granularity: str = "day",
    authorization: Optional[str] = Header(None),
):
    """
    Time-series trends: claims filed, recoveries, and resolutions over time.
    Granularity: day, week, or month.
    """
    verify_api_key(authorization)
    if granularity not in ("day", "week", "month"):
        granularity = "day"
    return store.get_trend_analytics(days=days, granularity=granularity)


@app.get("/v1/analytics/financial")
async def analytics_financial(
    authorization: Optional[str] = Header(None),
):
    """
    Financial overview: total claimed vs recovered, by recovery method,
    top exposure respondents, and projected recovery.
    """
    verify_api_key(authorization)
    return store.get_financial_summary()


@app.get("/v1/analytics/health-score")
async def analytics_health_score(
    authorization: Optional[str] = Header(None),
):
    """
    Composite platform health score (0-100) with grade (A-F),
    based on resolution rate, recovery effectiveness, SLA compliance,
    assignment coverage, and documentation rate.
    """
    verify_api_key(authorization)
    return store.get_platform_health_score()


@app.get("/v1/analytics/overview")
async def analytics_overview(
    authorization: Optional[str] = Header(None),
):
    """
    Combined analytics overview — all analytics modules in one call.
    """
    verify_api_key(authorization)
    return {
        "health": store.get_platform_health_score(),
        "financial": store.get_financial_summary(),
        "pipeline": store.get_pipeline_funnel(),
        "operator_summary": {
            k: v for k, v in store.get_operator_performance(days=90).items()
            if k != "operators"
        },
        "top_respondents": store.get_respondent_scorecards(limit=5),
    }


# ── Feature #43: Claimant Satisfaction Surveys ──


@app.get("/v1/surveys/stats")
async def survey_stats(authorization: Optional[str] = Header(None)):
    """Get overall satisfaction survey statistics, NPS score, and trends."""
    verify_api_key(authorization)
    return store.get_survey_stats()


@app.get("/v1/surveys")
async def list_surveys(
    claim_id: Optional[str] = None,
    status: Optional[str] = None,
    trigger_event: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """List satisfaction surveys with optional filters."""
    verify_api_key(authorization)
    return store.list_surveys(claim_id=claim_id, status=status,
                              trigger_event=trigger_event, limit=limit)


@app.post("/v1/surveys")
async def create_survey(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new satisfaction survey for a claim."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id")
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    return store.create_survey(
        claim_id=claim_id,
        trigger_event=body.get("trigger_event", "manual"),
        claimant_email=body.get("claimant_email"),
    )


@app.get("/v1/surveys/triggers")
async def survey_triggers(authorization: Optional[str] = Header(None)):
    """List available survey trigger events and statuses."""
    verify_api_key(authorization)
    return {
        "triggers": store.SURVEY_TRIGGERS,
        "statuses": store.SURVEY_STATUSES,
        "categories": store.SURVEY_CATEGORIES,
    }


@app.post("/v1/surveys/expire")
async def expire_surveys(authorization: Optional[str] = Header(None)):
    """Expire overdue pending/sent surveys past their expiration date."""
    verify_api_key(authorization)
    return store.expire_surveys()


@app.get("/v1/surveys/{survey_id}")
async def get_survey(survey_id: str, authorization: Optional[str] = Header(None)):
    """Get a single satisfaction survey."""
    verify_api_key(authorization)
    return store.get_survey(survey_id)


@app.post("/v1/surveys/{survey_id}/send")
async def send_survey(survey_id: str, authorization: Optional[str] = Header(None)):
    """Mark a survey as sent to the claimant."""
    verify_api_key(authorization)
    return store.send_survey(survey_id)


@app.post("/v1/surveys/{survey_id}/respond")
async def respond_to_survey(survey_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Submit a claimant's survey response (rating 1-5 + optional feedback)."""
    verify_api_key(authorization)
    body = await request.json()
    rating = body.get("rating")
    if rating is None:
        raise HTTPException(status_code=400, detail="rating (1-5) is required")
    return store.submit_survey_response(
        survey_id=survey_id,
        rating=int(rating),
        feedback_text=body.get("feedback_text", ""),
        categories=body.get("categories", []),
    )


@app.get("/v1/claims/{claim_id}/surveys")
async def claim_surveys(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all satisfaction surveys for a specific claim."""
    verify_api_key(authorization)
    return store.get_claim_surveys(claim_id)


# ── Feature #44: Escalation Playbooks ──


@app.get("/v1/playbooks/stats")
async def playbook_stats(authorization: Optional[str] = Header(None)):
    """Get playbook statistics and execution metrics."""
    verify_api_key(authorization)
    return store.get_playbook_stats()


@app.get("/v1/playbooks/triggers")
async def playbook_triggers(authorization: Optional[str] = Header(None)):
    """List available playbook trigger types and step types."""
    verify_api_key(authorization)
    return {
        "triggers": store.PLAYBOOK_TRIGGERS,
        "step_types": store.PLAYBOOK_STEP_TYPES,
        "statuses": store.PLAYBOOK_STATUSES,
    }


@app.get("/v1/playbooks")
async def list_playbooks(active_only: bool = False, authorization: Optional[str] = Header(None)):
    """List all escalation playbooks."""
    verify_api_key(authorization)
    return store.list_playbooks(active_only=active_only)


@app.post("/v1/playbooks")
async def create_playbook(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new escalation playbook."""
    verify_api_key(authorization)
    body = await request.json()
    name = body.get("name")
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    return store.create_playbook(
        name=name,
        description=body.get("description", ""),
        trigger_type=body.get("trigger_type", "manual"),
        trigger_config=body.get("trigger_config"),
        steps=body.get("steps"),
        cooldown_hours=body.get("cooldown_hours", 24),
        created_by=body.get("created_by", "operator"),
    )


@app.get("/v1/playbooks/executions")
async def list_executions(
    playbook_id: Optional[str] = None,
    claim_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    authorization: Optional[str] = Header(None),
):
    """List playbook executions with filters."""
    verify_api_key(authorization)
    return store.list_playbook_executions(playbook_id=playbook_id, claim_id=claim_id,
                                          status=status, limit=limit)


@app.get("/v1/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str, authorization: Optional[str] = Header(None)):
    """Get a single playbook with execution history."""
    verify_api_key(authorization)
    return store.get_playbook(playbook_id)


@app.patch("/v1/playbooks/{playbook_id}")
async def update_playbook(playbook_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a playbook's configuration."""
    verify_api_key(authorization)
    body = await request.json()
    return store.update_playbook(playbook_id, body)


@app.delete("/v1/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str, authorization: Optional[str] = Header(None)):
    """Delete a playbook."""
    verify_api_key(authorization)
    return store.delete_playbook(playbook_id)


@app.post("/v1/playbooks/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Execute a playbook against a specific claim."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id")
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    return store.execute_playbook(playbook_id, claim_id)


# ── Feature #45: Communication Channel Registry ──


@app.get("/v1/channels/stats")
async def channel_stats(authorization: Optional[str] = Header(None)):
    """Get channel registry statistics and effectiveness analytics."""
    verify_api_key(authorization)
    return store.get_channel_stats()


@app.get("/v1/channels/types")
async def channel_types(authorization: Optional[str] = Header(None)):
    """List available channel types and statuses."""
    verify_api_key(authorization)
    return {"types": store.CHANNEL_TYPES, "statuses": store.CHANNEL_STATUSES}


@app.get("/v1/channels")
async def list_channels(
    respondent_entity: Optional[str] = None,
    channel_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    authorization: Optional[str] = Header(None),
):
    """List communication channels with optional filters."""
    verify_api_key(authorization)
    return store.list_channels(respondent_entity=respondent_entity, channel_type=channel_type,
                               status=status, limit=limit)


@app.post("/v1/channels")
async def add_channel(request: Request, authorization: Optional[str] = Header(None)):
    """Register a new communication channel for a respondent."""
    verify_api_key(authorization)
    body = await request.json()
    respondent = body.get("respondent_entity")
    ch_type = body.get("channel_type")
    contact = body.get("contact_value")
    if not respondent or not ch_type or not contact:
        raise HTTPException(status_code=400, detail="respondent_entity, channel_type, and contact_value are required")
    return store.add_channel(
        respondent_entity=respondent, channel_type=ch_type, contact_value=contact,
        label=body.get("label", ""), is_primary=body.get("is_primary", False),
        notes=body.get("notes", ""),
    )


@app.get("/v1/channels/{channel_id}")
async def get_channel(channel_id: str, authorization: Optional[str] = Header(None)):
    """Get a single communication channel."""
    verify_api_key(authorization)
    return store.get_channel(channel_id)


@app.patch("/v1/channels/{channel_id}")
async def update_channel(channel_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a channel's properties."""
    verify_api_key(authorization)
    body = await request.json()
    return store.update_channel(channel_id, body)


@app.delete("/v1/channels/{channel_id}")
async def delete_channel(channel_id: str, authorization: Optional[str] = Header(None)):
    """Delete a communication channel."""
    verify_api_key(authorization)
    return store.delete_channel(channel_id)


@app.post("/v1/channels/{channel_id}/outcome")
async def record_outcome(channel_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Record a success or failure for a channel delivery."""
    verify_api_key(authorization)
    body = await request.json()
    success = body.get("success", True)
    return store.record_channel_outcome(channel_id, success=success)


@app.get("/v1/respondents/{respondent_entity}/channels")
async def respondent_channels(respondent_entity: str, authorization: Optional[str] = Header(None)):
    """Get all channels for a specific respondent with effectiveness metrics."""
    verify_api_key(authorization)
    return store.get_respondent_channels(respondent_entity)


# ── Feature #46: Fee & Billing Tracker Endpoints ──

@app.get("/v1/billing/stats")
async def billing_stats(authorization: Optional[str] = Header(None)):
    """Get billing/fee statistics across all claims."""
    verify_api_key(authorization)
    return store.get_billing_stats()


@app.get("/v1/billing/types")
async def billing_types(authorization: Optional[str] = Header(None)):
    """Get all billing entry types in use."""
    verify_api_key(authorization)
    return store.get_billing_types()


@app.get("/v1/billing")
async def list_billing(claim_id: str = None, status: str = None, entry_type: str = None,
                       limit: int = 100, offset: int = 0,
                       authorization: Optional[str] = Header(None)):
    """List billing entries with optional filters."""
    verify_api_key(authorization)
    return store.list_billing_entries(claim_id=claim_id, status=status, entry_type=entry_type, limit=limit, offset=offset)


@app.post("/v1/billing")
async def create_billing(request: Request, authorization: Optional[str] = Header(None)):
    """Create a new billing/fee entry for a claim."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id")
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    return store.create_billing_entry(
        claim_id=claim_id,
        entry_type=body.get("entry_type", "contingency_fee"),
        description=body.get("description", ""),
        amount_usd=float(body.get("amount_usd", 0)),
        fee_pct=body.get("fee_pct"),
        due_date=body.get("due_date"),
        notes=body.get("notes", ""),
        created_by=body.get("created_by", "system"),
    )


@app.get("/v1/billing/{entry_id}")
async def get_billing(entry_id: str, authorization: Optional[str] = Header(None)):
    """Get a specific billing entry."""
    verify_api_key(authorization)
    entry = store.get_billing_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Billing entry not found")
    return entry


@app.patch("/v1/billing/{entry_id}")
async def update_billing(entry_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a billing entry."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.update_billing_entry(entry_id, body)
    if result is None:
        raise HTTPException(status_code=404, detail="Billing entry not found")
    return result


@app.delete("/v1/billing/{entry_id}")
async def delete_billing(entry_id: str, authorization: Optional[str] = Header(None)):
    """Delete a billing entry."""
    verify_api_key(authorization)
    result = store.delete_billing_entry(entry_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Billing entry not found")
    return result


@app.post("/v1/billing/{entry_id}/pay")
async def pay_billing(entry_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Mark a billing entry as paid."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.mark_billing_paid(
        entry_id,
        payment_method=body.get("payment_method", ""),
        notes=body.get("notes", ""),
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Billing entry not found")
    return result


@app.post("/v1/billing/invoice/{claim_id}")
async def generate_invoice(claim_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Generate an invoice for pending billing entries on a claim."""
    verify_api_key(authorization)
    body = await request.json()
    entries = body.get("entries")
    return store.generate_invoice(claim_id, entries=entries)


# ── Feature #47: Claim Dependencies & Linked Cases Endpoints ──

@app.get("/v1/claim-links/stats")
async def claim_link_stats(authorization: Optional[str] = Header(None)):
    """Get statistics about claim links/dependencies."""
    verify_api_key(authorization)
    return store.get_link_stats()


@app.get("/v1/claim-links/types")
async def claim_link_types(authorization: Optional[str] = Header(None)):
    """Get available link types."""
    verify_api_key(authorization)
    return store.get_link_types()


@app.get("/v1/claim-links")
async def list_claim_links(claim_id: str = None, link_type: str = None,
                           limit: int = 100, offset: int = 0,
                           authorization: Optional[str] = Header(None)):
    """List claim links with optional filters."""
    verify_api_key(authorization)
    return store.list_claim_links(claim_id=claim_id, link_type=link_type, limit=limit, offset=offset)


@app.post("/v1/claim-links")
async def create_claim_link(request: Request, authorization: Optional[str] = Header(None)):
    """Create a link between two claims."""
    verify_api_key(authorization)
    body = await request.json()
    source = body.get("source_claim_id")
    target = body.get("target_claim_id")
    if not source or not target:
        raise HTTPException(status_code=400, detail="source_claim_id and target_claim_id are required")
    result = store.create_claim_link(
        source_claim_id=source,
        target_claim_id=target,
        link_type=body.get("link_type", "related"),
        description=body.get("description", ""),
        strength=float(body.get("strength", 1.0)),
        created_by=body.get("created_by", "system"),
    )
    if result.get("error"):
        raise HTTPException(status_code=409, detail=result["error"])
    return result


@app.get("/v1/claim-links/{link_id}")
async def get_claim_link(link_id: str, authorization: Optional[str] = Header(None)):
    """Get a specific claim link."""
    verify_api_key(authorization)
    link = store.get_claim_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Claim link not found")
    return link


@app.patch("/v1/claim-links/{link_id}")
async def update_claim_link(link_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update a claim link."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.update_claim_link(link_id, body)
    if result is None:
        raise HTTPException(status_code=404, detail="Claim link not found")
    return result


@app.delete("/v1/claim-links/{link_id}")
async def delete_claim_link(link_id: str, authorization: Optional[str] = Header(None)):
    """Delete a claim link."""
    verify_api_key(authorization)
    result = store.delete_claim_link(link_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Claim link not found")
    return result


@app.get("/v1/claims/{claim_id}/dependencies")
async def claim_dependencies(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get full dependency graph for a specific claim."""
    verify_api_key(authorization)
    return store.get_claim_dependencies(claim_id)


# ── Feature #48: Claim Evidence Vault Endpoints ──

@app.get("/v1/evidence/stats")
async def evidence_stats(authorization: Optional[str] = Header(None)):
    """Get evidence vault statistics."""
    verify_api_key(authorization)
    return store.get_evidence_stats()


@app.get("/v1/evidence/types")
async def evidence_types(authorization: Optional[str] = Header(None)):
    """Get available evidence types."""
    verify_api_key(authorization)
    return store.get_evidence_types()


@app.get("/v1/evidence")
async def list_evidence(claim_id: str = None, evidence_type: str = None,
                        verified: bool = None, status: str = None,
                        limit: int = 100, offset: int = 0,
                        authorization: Optional[str] = Header(None)):
    """List evidence items with optional filters."""
    verify_api_key(authorization)
    return store.list_evidence(claim_id=claim_id, evidence_type=evidence_type,
                               verified=verified, status=status, limit=limit, offset=offset)


@app.post("/v1/evidence")
async def add_evidence(request: Request, authorization: Optional[str] = Header(None)):
    """Add a new evidence item to the vault."""
    verify_api_key(authorization)
    body = await request.json()
    claim_id = body.get("claim_id")
    if not claim_id:
        raise HTTPException(status_code=400, detail="claim_id is required")
    return store.add_evidence(
        claim_id=claim_id,
        evidence_type=body.get("evidence_type", "document"),
        title=body.get("title", ""),
        description=body.get("description", ""),
        source_url=body.get("source_url", ""),
        file_hash=body.get("file_hash", ""),
        file_size_bytes=int(body.get("file_size_bytes", 0)),
        mime_type=body.get("mime_type", ""),
        tags=body.get("tags", []),
        uploaded_by=body.get("uploaded_by", "system"),
    )


@app.get("/v1/evidence/{evidence_id}")
async def get_evidence(evidence_id: str, authorization: Optional[str] = Header(None)):
    """Get a specific evidence item."""
    verify_api_key(authorization)
    item = store.get_evidence(evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return item


@app.patch("/v1/evidence/{evidence_id}")
async def update_evidence(evidence_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Update an evidence item."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.update_evidence(evidence_id, body)
    if result is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return result


@app.delete("/v1/evidence/{evidence_id}")
async def delete_evidence(evidence_id: str, authorization: Optional[str] = Header(None)):
    """Delete an evidence item."""
    verify_api_key(authorization)
    result = store.delete_evidence(evidence_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return result


@app.post("/v1/evidence/{evidence_id}/verify")
async def verify_evidence(evidence_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Verify an evidence item and update chain of custody."""
    verify_api_key(authorization)
    body = await request.json()
    result = store.verify_evidence(
        evidence_id,
        verified_by=body.get("verified_by", "operator"),
        notes=body.get("notes", ""),
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return result


@app.get("/v1/claims/{claim_id}/evidence")
async def claim_evidence(claim_id: str, authorization: Optional[str] = Header(None)):
    """Get all evidence items for a specific claim."""
    verify_api_key(authorization)
    return store.list_evidence(claim_id=claim_id)




# ── LITMUS Scoring Endpoints ──
@app.get("/v1/litmus/stats")
async def litmus_stats(authorization: Optional[str] = Header(None)):
    verify_api_key(authorization); return store.get_litmus_stats()

@app.post("/v1/litmus/score/{claim_id}")
async def score_claim_litmus(claim_id: str, request: Request, authorization: Optional[str] = Header(None)):
    verify_api_key(authorization)
    body={}
    try: body=await request.json()
    except: pass
    r=store.score_litmus(claim_id, scores=body if body else None)
    if r is None: raise HTTPException(status_code=404, detail="Claim not found")
    return r

@app.get("/v1/litmus/score/{claim_id}")
async def get_claim_litmus(claim_id: str, authorization: Optional[str] = Header(None)):
    verify_api_key(authorization)
    r=store.get_litmus_score(claim_id)
    if r is None: raise HTTPException(status_code=404, detail="No LITMUS score found")
    return r

@app.post("/v1/litmus/score-all")
async def score_all_litmus(authorization: Optional[str] = Header(None)):
    verify_api_key(authorization)
    conn=_get_db()
    scored={r[0] for r in conn.execute("SELECT DISTINCT claim_id FROM litmus_scores").fetchall()}
    all_ids=[r[0] for r in conn.execute("SELECT claim_id FROM claims").fetchall()]
    conn.close()
    res={"scored":0,"failed":0,"already_scored":len(scored)}
    for cid in all_ids:
        if cid in scored: continue
        try: store.score_litmus(cid); res["scored"]+=1
        except: res["failed"]+=1
    return res

@app.post("/v1/ilf/auto-route/{claim_id}")
async def auto_route(claim_id: str, authorization: Optional[str] = Header(None)):
    verify_api_key(authorization)
    r=store.auto_route_claim(claim_id)
    if "error" in r: raise HTTPException(status_code=404, detail=r["error"])
    return r

@app.post("/v1/ilf/auto-route-approve/{claim_id}")
async def approve_route(claim_id: str, request: Request, authorization: Optional[str] = Header(None)):
    verify_api_key(authorization); body=await request.json()
    lid=body.get("lawyer_id",""); consent=body.get("claimant_consent",False)
    if not lid: raise HTTPException(status_code=400, detail="lawyer_id required")
    if not consent: raise HTTPException(status_code=400, detail="Claimant consent required")
    claim=store.get_claim(claim_id)
    if not claim: raise HTTPException(status_code=404, detail="Claim not found")
    lawyer=store.get_lawyer(lid)
    if not lawyer: raise HTTPException(status_code=404, detail="Lawyer not found")
    rid=store.create_referral(claim_id, lid)
    conn=_get_db(); conn.execute("UPDATE ilf_referrals SET claimant_consent_at=?, consent_version='1.0' WHERE referral_id=?",(datetime.utcnow().isoformat(),rid)); conn.commit(); conn.close()
    try:
        cs=claim.get("status","filed")
        if cs in ("under_review","escalated"): store.transition_claim(claim_id,"awaiting_professional",actor="auto_route",reason=f"Referred to {lawyer['full_name']}")
    except: pass
    return {"referral_id":rid,"claim_id":claim_id,"lawyer_id":lid,"status":"awaiting_professional"}

@app.get("/v1/claims/{claim_id}/masked")
async def get_masked(claim_id: str, level: str = "standard", authorization: Optional[str] = Header(None)):
    verify_api_key(authorization)
    c=store.get_claim(claim_id)
    if not c: raise HTTPException(status_code=404, detail="Claim not found")
    return store.mask_pii(c, level=level)

@app.get("/v1/public/about")
async def public_about():
    return {"name":"GhostLedger","parent":"Internet Law Firm (ILF)","tagline":"Payment Recovery Coordination","doctrine":"We coordinate recovery, we do not promise outcomes, we do not hold your money, and we only win when you win.","what_we_are":["A case intake and triage system","A routing engine for lawyers and recovery specialists","A coordination layer for contingency-based legal work","A neutral marketplace infrastructure"],"what_we_are_not":["A law firm","A legal representative","A provider of legal advice","A guarantor of outcomes","A custodian of trust funds"],"principles":{"human_in_the_loop":"All legal actions performed by licensed professionals.","pay_on_success":"No upfront fees. Compensation only if recovery occurs.","non_custodial":"We do not hold settlement funds or touch client money."},"litmus_standard":{"L":"Lives in bear markets","I":"Independent of speculation","T":"Tolerates conflict","M":"Measures execution not promises","U":"Uncomfortable transparency","S":"Settles real-world consequences"},"fee_model":"No recovery, no fee.","disclaimer":"GhostLedger coordinates recovery efforts and does not provide legal advice or legal representation."}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8081))
    uvicorn.run(app, host="0.0.0.0", port=port)

# ═══════════════════════════════════════════════════════════════
# LICO — Legal Internet Traffic Control (Decision Layer)
# ═══════════════════════════════════════════════════════════════

@app.post("/v1/lico/decide")
async def lico_decide(body: dict, authorization: Optional[str] = Header(None)):
    """Record a LICO decision on a signal: monitor, dismiss, or escalate."""
    import uuid
    from datetime import datetime
    
    signal_key = body.get("signal_key", "")
    decision = body.get("decision", "")
    reason_code = body.get("reason_code", "")
    notes = body.get("notes", "")
    operator_id = body.get("operator_id", "operator")
    
    if not signal_key:
        raise HTTPException(400, "signal_key required")
    if decision not in ("monitor", "dismiss", "escalate"):
        raise HTTPException(400, "decision must be monitor, dismiss, or escalate")
    
    decision_id = "lico_" + uuid.uuid4().hex[:12]
    now = datetime.utcnow().isoformat()
    
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO lico_decisions (decision_id, signal_key, decision, reason_code, notes, operator_id, created_at) VALUES (?,?,?,?,?,?,?)",
        (decision_id, signal_key, decision, reason_code, notes, operator_id, now)
    )
    conn.commit()
    
    result = {"decision_id": decision_id, "signal_key": signal_key, "decision": decision}
    
    # If escalate → auto-create case group
    if decision == "escalate":
        group_result = _create_case_group_from_signal(conn, signal_key, operator_id)
        result["case_group"] = group_result
    
    conn.close()
    
    store.audit("lico.decision", {
        "decision_id": decision_id,
        "signal_key": signal_key,
        "decision": decision,
        "reason_code": reason_code
    })
    
    return result


@app.get("/v1/lico/decisions")
async def lico_list_decisions(signal_key: str = None, limit: int = 50, authorization: Optional[str] = Header(None)):
    """List LICO decisions, optionally filtered by signal_key."""
    conn = sqlite3.connect(DB_PATH)
    if signal_key:
        rows = conn.execute(
            "SELECT * FROM lico_decisions WHERE signal_key = ? ORDER BY created_at DESC LIMIT ?",
            (signal_key, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM lico_decisions ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    cols = ["decision_id", "signal_key", "decision", "reason_code", "notes", "operator_id", "created_at"]
    return {"decisions": [dict(zip(cols, r)) for r in rows]}


def _create_case_group_from_signal(conn, signal_key: str, operator_id: str = "operator") -> dict:
    """Create a case group from a signal key (respondent_id) and link matching claims."""
    import uuid
    from datetime import datetime
    
    now = datetime.utcnow().isoformat()
    
    # Check if group already exists for this respondent
    existing = conn.execute(
        "SELECT group_id FROM case_groups WHERE respondent_key = ? AND status = 'active'",
        (signal_key,)
    ).fetchone()
    
    if existing:
        group_id = existing[0]
    else:
        group_id = "grp_" + uuid.uuid4().hex[:12]
        conn.execute(
            """INSERT INTO case_groups (group_id, name, description, group_type, status, respondent_key, tags, strategy_notes, created_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (group_id, f"LICO Escalation: {signal_key}", f"Auto-created from LICO escalation of signal: {signal_key}",
             "respondent", "active", signal_key, "[]", "", operator_id, now, now)
        )
    
    # Find all claims matching this respondent
    # signal_key might be respondent_id (lowercase) or respondent name
    claims = conn.execute(
        """SELECT claim_id FROM claims 
           WHERE LOWER(REPLACE(respondent_entity, ' ', '_')) = LOWER(?) 
              OR LOWER(respondent_entity) = LOWER(?)""",
        (signal_key, signal_key)
    ).fetchall()
    
    linked = 0
    for (cid,) in claims:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO case_group_members (group_id, claim_id, added_by) VALUES (?,?,?)",
                (group_id, cid, operator_id)
            )
            linked += 1
        except:
            pass
    
    conn.commit()
    return {"group_id": group_id, "respondent": signal_key, "claims_linked": linked, "is_new": existing is None}




@app.post("/v1/case-groups/from-respondent")
async def create_group_from_respondent(body: dict, authorization: Optional[str] = Header(None)):
    """Create a case group from a respondent name/key and link all their claims."""
    respondent = body.get("respondent", "")
    if not respondent:
        raise HTTPException(400, "respondent required")
    conn = sqlite3.connect(DB_PATH)
    result = _create_case_group_from_signal(conn, respondent, body.get("operator_id", "operator"))
    conn.close()
    store.audit("case_group.created_from_respondent", {"group_id": result["group_id"], "respondent": respondent, "claims_linked": result["claims_linked"]})
    return result


@app.get("/v1/case-groups/{group_id}/members")
async def get_group_members(group_id: str, authorization: Optional[str] = Header(None)):
    """Get all claims in a case group."""
    conn = sqlite3.connect(DB_PATH)
    group = conn.execute("SELECT * FROM case_groups WHERE group_id = ?", (group_id,)).fetchone()
    if not group:
        conn.close()
        raise HTTPException(404, "Group not found")
    members = conn.execute(
        """SELECT m.claim_id, m.added_at, m.added_by, c.claimant_name, c.respondent_entity, c.amount_claimed, c.status, c.harm_type
           FROM case_group_members m JOIN claims c ON m.claim_id = c.claim_id WHERE m.group_id = ? ORDER BY m.added_at""",
        (group_id,)
    ).fetchall()
    conn.close()
    cols_g = ["group_id", "name", "description", "group_type", "status", "respondent_key", "tags", "strategy_notes", "created_by", "created_at", "updated_at"]
    cols_m = ["claim_id", "added_at", "added_by", "claimant_name", "respondent_entity", "amount_claimed", "status", "harm_type"]
    return {"group": dict(zip(cols_g, group)), "members": [dict(zip(cols_m, m)) for m in members], "total": len(members)}


@app.get("/v1/litmus/respondent/{respondent_name}")
async def litmus_respondent_scores(respondent_name: str, authorization: Optional[str] = Header(None)):
    """Get average LITMUS scores for all claims against a respondent."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        """SELECT ls.composite_score, ls.action_level, ls.claim_id FROM litmus_scores ls
           JOIN claims c ON ls.claim_id = c.claim_id WHERE LOWER(c.respondent_entity) = LOWER(?) ORDER BY ls.scored_at DESC""",
        (respondent_name,)
    ).fetchall()
    conn.close()
    if not rows:
        return {"respondent": respondent_name, "avg_composite": None, "scores": [], "count": 0}
    composites = [r[0] for r in rows]
    return {"respondent": respondent_name, "avg_composite": round(sum(composites)/len(composites), 3),
            "min_composite": round(min(composites), 3), "max_composite": round(max(composites), 3),
            "count": len(rows), "scores": [{"claim_id": r[2], "composite": r[0], "action_level": r[1]} for r in rows]}
