#!/usr/bin/env python3
"""
GhostLedger — Complete Type Definitions
========================================
All data objects, enums, scoring models, policy rule types,
and HRN framework types for the GhostLedger system.

Usage:
    from ghostledger_types import NoiseEvent, Storm, Front, HarmRecord, ...

Version: 1.0  —  February 2026
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Literal, Optional, Union


# ============================================================================
# ENUMS
# ============================================================================

class NoiseType(str, Enum):
    """Classification of a raw noise signal."""
    CHAOS = "chaos"
    RUMOR = "rumor"
    HYPE = "hype"


class Platform(str, Enum):
    """Supported source platforms."""
    TWITTER = "twitter"
    REDDIT = "reddit"
    DISCORD = "discord"
    TIKTOK = "tiktok"
    TELEGRAM = "telegram"
    YOUTUBE = "youtube"
    ONCHAIN = "onchain"
    NEWS = "news"
    FORUM = "forum"
    OTHER = "other"


class Severity(str, Enum):
    """Severity level for noise events and storms."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StormStatus(str, Enum):
    """Lifecycle status of a Storm."""
    FORMING = "forming"
    ACTIVE = "active"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    ARCHIVED = "archived"


class FrontStatus(str, Enum):
    """Lifecycle status of a Front (multi-storm convergence)."""
    DETECTED = "detected"
    MONITORING = "monitoring"
    ACTIVE = "active"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


class HarmType(str, Enum):
    """Categories of silent harm detected by the Shadow Detector."""
    WAGE_THEFT = "wage_theft"
    PLATFORM_LOCKOUT = "platform_lockout"
    ALGORITHMIC_SUPPRESSION = "algorithmic_suppression"
    PAYOUT_WITHHOLDING = "payout_withholding"
    GRANT_DEFAULT = "grant_default"
    DEPLATFORMING = "deplatforming"
    SILENT_PENALTY = "silent_penalty"
    UNDISCLOSED_FEE = "undisclosed_fee"
    DATA_EXPLOITATION = "data_exploitation"
    OTHER = "other"


class VictimStatus(str, Enum):
    """Shadow profile lifecycle status."""
    DETECTED = "detected"
    MONITORING = "monitoring"
    CONSENT_PENDING = "consent_pending"
    ACTIVE = "active"
    REPRESENTED = "represented"
    RESOLVED = "resolved"


class ConsentStatus(str, Enum):
    """Consent unlock state."""
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"


class DecisionOutcome(str, Enum):
    """Possible outcomes from the three-signature gate."""
    APPROVED = "approved"
    REJECTED = "rejected"
    VETOED = "vetoed"
    ESCALATED = "escalated"
    DEFERRED = "deferred"


class LawID(str, Enum):
    """The 7 Laws governing the Internet Reality Engine."""
    DO_NO_HARM = "law_1_do_no_harm"
    TRUTH_OVER_VIRALITY = "law_2_truth_over_virality"
    CONSENT_AND_PRIVACY = "law_3_consent_and_privacy"
    NO_MANIPULATION = "law_4_no_manipulation"
    COMPLY_BY_DEFAULT = "law_5_comply_by_default"
    EXPLAINABILITY = "law_6_explainability"
    AUDITABILITY = "law_7_auditability"


class EvidenceType(str, Enum):
    """Types of evidence that can be attached to a record."""
    SCREENSHOT = "screenshot"
    TRANSACTION = "transaction"
    API_RESPONSE = "api_response"
    EMAIL = "email"
    CONTRACT = "contract"
    SOCIAL_POST = "social_post"
    FINANCIAL_RECORD = "financial_record"
    CHAIN_EVENT = "chain_event"
    WITNESS_STATEMENT = "witness_statement"
    POLICY_DOCUMENT = "policy_document"
    OTHER = "other"


class CaseStatus(str, Enum):
    """GhostLedger claim / case lifecycle."""
    DRAFT = "draft"
    FILED = "filed"
    UNDER_REVIEW = "under_review"
    ESCALATED = "escalated"
    IN_RESOLUTION = "in_resolution"
    RESOLVED = "resolved"
    CLOSED = "closed"
    APPEALED = "appealed"


class SupportContactStatus(str, Enum):
    """Has the claimant already contacted support?"""
    YES_NO_RESOLUTION = "yes_no_resolution"
    YES_STILL_WAITING = "yes_still_waiting"
    NO_NOT_YET = "no_not_yet"


class ReferralSource(str, Enum):
    """How the claimant heard about GhostLedger."""
    REDDIT = "reddit"
    TWITTER_X = "twitter_x"
    DISCORD = "discord"
    WORD_OF_MOUTH = "word_of_mouth"
    TIKTOK = "tiktok"
    OTHER = "other"


class AgentCategory(str, Enum):
    """The six agent categories in the system."""
    LITMUS_EVALUATION = "litmus_evaluation"
    NOISE_INTELLIGENCE = "noise_intelligence"
    SHADOW_DETECTION = "shadow_detection"
    CASE_MANAGEMENT = "case_management"
    GOVERNANCE = "governance"
    DISTRIBUTION = "distribution"


class ScoutStatus(str, Enum):
    """Lifecycle status of a Signal Scout."""
    ACTIVE = "active"
    SHADOW_THROTTLE = "shadow_throttle"
    HARD_THROTTLE = "hard_throttle"
    SUSPENSION_REVIEW = "suspension_review"
    SUSPENDED = "suspended"
    COOL_OFF = "cool_off"           # transitioning to analyst
    GRADUATED = "graduated"          # promoted to analyst


class AnalystStatus(str, Enum):
    """Lifecycle status of an Analyst."""
    PROBATION = "probation"          # first 90 days
    ACTIVE = "active"
    SENIOR = "senior"
    ON_LEAVE = "on_leave"
    REVOKED = "revoked"


class EnforcementAction(str, Enum):
    """Signal Scouts enforcement ladder steps."""
    NORMAL = "normal"
    SHADOW_THROTTLE = "shadow_throttle"
    HARD_THROTTLE = "hard_throttle"
    SUSPENSION_REVIEW = "suspension_review"


class JurisdictionCode(str, Enum):
    """Supported jurisdiction identifiers."""
    US = "us"
    EU = "eu"
    UK = "uk"
    NG = "ng"                        # Nigeria
    FALLBACK = "fallback"            # global baseline


# ── Independent Legal Fellowship (ILF) + Case Classification Engine (CCE) ──

class DisputeType(str, Enum):
    """Closed taxonomy of internet dispute categories."""
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


class JurisdictionalScope(str, Enum):
    """How many jurisdictions are involved."""
    SINGLE = "single"               # e.g., US-CA only
    MULTI_STATE = "multi_state"     # e.g., US multi-state
    CROSS_BORDER = "cross_border"   # e.g., US-EU
    UNKNOWN = "unknown"             # requires human review


class ValueBand(str, Enum):
    """Case value band — determines routing pool."""
    MICRO = "micro"                 # < $500
    SMALL = "small"                 # $500 – $5k
    MEDIUM = "medium"               # $5k – $50k
    LARGE = "large"                 # $50k – $250k
    STRATEGIC = "strategic"         # $250k+


class RecoveryPath(str, Enum):
    """Estimated recovery approach (internal only, never shown to user)."""
    INFORMAL_DEMAND = "informal_demand"
    PLATFORM_ESCALATION = "platform_escalation"
    ARBITRATION = "arbitration"
    LITIGATION = "litigation"
    INFORMATIONAL_ONLY = "informational_only"


class LawyerSpecialty(str, Enum):
    """Legal specialty categories for professional matching."""
    CONSUMER_PROTECTION = "consumer_protection"
    EMPLOYMENT_LAW = "employment_law"
    FINANCIAL_DISPUTES = "financial_disputes"
    CONTRACT_LAW = "contract_law"
    INTERNATIONAL_LAW = "international_law"
    DIGITAL_RIGHTS = "digital_rights"
    CLASS_ACTION = "class_action"
    GENERAL_PRACTICE = "general_practice"


class ProfessionalStatus(str, Enum):
    """Status of a lawyer/firm in the ILF network."""
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    ON_HOLD = "on_hold"
    SUSPENDED = "suspended"
    WITHDRAWN = "withdrawn"


class HRNRole(str, Enum):
    """Roles within the Human Representation Network."""
    LEGAL_ADVOCATE = "legal_advocate"
    FINANCIAL_AUDITOR = "financial_auditor"
    MEDIATOR = "mediator"
    INVESTIGATOR = "investigator"
    REGULATORY_LIAISON = "regulatory_liaison"


class HRNStatus(str, Enum):
    """Status of an HRN engagement."""
    AVAILABLE = "available"
    ASSIGNED = "assigned"
    ACTIVE = "active"
    UNDER_REVIEW = "under_review"
    COMPLETED = "completed"
    WITHDRAWN = "withdrawn"


# ============================================================================
# CORE DATA OBJECTS — Noise Intelligence Engine
# ============================================================================

@dataclass
class EvidenceRef:
    """Reference to a piece of evidence stored in the system."""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType = EvidenceType.OTHER
    source_url: Optional[str] = None
    hash_sha256: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    description: str = ""
    storage_uri: str = ""          # internal storage location
    verified: bool = False
    chain_anchor_tx: Optional[str] = None  # Solana tx if anchored

    def compute_hash(self, content: bytes) -> str:
        self.hash_sha256 = hashlib.sha256(content).hexdigest()
        return self.hash_sha256


@dataclass
class NoiseEvent:
    """
    A single raw noise signal captured from any platform.
    The atomic unit of the Noise Intelligence Engine.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    noise_type: NoiseType = NoiseType.CHAOS
    platform: Platform = Platform.OTHER
    source_url: Optional[str] = None
    content_snippet: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    severity: Severity = Severity.LOW
    confidence: float = 0.0         # 0.0 – 1.0
    entities: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    evidence: List[EvidenceRef] = field(default_factory=list)
    storm_id: Optional[str] = None  # assigned when clustered
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StormScore:
    """Composite score for a Storm."""
    velocity: float = 0.0           # events per hour
    volume: int = 0                 # total events
    cross_platform: int = 0         # distinct platforms
    entity_concentration: float = 0.0
    composite: float = 0.0

    def compute(self) -> float:
        """
        StormScore = (velocity × 0.3) + (log2(volume) × 0.25)
                   + (cross_platform × 0.25) + (entity_concentration × 0.2)
        """
        import math
        self.composite = (
            (self.velocity * 0.3)
            + (math.log2(max(self.volume, 1)) * 0.25)
            + (self.cross_platform * 0.25)
            + (self.entity_concentration * 0.2)
        )
        return self.composite


@dataclass
class Storm:
    """
    A cluster of related NoiseEvents that form a coherent narrative.
    Storms are detected when events share entities, timing, or themes.
    """
    storm_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    status: StormStatus = StormStatus.FORMING
    noise_type: NoiseType = NoiseType.CHAOS
    severity: Severity = Severity.LOW
    score: StormScore = field(default_factory=StormScore)
    events: List[str] = field(default_factory=list)       # event IDs
    entities: List[str] = field(default_factory=list)
    platforms: List[Platform] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    front_id: Optional[str] = None  # assigned when merged into a Front
    evidence: List[EvidenceRef] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FrontScore:
    """Composite score for a Front."""
    storm_count: int = 0
    entity_overlap: float = 0.0
    temporal_correlation: float = 0.0
    severity_max: float = 0.0
    composite: float = 0.0

    def compute(self) -> float:
        """
        FrontScore = (storm_count × 0.3) + (entity_overlap × 0.3)
                   + (temporal_correlation × 0.2) + (severity_max × 0.2)
        """
        self.composite = (
            (self.storm_count * 0.3)
            + (self.entity_overlap * 0.3)
            + (self.temporal_correlation * 0.2)
            + (self.severity_max * 0.2)
        )
        return self.composite


@dataclass
class Front:
    """
    A convergence of multiple Storms indicating a systemic pattern.
    Fronts trigger deeper investigation and potential escalation.
    """
    front_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    status: FrontStatus = FrontStatus.DETECTED
    severity: Severity = Severity.HIGH
    score: FrontScore = field(default_factory=FrontScore)
    storms: List[str] = field(default_factory=list)        # storm IDs
    entities: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    evidence: List[EvidenceRef] = field(default_factory=list)
    related_harm_records: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# CORE DATA OBJECTS — Shadow Detector Engine
# ============================================================================

@dataclass
class HarmRecord:
    """
    A documented instance of silent harm identified by the Shadow Detector.
    This is the bridge between noise detection and victim representation.
    """
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    harm_type: HarmType = HarmType.OTHER
    severity: Severity = Severity.MEDIUM
    description: str = ""
    entity_accused: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    source_storms: List[str] = field(default_factory=list)  # storm IDs
    source_fronts: List[str] = field(default_factory=list)  # front IDs
    evidence: List[EvidenceRef] = field(default_factory=list)
    estimated_affected: int = 0
    estimated_amount_usd: float = 0.0
    victim_profiles: List[str] = field(default_factory=list)  # profile IDs
    chain_anchor_tx: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VictimShadowProfile:
    """
    A privacy-preserving profile of a potential victim.
    NO direct contact is made until consent is unlocked.
    """
    profile_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: VictimStatus = VictimStatus.DETECTED
    harm_records: List[str] = field(default_factory=list)   # record IDs
    platform_handles: Dict[Platform, str] = field(default_factory=dict)
    pseudonym: str = ""             # system-generated, never real name
    detected_at: datetime = field(default_factory=datetime.utcnow)
    severity_aggregate: float = 0.0
    estimated_loss_usd: float = 0.0
    consent_id: Optional[str] = None  # linked ConsentUnlock
    hrn_engagement_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConsentUnlock:
    """
    Governs whether the system may contact or represent a victim.
    Consent is NEVER assumed. Every action gate checks this object.
    """
    consent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    profile_id: str = ""            # linked VictimShadowProfile
    status: ConsentStatus = ConsentStatus.PENDING
    requested_at: datetime = field(default_factory=datetime.utcnow)
    granted_at: Optional[datetime] = None
    denied_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    scope: List[str] = field(default_factory=list)  # what actions are permitted
    method: str = ""                # how consent was collected
    verification_hash: Optional[str] = None
    withdrawal_reason: Optional[str] = None

    @property
    def is_active(self) -> bool:
        if self.status != ConsentStatus.GRANTED:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True


# ============================================================================
# CORE DATA OBJECTS — LITMUS Evaluation
# ============================================================================

@dataclass
class LITMUSCriterion:
    """Score for a single LITMUS letter."""
    letter: Literal["L", "I", "T", "M", "U", "S"]
    label: str = ""
    score: float = 0.0              # 0.0 – 1.0
    confidence: float = 0.0
    reasoning: str = ""
    evidence_refs: List[str] = field(default_factory=list)


@dataclass
class LITMUSScore:
    """
    Full LITMUS evaluation result.
    Composite = weighted average of six criteria.
    """
    evaluation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_entity: str = ""
    criteria: List[LITMUSCriterion] = field(default_factory=list)
    composite: float = 0.0
    evaluated_at: datetime = field(default_factory=datetime.utcnow)
    evaluator_agents: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_composite(
        self,
        weights: Optional[Dict[str, float]] = None
    ) -> float:
        """
        Default weights: L=0.15, I=0.15, T=0.15, M=0.20, U=0.15, S=0.20
        """
        default_weights = {
            "L": 0.15, "I": 0.15, "T": 0.15,
            "M": 0.20, "U": 0.15, "S": 0.20,
        }
        w = weights or default_weights
        total = 0.0
        for c in self.criteria:
            total += c.score * w.get(c.letter, 0.0)
        self.composite = round(total, 4)
        return self.composite


# ============================================================================
# CORE DATA OBJECTS — GhostLedger Case Management
# ============================================================================

@dataclass
class IntakeSubmission:
    """
    Maps directly to the live GhostLedger Payment Recovery Intake form.
    This is the front door — every claim starts here.
    Google Form fields → IntakeSubmission → Claim pipeline.
    """
    submission_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # Claimant identity
    full_name: str = ""
    email: str = ""
    phone: Optional[str] = None
    # Claim details
    platform_or_company: str = ""   # "PayPal, Uber, Stripe, DoorDash, Shopify, Square"
    estimated_amount_usd: float = 0.0
    last_expected_payment: Optional[datetime] = None
    platform_reason: str = ""       # what the platform told them
    contacted_support: SupportContactStatus = SupportContactStatus.NO_NOT_YET
    # Discovery & consent
    referral_source: ReferralSource = ReferralSource.OTHER
    authorization_granted: bool = False  # must be True to proceed
    # System fields
    submitted_at: datetime = field(default_factory=datetime.utcnow)
    converted_to_claim_id: Optional[str] = None  # set when intake → Claim
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_claim(self) -> 'Claim':
        """Convert an authorized intake submission into a formal Claim."""
        if not self.authorization_granted:
            raise ValueError("Cannot create claim without authorization")
        claim = Claim(
            status=CaseStatus.FILED,
            claimant_name=self.full_name,
            claimant_email=self.email,
            claimant_phone=self.phone,
            respondent_entity=self.platform_or_company,
            harm_type=HarmType.PAYOUT_WITHHOLDING,
            amount_claimed_usd=self.estimated_amount_usd,
            description=self.platform_reason,
            last_expected_payment=self.last_expected_payment,
            contacted_support=self.contacted_support,
            referral_source=self.referral_source,
            filed_at=datetime.utcnow(),
            intake_submission_id=self.submission_id,
        )
        self.converted_to_claim_id = claim.claim_id
        return claim


@dataclass
class Claim:
    """
    A financial claim filed in the GhostLedger system.
    The fundamental unit of accountability.
    Created from IntakeSubmission or from the Shadow Detector pipeline.
    """
    claim_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: CaseStatus = CaseStatus.DRAFT
    # Claimant info (from intake form or shadow profile)
    claimant_profile_id: Optional[str] = None   # shadow profile link
    claimant_name: str = ""                      # from intake form
    claimant_email: str = ""                     # from intake form
    claimant_phone: Optional[str] = None         # from intake form
    intake_submission_id: Optional[str] = None   # links back to IntakeSubmission
    # Claim details
    respondent_entity: str = ""
    harm_type: HarmType = HarmType.OTHER
    amount_claimed_usd: float = 0.0
    amount_recovered_usd: float = 0.0
    currency: str = "USD"
    description: str = ""
    last_expected_payment: Optional[datetime] = None
    contacted_support: SupportContactStatus = SupportContactStatus.NO_NOT_YET
    referral_source: ReferralSource = ReferralSource.OTHER
    # Lifecycle
    filed_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    evidence: List[EvidenceRef] = field(default_factory=list)
    related_harm_records: List[str] = field(default_factory=list)
    escalation_history: List[EscalationEvent] = field(default_factory=list)
    chain_anchor_tx: Optional[str] = None
    execution_score: float = 0.0    # derived from actions taken
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EscalationEvent:
    """Records each escalation step in a claim's lifecycle."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_id: str = ""
    from_status: CaseStatus = CaseStatus.DRAFT
    to_status: CaseStatus = CaseStatus.FILED
    triggered_by: str = ""          # agent or rule that triggered
    reason: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionRecord:
    """
    Immutable record of every action taken on a claim.
    These records form the basis of Execution Score.
    """
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_id: str = ""
    action: str = ""
    actor: str = ""                 # agent ID or HRN member
    timestamp: datetime = field(default_factory=datetime.utcnow)
    result: str = ""
    chain_anchor_tx: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# GOVERNANCE — Policy Rule DSL Types
# ============================================================================

@dataclass
class PolicyCondition:
    """A single condition in a policy rule."""
    field: str = ""                 # e.g., "event.severity"
    operator: str = ""              # eq, neq, gt, lt, gte, lte, in, contains
    value: Any = None

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate this condition against a context dict."""
        actual = context
        for part in self.field.split("."):
            if isinstance(actual, dict):
                actual = actual.get(part)
            else:
                actual = getattr(actual, part, None)
            if actual is None:
                return False

        ops = {
            "eq": lambda a, v: a == v,
            "neq": lambda a, v: a != v,
            "gt": lambda a, v: a > v,
            "lt": lambda a, v: a < v,
            "gte": lambda a, v: a >= v,
            "lte": lambda a, v: a <= v,
            "in": lambda a, v: a in v,
            "contains": lambda a, v: v in a,
        }
        fn = ops.get(self.operator)
        return fn(actual, self.value) if fn else False


@dataclass
class PolicyAction:
    """An action to execute when a policy rule fires."""
    action_type: str = ""           # block, flag, escalate, notify, log, require_consent
    target: str = ""                # agent, topic, or system component
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyRule:
    """
    A deterministic rule in the Policy Rule DSL.
    Rules are evaluated in priority order (lower number = higher priority).
    """
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    law: LawID = LawID.DO_NO_HARM
    priority: int = 100             # lower = higher priority
    conditions: List[PolicyCondition] = field(default_factory=list)
    actions: List[PolicyAction] = field(default_factory=list)
    enabled: bool = True
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Returns True if ALL conditions are met."""
        if not self.enabled:
            return False
        return all(c.evaluate(context) for c in self.conditions)


# ============================================================================
# GOVERNANCE — Decision Gate
# ============================================================================

@dataclass
class GateSignature:
    """A single signature in the three-signature decision gate."""
    signer: str = ""                # "verifier", "policy", "risk"
    approved: bool = False
    veto: bool = False
    reason: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Decision:
    """
    Three-signature governance gate.
    Requires: Verifier + Policy + Risk.
    Any signer can VETO (immediate block).
    """
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    context_type: str = ""          # "storm_escalation", "claim_action", etc.
    context_id: str = ""            # ID of the object being decided on
    signatures: List[GateSignature] = field(default_factory=list)
    outcome: DecisionOutcome = DecisionOutcome.DEFERRED
    decided_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def resolve(self) -> DecisionOutcome:
        """
        Resolution logic:
        - Any VETO → VETOED
        - All three approve → APPROVED
        - Otherwise → DEFERRED
        """
        if any(s.veto for s in self.signatures):
            self.outcome = DecisionOutcome.VETOED
        elif (
            len(self.signatures) >= 3
            and all(s.approved for s in self.signatures)
        ):
            self.outcome = DecisionOutcome.APPROVED
        else:
            self.outcome = DecisionOutcome.DEFERRED

        if self.outcome != DecisionOutcome.DEFERRED:
            self.decided_at = datetime.utcnow()
        return self.outcome


# ============================================================================
# HUMAN REPRESENTATION NETWORK (HRN)
# ============================================================================

@dataclass
class HRNMember:
    """A professional in the Human Representation Network."""
    member_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: HRNRole = HRNRole.LEGAL_ADVOCATE
    name: str = ""
    jurisdiction: List[str] = field(default_factory=list)
    specializations: List[HarmType] = field(default_factory=list)
    status: HRNStatus = HRNStatus.AVAILABLE
    cases_completed: int = 0
    success_rate: float = 0.0
    joined_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HRNEngagement:
    """
    An active engagement between an HRN member and a victim case.
    Created only AFTER ConsentUnlock.is_active == True.
    """
    engagement_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    member_id: str = ""
    profile_id: str = ""            # VictimShadowProfile
    claim_ids: List[str] = field(default_factory=list)
    consent_id: str = ""            # must reference active ConsentUnlock
    status: HRNStatus = HRNStatus.ASSIGNED
    assigned_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    outcome: str = ""
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OpportunityBrief:
    """
    A case brief sent to HRN members for potential pickup.
    Contains NO personally identifiable information.
    """
    brief_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    harm_type: HarmType = HarmType.OTHER
    severity: Severity = Severity.MEDIUM
    jurisdiction_hint: str = ""
    estimated_amount_usd: float = 0.0
    affected_count: int = 0
    summary: str = ""               # anonymized case summary
    required_roles: List[HRNRole] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# AGENT DEFINITIONS
# ============================================================================

@dataclass
class AgentConfig:
    """Configuration for a GhostLedger autonomous agent."""
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: AgentCategory = AgentCategory.GOVERNANCE
    description: str = ""
    system_prompt: str = ""
    model: str = "claude-opus-4-6"
    tools: List[str] = field(default_factory=list)
    input_topics: List[str] = field(default_factory=list)   # event bus
    output_topics: List[str] = field(default_factory=list)
    policy_rules: List[str] = field(default_factory=list)   # rule IDs
    enabled: bool = True
    max_concurrent: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# EVENT BUS
# ============================================================================

class EventTopic(str, Enum):
    """Namespaced event bus topics for inter-agent communication."""
    # Noise Intelligence
    NOISE_RAW = "nie.noise.raw"
    NOISE_CLASSIFIED = "nie.noise.classified"
    STORM_DETECTED = "nie.storm.detected"
    STORM_UPDATED = "nie.storm.updated"
    STORM_ESCALATED = "nie.storm.escalated"
    FRONT_DETECTED = "nie.front.detected"
    FRONT_ESCALATED = "nie.front.escalated"

    # Shadow Detector
    HARM_DETECTED = "sde.harm.detected"
    VICTIM_IDENTIFIED = "sde.victim.identified"
    CONSENT_REQUESTED = "sde.consent.requested"
    CONSENT_GRANTED = "sde.consent.granted"
    CONSENT_DENIED = "sde.consent.denied"

    # LITMUS Evaluation
    EVAL_REQUESTED = "litmus.eval.requested"
    EVAL_COMPLETED = "litmus.eval.completed"
    EVAL_FAILED = "litmus.eval.failed"

    # Intake
    INTAKE_RECEIVED = "intake.submission.received"
    INTAKE_CONVERTED = "intake.submission.converted"

    # Case Management
    CLAIM_FILED = "case.claim.filed"
    CLAIM_UPDATED = "case.claim.updated"
    CLAIM_ESCALATED = "case.claim.escalated"
    CLAIM_RESOLVED = "case.claim.resolved"
    EXECUTION_LOGGED = "case.execution.logged"

    # Governance
    DECISION_REQUESTED = "gov.decision.requested"
    DECISION_RESOLVED = "gov.decision.resolved"
    POLICY_VIOLATION = "gov.policy.violation"
    AUDIT_EVENT = "gov.audit.event"

    # HRN
    BRIEF_PUBLISHED = "hrn.brief.published"
    ENGAGEMENT_CREATED = "hrn.engagement.created"
    ENGAGEMENT_COMPLETED = "hrn.engagement.completed"

    # Signal Scouts
    SCOUT_REPORT_SUBMITTED = "scout.report.submitted"
    SCOUT_TELEMETRY_COMPUTED = "scout.telemetry.computed"
    SCOUT_ENFORCEMENT_APPLIED = "scout.enforcement.applied"
    SCOUT_ANALYST_ELIGIBLE = "scout.analyst.eligible"
    SCOUT_ANALYST_PROMOTED = "scout.analyst.promoted"
    COORDINATION_DETECTED = "scout.coordination.detected"

    # Independent Legal Fellowship (ILF)
    CASE_CLASSIFIED = "ilf.case.classified"
    CASE_ROUTED = "ilf.case.routed"
    LAWYER_MATCHED = "ilf.lawyer.matched"
    ENGAGEMENT_STARTED = "ilf.engagement.started"
    ENGAGEMENT_RESOLVED = "ilf.engagement.resolved"
    SYSTEMIC_PATTERN_FLAGGED = "ilf.systemic.flagged"

    # Distribution
    CONTENT_GENERATED = "dist.content.generated"
    CONTENT_PUBLISHED = "dist.content.published"


@dataclass
class BusEvent:
    """A message on the event bus."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    topic: EventTopic = EventTopic.AUDIT_EVENT
    payload: Dict[str, Any] = field(default_factory=dict)
    source_agent: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: Optional[str] = None  # trace related events


# ============================================================================
# SCORING UTILITIES
# ============================================================================

@dataclass
class LoopholeScore:
    """
    Measures how likely a financial mechanism is designed to avoid accountability.
    Used by the Shadow Detector to flag structural harm.
    """
    complexity: float = 0.0         # structural complexity
    opacity: float = 0.0            # how hidden is the mechanism
    affected_ratio: float = 0.0     # % of users affected
    precedent: float = 0.0          # similar patterns seen before
    composite: float = 0.0

    def compute(self) -> float:
        """
        LoopholeScore = (complexity × 0.25) + (opacity × 0.30)
                      + (affected_ratio × 0.25) + (precedent × 0.20)
        """
        self.composite = (
            (self.complexity * 0.25)
            + (self.opacity * 0.30)
            + (self.affected_ratio * 0.25)
            + (self.precedent * 0.20)
        )
        return self.composite


@dataclass
class ExecutionScore:
    """
    Derived from actual actions taken on a claim.
    Higher score = more action was attempted regardless of outcome.
    """
    actions_taken: int = 0
    escalations: int = 0
    evidence_gathered: int = 0
    response_time_hours: float = 0.0
    resolution_attempted: bool = False
    composite: float = 0.0

    def compute(self) -> float:
        """
        ExecutionScore = (actions × 0.25) + (escalations × 0.20)
                       + (evidence × 0.20) + (speed_factor × 0.15)
                       + (resolution_bonus × 0.20)
        Speed factor: 1.0 if < 24h, 0.5 if < 72h, 0.2 otherwise.
        """
        if self.response_time_hours < 24:
            speed = 1.0
        elif self.response_time_hours < 72:
            speed = 0.5
        else:
            speed = 0.2

        resolution_bonus = 1.0 if self.resolution_attempted else 0.0

        self.composite = (
            (min(self.actions_taken / 10, 1.0) * 0.25)
            + (min(self.escalations / 5, 1.0) * 0.20)
            + (min(self.evidence_gathered / 10, 1.0) * 0.20)
            + (speed * 0.15)
            + (resolution_bonus * 0.20)
        )
        return self.composite


# ============================================================================
# SOLANA CHAIN ANCHOR
# ============================================================================

@dataclass
class ChainAnchor:
    """
    Reference to an immutable on-chain record on Solana.
    Used to timestamp and verify the existence of system records.
    """
    anchor_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tx_signature: str = ""
    slot: int = 0
    block_time: Optional[datetime] = None
    program_id: str = ""
    data_hash: str = ""             # SHA-256 of the anchored data
    record_type: str = ""           # "claim", "evidence", "decision", etc.
    record_id: str = ""             # ID of the anchored record
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# SIGNAL SCOUTS — Anti-Gaming Telemetry
# ============================================================================

@dataclass
class FixationMetrics:
    """
    Measures single-entity fixation — a Scout repeatedly reporting
    the same target is a gaming signal.
    """
    entity_name: str = ""
    reports_on_entity: int = 0
    total_reports: int = 0
    fixation_score: float = 0.0     # reports_on_entity / total_reports
    first_report: Optional[datetime] = None
    last_report: Optional[datetime] = None

    def compute(self) -> float:
        if self.total_reports > 0:
            self.fixation_score = self.reports_on_entity / self.total_reports
        return self.fixation_score


@dataclass
class CoordinationSignal:
    """
    Detects coordinated/collusion patterns — multiple Scouts
    filing similar reports in tight time windows.
    """
    signal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scout_ids: List[str] = field(default_factory=list)
    target_entity: str = ""
    time_window_minutes: int = 0
    report_count: int = 0
    semantic_similarity: float = 0.0    # 0.0 – 1.0
    detected_at: datetime = field(default_factory=datetime.utcnow)
    is_flagged: bool = False

    def evaluate(self) -> bool:
        """Flag if 3+ Scouts report same target within 30min with >0.8 similarity."""
        self.is_flagged = (
            len(self.scout_ids) >= 3
            and self.time_window_minutes <= 30
            and self.semantic_similarity > 0.8
        )
        return self.is_flagged


@dataclass
class InflationMetrics:
    """
    Tracks language inflation — escalating severity language
    without corresponding evidence growth.
    """
    scout_id: str = ""
    avg_severity_claimed: float = 0.0   # 0.0 – 1.0
    avg_evidence_quality: float = 0.0   # 0.0 – 1.0
    inflation_rate: float = 0.0         # severity - evidence quality
    sample_count: int = 0

    def compute(self) -> float:
        self.inflation_rate = max(0.0,
            self.avg_severity_claimed - self.avg_evidence_quality)
        return self.inflation_rate


@dataclass
class LateStageBias:
    """
    Detects late-stage reporting bias — Scouts who only report
    entities that are already under investigation or trending.
    """
    scout_id: str = ""
    total_reports: int = 0
    reports_on_known_targets: int = 0   # already-flagged entities
    late_stage_ratio: float = 0.0
    sample_period_days: int = 30

    def compute(self) -> float:
        if self.total_reports > 0:
            self.late_stage_ratio = (
                self.reports_on_known_targets / self.total_reports)
        return self.late_stage_ratio


@dataclass
class ScoutTelemetry:
    """
    Complete anti-gaming telemetry for a single Signal Scout.
    Signal Quality Score (SQS) is the composite health metric.
    """
    telemetry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scout_id: str = ""
    period_start: datetime = field(default_factory=datetime.utcnow)
    period_end: Optional[datetime] = None

    # Sub-metrics
    fixation_top: Optional[FixationMetrics] = None      # worst fixation
    coordination_flags: int = 0
    inflation: Optional[InflationMetrics] = None
    late_stage: Optional[LateStageBias] = None

    # Composite
    signal_quality_score: float = 1.0   # 0.0 (bad) – 1.0 (clean)
    enforcement_action: EnforcementAction = EnforcementAction.NORMAL
    enforcement_history: List[Dict[str, Any]] = field(default_factory=list)
    computed_at: datetime = field(default_factory=datetime.utcnow)

    def compute_sqs(self) -> float:
        """
        SQS = 1.0 - penalties
        Penalties: fixation (0.3), coordination (0.25),
                   inflation (0.25), late_stage (0.2)
        """
        penalty = 0.0
        if self.fixation_top and self.fixation_top.fixation_score > 0.4:
            penalty += min(self.fixation_top.fixation_score, 1.0) * 0.30
        if self.coordination_flags > 0:
            penalty += min(self.coordination_flags / 5, 1.0) * 0.25
        if self.inflation and self.inflation.inflation_rate > 0.2:
            penalty += min(self.inflation.inflation_rate, 1.0) * 0.25
        if self.late_stage and self.late_stage.late_stage_ratio > 0.6:
            penalty += min(self.late_stage.late_stage_ratio, 1.0) * 0.20

        self.signal_quality_score = max(0.0, 1.0 - penalty)
        self._apply_enforcement()
        return self.signal_quality_score

    def _apply_enforcement(self):
        """Enforcement ladder based on SQS."""
        if self.signal_quality_score >= 0.7:
            self.enforcement_action = EnforcementAction.NORMAL
        elif self.signal_quality_score >= 0.5:
            self.enforcement_action = EnforcementAction.SHADOW_THROTTLE
        elif self.signal_quality_score >= 0.3:
            self.enforcement_action = EnforcementAction.HARD_THROTTLE
        else:
            self.enforcement_action = EnforcementAction.SUSPENSION_REVIEW


@dataclass
class ScoutProfile:
    """
    Complete profile for a Signal Scout — the community member
    who observes and reports internet harm signals.
    """
    scout_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    display_name: str = ""          # pseudonym, never real name
    status: ScoutStatus = ScoutStatus.ACTIVE
    joined_at: datetime = field(default_factory=datetime.utcnow)

    # Performance
    total_reports: int = 0
    confirmed_reports: int = 0      # led to actual claims
    false_positives: int = 0
    accuracy_rate: float = 0.0      # confirmed / total

    # Telemetry
    current_sqs: float = 1.0
    telemetry_history: List[str] = field(default_factory=list)  # telemetry IDs

    # Scout → Analyst transition
    eligible_for_analyst: bool = False
    cool_off_start: Optional[datetime] = None   # 30-day cool-off
    analyst_application_id: Optional[str] = None

    # Reward tracking
    reward_tokens_earned: float = 0.0
    reward_tokens_frozen: float = 0.0   # frozen during enforcement
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_accuracy(self) -> float:
        if self.total_reports > 0:
            self.accuracy_rate = self.confirmed_reports / self.total_reports
        return self.accuracy_rate

    def check_analyst_eligibility(self) -> bool:
        """
        Eligibility: 90+ days active, 50+ reports, >70% accuracy,
        SQS >= 0.8, zero suspensions.
        """
        from datetime import timedelta
        days_active = (datetime.utcnow() - self.joined_at).days
        self.eligible_for_analyst = (
            days_active >= 90
            and self.total_reports >= 50
            and self.accuracy_rate >= 0.70
            and self.current_sqs >= 0.80
            and self.status == ScoutStatus.ACTIVE
        )
        return self.eligible_for_analyst


@dataclass
class AnalystProfile:
    """
    An Analyst is a graduated Scout with elevated access:
    claim review, pattern analysis, and HRN coordination.
    """
    analyst_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scout_id: str = ""              # original scout profile
    display_name: str = ""
    status: AnalystStatus = AnalystStatus.PROBATION
    promoted_at: datetime = field(default_factory=datetime.utcnow)
    cool_off_completed: Optional[datetime] = None

    # Responsibilities
    claims_reviewed: int = 0
    patterns_identified: int = 0
    hrn_referrals: int = 0
    quality_score: float = 1.0      # peer + system review

    # Compensation
    monthly_stipend_usd: float = 0.0
    performance_bonus_usd: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# JURISDICTION PACKS
# ============================================================================

@dataclass
class JurisdictionDisclaimer:
    """
    A jurisdiction-tuned legal disclaimer for user-facing text.
    Role-specific (Scout, Analyst, HRN) + jurisdiction add-ons.
    """
    disclaimer_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    jurisdiction: JurisdictionCode = JurisdictionCode.FALLBACK
    role: str = "global"            # "global", "scout", "analyst", "hrn"
    text: str = ""
    effective_date: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class JurisdictionPack:
    """
    Complete jurisdiction configuration — disclaimers, regulatory
    references, and compliance requirements for a region.
    """
    pack_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    jurisdiction: JurisdictionCode = JurisdictionCode.FALLBACK
    display_name: str = ""          # e.g., "United States"
    disclaimers: List[JurisdictionDisclaimer] = field(default_factory=list)
    regulatory_refs: List[str] = field(default_factory=list)
    data_residency: str = ""        # where data must stay
    consent_requirements: str = ""  # special consent rules
    age_of_majority: int = 18
    currency: str = "USD"
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# INTERNET LAW FIRM (ILF) — Case Classification Engine
# ============================================================================

@dataclass
class CaseClassification:
    """
    The CCE output — five-dimensional classification of every case.
    This determines routing, never legal merit.
    The CCE is air traffic control, not autopilot.
    """
    classification_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_id: str = ""              # linked Claim

    # Five mandatory dimensions
    dispute_type: DisputeType = DisputeType.OTHER
    jurisdictional_scope: JurisdictionalScope = JurisdictionalScope.UNKNOWN
    value_band: ValueBand = ValueBand.MICRO
    complexity_score: int = 1       # 1-5 (≥4 = human triage mandatory)
    recovery_path: RecoveryPath = RecoveryPath.INFORMATIONAL_ONLY

    # Routing metadata
    requires_human_triage: bool = False
    systemic_flag: bool = False     # LITMUS pattern detected
    related_case_count: int = 0     # other cases against same entity
    classified_at: datetime = field(default_factory=datetime.utcnow)
    classified_by: str = "cce_auto" # "cce_auto" or analyst ID
    metadata: Dict[str, Any] = field(default_factory=dict)

    def classify_value_band(self, amount_usd: float) -> ValueBand:
        """Assign value band from dollar amount."""
        if amount_usd < 500:
            self.value_band = ValueBand.MICRO
        elif amount_usd < 5_000:
            self.value_band = ValueBand.SMALL
        elif amount_usd < 50_000:
            self.value_band = ValueBand.MEDIUM
        elif amount_usd < 250_000:
            self.value_band = ValueBand.LARGE
        else:
            self.value_band = ValueBand.STRATEGIC
        return self.value_band

    def check_human_triage(self) -> bool:
        """Determine if human review is required."""
        self.requires_human_triage = (
            self.complexity_score >= 4
            or self.jurisdictional_scope == JurisdictionalScope.UNKNOWN
            or self.jurisdictional_scope == JurisdictionalScope.CROSS_BORDER
            or self.value_band == ValueBand.STRATEGIC
            or self.systemic_flag
        )
        return self.requires_human_triage


@dataclass
class LawyerProfile:
    """
    A legal professional registered in the ILF network.
    Lawyers opt in — they are never assigned.
    """
    lawyer_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    display_name: str = ""
    status: ProfessionalStatus = ProfessionalStatus.PENDING_VERIFICATION
    specialties: List[LawyerSpecialty] = field(default_factory=list)
    jurisdictions: List[JurisdictionCode] = field(default_factory=list)
    bar_numbers: Dict[str, str] = field(default_factory=dict)  # jurisdiction → bar#
    value_band_min: ValueBand = ValueBand.MICRO
    value_band_max: ValueBand = ValueBand.STRATEGIC
    accepts_contingency: bool = True
    cases_accepted: int = 0
    cases_resolved: int = 0
    success_rate: float = 0.0
    joined_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_success_rate(self) -> float:
        if self.cases_accepted > 0:
            self.success_rate = self.cases_resolved / self.cases_accepted
        return self.success_rate


@dataclass
class FirmProfile:
    """A law firm or recovery specialist firm in the ILF network."""
    firm_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    status: ProfessionalStatus = ProfessionalStatus.PENDING_VERIFICATION
    lawyers: List[str] = field(default_factory=list)  # lawyer IDs
    specialties: List[LawyerSpecialty] = field(default_factory=list)
    jurisdictions: List[JurisdictionCode] = field(default_factory=list)
    value_band_min: ValueBand = ValueBand.SMALL
    value_band_max: ValueBand = ValueBand.STRATEGIC
    accepts_contingency: bool = True
    cases_completed: int = 0
    avg_resolution_days: float = 0.0
    joined_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ILFEngagement:
    """
    An engagement between a case and a legal professional via ILF.
    ILF exits the legal loop once engagement starts —
    the lawyer and user interact directly.
    """
    engagement_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_id: str = ""
    classification_id: str = ""     # linked CaseClassification
    lawyer_id: Optional[str] = None
    firm_id: Optional[str] = None
    status: str = "pending"         # pending, accepted, active, resolved, declined
    fee_structure: str = "contingency"  # contingency, fixed_success, hybrid
    fee_percentage: Optional[float] = None
    coordination_fee_pct: float = 0.0  # ILF's cut (only on success)
    engaged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    amount_recovered_usd: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DesignDoctrineCheck:
    """
    Anti-fragility checklist — every system component must pass.
    Derived from the Anti-WLFI stress test.
    If any answer is wrong → redesign.
    """
    check_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    component: str = ""             # e.g., "treasury", "governance", "narrative"
    # The five fatal questions
    can_treasury_be_liquidated: bool = False     # must be False
    can_founders_rug_governance: bool = False     # must be False
    can_politics_affect_operations: bool = False  # must be False
    is_token_required_to_use: bool = False        # must be False
    would_regulators_find_boring: bool = True     # must be True
    # Extended checks
    holds_user_funds: bool = False               # must be False
    uses_leverage: bool = False                  # must be False
    has_live_treasury_dashboard: bool = True      # must be True
    survives_founder_disappearance: bool = True   # must be True
    checked_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def passes(self) -> bool:
        """All checks must pass for the component to be safe."""
        return (
            not self.can_treasury_be_liquidated
            and not self.can_founders_rug_governance
            and not self.can_politics_affect_operations
            and not self.is_token_required_to_use
            and self.would_regulators_find_boring
            and not self.holds_user_funds
            and not self.uses_leverage
            and self.has_live_treasury_dashboard
            and self.survives_founder_disappearance
        )


# ============================================================================
# CONVENIENCE — TYPE ALIASES & COLLECTIONS
# ============================================================================

# All object types that can be anchored on-chain
Anchorable = Union[Claim, HarmRecord, EvidenceRef, Decision, ExecutionRecord]

# All object types that carry evidence
Evidenced = Union[NoiseEvent, Storm, Front, HarmRecord, Claim]

# All score types
Score = Union[StormScore, FrontScore, LoopholeScore, LITMUSScore, ExecutionScore]

# Scout ecosystem types
ScoutEcosystem = Union[ScoutProfile, AnalystProfile, ScoutTelemetry]

# ILF types
ILFTypes = Union[CaseClassification, LawyerProfile, FirmProfile, ILFEngagement]


# ============================================================================
# MODULE SELF-TEST
# ============================================================================

if __name__ == "__main__":
    # Quick smoke test — instantiate every type
    print("GhostLedger Type Definitions — smoke test")
    print("=" * 50)

    ev = EvidenceRef(evidence_type=EvidenceType.TRANSACTION)
    ne = NoiseEvent(noise_type=NoiseType.RUMOR, platform=Platform.TWITTER)
    ss = StormScore(velocity=12.5, volume=200, cross_platform=4, entity_concentration=0.8)
    ss.compute()
    st = Storm(title="Test Storm", score=ss)
    fs = FrontScore(storm_count=3, entity_overlap=0.7, temporal_correlation=0.9, severity_max=0.8)
    fs.compute()
    fr = Front(title="Test Front", score=fs)
    hr = HarmRecord(harm_type=HarmType.WAGE_THEFT, entity_accused="TestCorp")
    vp = VictimShadowProfile(pseudonym="shadow-alpha-7")
    cu = ConsentUnlock(profile_id=vp.profile_id, status=ConsentStatus.GRANTED)
    lc = LITMUSCriterion(letter="L", label="Lives in bear markets", score=0.85)
    ls = LITMUSScore(target_entity="TestProject", criteria=[lc])

    # IntakeSubmission → Claim conversion (mirrors live Google Form)
    intake = IntakeSubmission(
        full_name="Test User",
        email="test@example.com",
        phone="+1-555-0100",
        platform_or_company="Stripe",
        estimated_amount_usd=630.00,
        platform_reason="Payout withheld without explanation for 60 days",
        contacted_support=SupportContactStatus.YES_NO_RESOLUTION,
        referral_source=ReferralSource.REDDIT,
        authorization_granted=True,
    )
    cl = intake.to_claim()  # live form → formal claim

    ee = EscalationEvent(claim_id=cl.claim_id)
    er = ExecutionRecord(claim_id=cl.claim_id, action="filed_claim", actor="agent-001")
    pc = PolicyCondition(field="event.severity", operator="eq", value="critical")
    pa = PolicyAction(action_type="escalate", target="case_manager")
    pr = PolicyRule(name="critical-escalation", law=LawID.DO_NO_HARM, conditions=[pc], actions=[pa])
    gs = GateSignature(signer="verifier", approved=True)
    de = Decision(context_type="claim_action", signatures=[gs])
    hm = HRNMember(role=HRNRole.LEGAL_ADVOCATE, name="Test Advocate")
    he = HRNEngagement(member_id=hm.member_id, profile_id=vp.profile_id, consent_id=cu.consent_id)
    ob = OpportunityBrief(harm_type=HarmType.PLATFORM_LOCKOUT)
    ac = AgentConfig(name="litmus-L-agent", category=AgentCategory.LITMUS_EVALUATION)
    be = BusEvent(topic=EventTopic.CLAIM_FILED, source_agent=ac.agent_id)
    lo = LoopholeScore(complexity=0.7, opacity=0.9, affected_ratio=0.4, precedent=0.6)
    lo.compute()
    es = ExecutionScore(actions_taken=7, escalations=2, evidence_gathered=5, response_time_hours=18)
    es.compute()
    ca = ChainAnchor(tx_signature="abc123", data_hash="sha256hash", record_type="claim")

    # Signal Scouts telemetry
    fix = FixationMetrics(entity_name="BadCorp", reports_on_entity=12,
        total_reports=20)
    fix.compute()
    coord = CoordinationSignal(scout_ids=["s1", "s2", "s3"],
        target_entity="BadCorp", time_window_minutes=15,
        semantic_similarity=0.9)
    coord.evaluate()
    infl = InflationMetrics(scout_id="scout-001",
        avg_severity_claimed=0.8, avg_evidence_quality=0.4, sample_count=30)
    infl.compute()
    lsb = LateStageBias(scout_id="scout-001", total_reports=40,
        reports_on_known_targets=28, sample_period_days=30)
    lsb.compute()
    telem = ScoutTelemetry(scout_id="scout-001",
        fixation_top=fix, coordination_flags=2,
        inflation=infl, late_stage=lsb)
    telem.compute_sqs()

    sp = ScoutProfile(display_name="SignalHawk",
        total_reports=65, confirmed_reports=52, current_sqs=telem.signal_quality_score)
    sp.compute_accuracy()
    sp.check_analyst_eligibility()

    ap = AnalystProfile(scout_id=sp.scout_id, display_name="SignalHawk-Analyst",
        claims_reviewed=12, patterns_identified=3)

    jd = JurisdictionDisclaimer(jurisdiction=JurisdictionCode.US,
        role="scout", text="Not legal advice under US law.")
    jp = JurisdictionPack(jurisdiction=JurisdictionCode.US,
        display_name="United States", disclaimers=[jd],
        data_residency="us-east", currency="USD")

    # Independent Legal Fellowship + Case Classification Engine
    cc = CaseClassification(claim_id=cl.claim_id,
        dispute_type=DisputeType.PAYMENT_WITHHELD,
        jurisdictional_scope=JurisdictionalScope.SINGLE,
        complexity_score=2)
    cc.classify_value_band(cl.amount_claimed_usd)
    cc.check_human_triage()

    lp = LawyerProfile(display_name="J. Recovery Esq.",
        specialties=[LawyerSpecialty.CONSUMER_PROTECTION],
        jurisdictions=[JurisdictionCode.US],
        bar_numbers={"us": "BAR-12345"},
        cases_accepted=40, cases_resolved=32)
    lp.compute_success_rate()

    fp = FirmProfile(name="Digital Rights LLP",
        lawyers=[lp.lawyer_id],
        specialties=[LawyerSpecialty.DIGITAL_RIGHTS],
        jurisdictions=[JurisdictionCode.US, JurisdictionCode.EU])

    ie = ILFEngagement(claim_id=cl.claim_id,
        classification_id=cc.classification_id,
        lawyer_id=lp.lawyer_id,
        fee_structure="contingency",
        coordination_fee_pct=5.0)

    ddc = DesignDoctrineCheck(component="ghostledger_core")

    objects = [
        ev, ne, ss, st, fs, fr, hr, vp, cu, lc, ls, intake, cl, ee, er,
        pc, pa, pr, gs, de, hm, he, ob, ac, be, lo, es, ca,
        fix, coord, infl, lsb, telem, sp, ap, jd, jp,
        cc, lp, fp, ie, ddc,
    ]

    for obj in objects:
        print(f"  \u2713 {type(obj).__name__}")

    print(f"\nAll {len(objects)} types instantiated successfully.")
    print(f"StormScore composite:     {ss.composite:.4f}")
    print(f"FrontScore composite:     {fs.composite:.4f}")
    print(f"LoopholeScore composite:  {lo.composite:.4f}")
    print(f"ExecutionScore composite: {es.composite:.4f}")
    print(f"ConsentUnlock active:     {cu.is_active}")
    print(f"PolicyRule evaluates:     {pr.evaluate({'event': {'severity': 'critical'}})}")
    print(f"\nIntake \u2192 Claim pipeline:")
    print(f"  Intake ID:     {intake.submission_id[:12]}...")
    print(f"  Converted to:  {intake.converted_to_claim_id[:12]}...")
    print(f"  Claim status:  {cl.status.value}")
    print(f"  Respondent:    {cl.respondent_entity}")
    print(f"  Amount:        ${cl.amount_claimed_usd:.2f}")
    print(f"  Support:       {cl.contacted_support.value}")
    print(f"\nSignal Scouts telemetry:")
    print(f"  Fixation score:         {fix.fixation_score:.2f}")
    print(f"  Coordination flagged:   {coord.is_flagged}")
    print(f"  Inflation rate:         {infl.inflation_rate:.2f}")
    print(f"  Late-stage ratio:       {lsb.late_stage_ratio:.2f}")
    print(f"  Signal Quality Score:   {telem.signal_quality_score:.4f}")
    print(f"  Enforcement action:     {telem.enforcement_action.value}")
    print(f"  Scout accuracy:         {sp.accuracy_rate:.2f}")
    print(f"  Analyst eligible:       {sp.eligible_for_analyst}")
    print(f"  Jurisdiction:           {jp.display_name} ({jp.jurisdiction.value})")
    print(f"\nIndependent Legal Fellowship / CCE:")
    print(f"  Case classified:        {cc.dispute_type.value}")
    print(f"  Value band:             {cc.value_band.value}")
    print(f"  Complexity:             {cc.complexity_score}/5")
    print(f"  Human triage needed:    {cc.requires_human_triage}")
    print(f"  Lawyer success rate:    {lp.success_rate:.2f}")
    print(f"  Firm:                   {fp.name}")
    print(f"  Engagement fee:         {ie.fee_structure} + {ie.coordination_fee_pct}% coord")
    print(f"  Design Doctrine passes: {ddc.passes}")
    print(f"\nDone.")
