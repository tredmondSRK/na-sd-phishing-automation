import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from .email_parser import ParsedEmailData
from ..integrations.microsoft.models import ExactEmailTrace, SenderHistoryTrace

logger = logging.getLogger(__name__)


class ConfidenceLevel(str, Enum):
    """Phishing confidence levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScoringReason:
    """Individual reason contributing to phishing score"""
    category: str
    description: str
    points: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class PhishingConfidence:
    """Complete phishing confidence assessment"""
    score: int  # 0-100
    confidence_level: ConfidenceLevel
    reasons: List[ScoringReason]
    total_points_possible: int

    def get_summary(self) -> str:
        """Get human-readable summary"""
        summary_lines = [
            f"PHISHING CONFIDENCE: {self.score}% ({self.confidence_level.value})",
            "",
            "Reasons:"
        ]

        # Group reasons by severity
        critical_reasons = [r for r in self.reasons if r.severity == "CRITICAL"]
        high_reasons = [r for r in self.reasons if r.severity == "HIGH"]
        medium_reasons = [r for r in self.reasons if r.severity == "MEDIUM"]
        low_reasons = [r for r in self.reasons if r.severity == "LOW"]

        for reason_list in [critical_reasons, high_reasons, medium_reasons, low_reasons]:
            for reason in reason_list:
                summary_lines.append(f"  • {reason.description} (+{reason.points} points)")

        if not self.reasons:
            summary_lines.append("  • No significant phishing indicators detected")

        return "\n".join(summary_lines)


class PhishingConfidenceScorer:
    """Calculate phishing confidence score based on multiple indicators"""

    # Scoring weights for various indicators
    WEIGHTS = {
        # Email content indicators (original)
        "suspicious_keyword": 10,  # per keyword, max 30
        "malicious_attachment": 30,
        "external_links": 10,
        "reply_to_spoofing": 20,
        "external_domain": 15,

        # NEW: High-priority email content indicators
        "company_name_impersonation": 60,  # CRITICAL - "Srk"/"srk" detected
        "display_name_spoofing": 40,       # HIGH - department name from external domain
        "display_name_unusual": 15,        # MEDIUM - department name from internal domain
        "financial_request": 30,           # HIGH - wire transfer, gift cards, etc.
        "credential_harvesting": 30,       # HIGH - password verification requests
        "misspelled_domain": 40,           # HIGH - typosquatting
        "html_form_embedded": 35,          # HIGH - embedded credential forms
        "url_shortener": 20,               # MEDIUM - bit.ly, tinyurl, etc.
        "subject_line_trick": 25,          # MEDIUM - fake Re:/Fwd:
        "time_pressure": 15,               # MEDIUM - urgency language

        # Mail trace pattern indicators
        "mass_distribution_small": 15,     # 10-20 recipients
        "mass_distribution_medium": 30,    # 21-50 recipients
        "mass_distribution_large": 50,     # 50+ recipients
        "external_to_multiple_internal": 20,
        "burst_sending": 15,
        "suspicious_subject_pattern": 10,
        "new_sender": 10,                  # LOW - first email from sender
    }

    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.org_domains = config.get_organization_domains() if config else []
        self.org_name = config.organization_name if config else "SRK Consulting"

    def calculate_confidence(
        self,
        parsed_email: Optional[ParsedEmailData],
        exact_trace: Optional[ExactEmailTrace],
        sender_trace: Optional[SenderHistoryTrace]
    ) -> PhishingConfidence:
        """Calculate phishing confidence score from all available data"""

        self.logger.info("Calculating phishing confidence score...")

        reasons: List[ScoringReason] = []
        total_score = 0

        # Analyze email content indicators
        if parsed_email:
            email_reasons, email_score = self._analyze_email_indicators(parsed_email)
            reasons.extend(email_reasons)
            total_score += email_score

        # Analyze mail trace patterns
        if sender_trace:
            trace_reasons, trace_score = self._analyze_mail_trace_patterns(
                parsed_email, exact_trace, sender_trace
            )
            reasons.extend(trace_reasons)
            total_score += trace_score

        # Cap score at 100
        final_score = min(total_score, 100)

        # Determine confidence level
        confidence_level = self._get_confidence_level(final_score)

        self.logger.info(f"Phishing confidence calculated: {final_score}% ({confidence_level.value})")
        self.logger.info(f"Reasons found: {len(reasons)}")

        return PhishingConfidence(
            score=final_score,
            confidence_level=confidence_level,
            reasons=reasons,
            total_points_possible=200  # Theoretical max before capping
        )

    def _analyze_email_indicators(
        self,
        parsed_email: ParsedEmailData
    ) -> Tuple[List[ScoringReason], int]:
        """Analyze email content for phishing indicators"""
        reasons: List[ScoringReason] = []
        score = 0

        # ===== NEW HIGH-PRIORITY CHECKS =====

        # 1. Company name impersonation (CRITICAL - highest priority)
        impersonation_reasons, impersonation_score = self._check_company_impersonation(parsed_email)
        reasons.extend(impersonation_reasons)
        score += impersonation_score

        # 2. Display name spoofing
        display_reasons, display_score = self._check_display_name_spoofing(parsed_email)
        reasons.extend(display_reasons)
        score += display_score

        # 3. Financial request language
        financial_reasons, financial_score = self._check_financial_language(parsed_email)
        reasons.extend(financial_reasons)
        score += financial_score

        # 4. Credential harvesting
        credential_reasons, credential_score = self._check_credential_harvesting(parsed_email)
        reasons.extend(credential_reasons)
        score += credential_score

        # 5. Domain misspelling
        domain_reasons, domain_score = self._check_domain_misspelling(parsed_email)
        reasons.extend(domain_reasons)
        score += domain_score

        # 6. HTML forms embedded
        form_reasons, form_score = self._check_html_forms(parsed_email)
        reasons.extend(form_reasons)
        score += form_score

        # 7. URL shorteners
        url_reasons, url_score = self._check_url_shorteners(parsed_email)
        reasons.extend(url_reasons)
        score += url_score

        # 8. Subject line tricks
        subject_reasons, subject_score = self._check_subject_tricks(parsed_email)
        reasons.extend(subject_reasons)
        score += subject_score

        # 9. Time pressure language
        time_reasons, time_score = self._check_time_pressure(parsed_email)
        reasons.extend(time_reasons)
        score += time_score

        # ===== ORIGINAL CHECKS =====

        # Suspicious keywords (max 3 keywords = +30)
        if parsed_email.suspicious_keywords_found:
            keyword_count = min(len(parsed_email.suspicious_keywords_found), 3)
            points = keyword_count * self.WEIGHTS["suspicious_keyword"]
            score += points

            keywords_str = ", ".join(parsed_email.suspicious_keywords_found[:3])
            reasons.append(ScoringReason(
                category="Email Content",
                description=f"Suspicious keywords detected: {keywords_str} ({keyword_count})",
                points=points,
                severity="MEDIUM"
            ))

        # Malicious attachments
        if parsed_email.has_attachments:
            malicious_attachments = [
                att for att in parsed_email.attachments
                if att.is_potentially_malicious
            ]

            if malicious_attachments:
                points = self.WEIGHTS["malicious_attachment"]
                score += points

                filenames = ", ".join([att.filename for att in malicious_attachments])
                reasons.append(ScoringReason(
                    category="Attachments",
                    description=f"Potentially malicious attachment(s): {filenames}",
                    points=points,
                    severity="HIGH"
                ))

        # External links in email
        if parsed_email.has_external_links:
            points = self.WEIGHTS["external_links"]
            score += points

            reasons.append(ScoringReason(
                category="Email Content",
                description="External links detected in email body",
                points=points,
                severity="LOW"
            ))

        # Reply-to spoofing
        if parsed_email.reply_to and parsed_email.reply_to != parsed_email.sender:
            points = self.WEIGHTS["reply_to_spoofing"]
            score += points

            reasons.append(ScoringReason(
                category="Email Headers",
                description=f"Reply-To address differs from sender (Reply-To: {parsed_email.reply_to})",
                points=points,
                severity="HIGH"
            ))

        # External domain check
        if parsed_email.sender:
            sender_domain = parsed_email.sender.split('@')[-1].lower()
            self.logger.debug(f"Sender domain: {sender_domain}")

        return reasons, score

    def _analyze_mail_trace_patterns(
        self,
        parsed_email: Optional[ParsedEmailData],
        exact_trace: Optional[ExactEmailTrace],
        sender_trace: SenderHistoryTrace
    ) -> Tuple[List[ScoringReason], int]:
        """Analyze mail trace data for phishing patterns"""
        reasons: List[ScoringReason] = []
        score = 0

        # Mass distribution detection (KEY INDICATOR!)
        # "Same subject to 40 people = high confidence phishing"
        unique_recipients = sender_trace.unique_recipients

        if unique_recipients >= 50:
            points = self.WEIGHTS["mass_distribution_large"]
            score += points
            reasons.append(ScoringReason(
                category="Distribution Pattern",
                description=f"CRITICAL: Mass distribution detected - {unique_recipients} unique recipients",
                points=points,
                severity="CRITICAL"
            ))

        elif unique_recipients >= 21:
            points = self.WEIGHTS["mass_distribution_medium"]
            score += points
            reasons.append(ScoringReason(
                category="Distribution Pattern",
                description=f"Mass distribution detected - {unique_recipients} unique recipients",
                points=points,
                severity="HIGH"
            ))

        elif unique_recipients >= 10:
            points = self.WEIGHTS["mass_distribution_small"]
            score += points
            reasons.append(ScoringReason(
                category="Distribution Pattern",
                description=f"Multiple recipients from same sender - {unique_recipients} unique recipients",
                points=points,
                severity="MEDIUM"
            ))

        # Check for same subject to multiple people
        # If sender history shows LOW subject diversity but HIGH recipient count = phishing pattern
        if sender_trace.unique_subjects <= 3 and unique_recipients >= 10:
            points = self.WEIGHTS["suspicious_subject_pattern"]
            score += points
            reasons.append(ScoringReason(
                category="Distribution Pattern",
                description=f"Same subject line(s) sent to {unique_recipients} recipients (pattern: mass phishing)",
                points=points,
                severity="HIGH"
            ))

        # Burst sending pattern (many emails in short time)
        if sender_trace.first_email_date and sender_trace.last_email_date:
            time_diff = (sender_trace.last_email_date - sender_trace.first_email_date).total_seconds()
            emails_per_hour = (sender_trace.total_emails_sent / max(time_diff / 3600, 0.01))

            # If more than 10 emails per hour = suspicious burst
            if emails_per_hour > 10 and sender_trace.total_emails_sent >= 10:
                points = self.WEIGHTS["burst_sending"]
                score += points
                reasons.append(ScoringReason(
                    category="Sending Pattern",
                    description=f"Burst sending detected - {sender_trace.total_emails_sent} emails in short timeframe",
                    points=points,
                    severity="MEDIUM"
                ))

        # External sender to multiple internal recipients
        # This would require knowing your organization's domain
        # For now, just check if sender has external-looking domain and high recipient count
        if parsed_email and parsed_email.sender:
            sender_domain = parsed_email.sender.split('@')[-1].lower()
            # Common external domains that might be spoofed
            suspicious_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']

            if any(domain in sender_domain for domain in suspicious_domains) and unique_recipients >= 5:
                points = self.WEIGHTS["external_to_multiple_internal"]
                score += points
                reasons.append(ScoringReason(
                    category="Sender Pattern",
                    description=f"External sender ({sender_domain}) to multiple recipients",
                    points=points,
                    severity="MEDIUM"
                ))

        # Check for new sender pattern
        if sender_trace.total_emails_sent == 1:
            points = self.WEIGHTS["new_sender"]
            score += points
            reasons.append(ScoringReason(
                category="Sender Pattern",
                description="First email from this sender to organization",
                points=points,
                severity="LOW"
            ))

        return reasons, score

    def _check_company_impersonation(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for company name impersonation (CRITICAL indicator)"""
        reasons: List[ScoringReason] = []
        score = 0

        # Search for "Srk" or "srk" but NOT "SRK" (exact case)
        search_text = f"{parsed_email.subject} {parsed_email.sender_display_name} {parsed_email.text_body} {parsed_email.html_body}"

        # Pattern: Find "srk" or "Srk" but not "SRK"
        import re
        # This regex finds "srk" in any case EXCEPT all caps
        impersonation_patterns = [
            r'\bsrk\b',   # lowercase "srk"
            r'\bSrk\b',   # Title case "Srk"
            r'\bsRk\b',   # Mixed case variations
            r'\bsrK\b',
            r'\bSRk\b',
            r'\bsRK\b',
            r'\bSrK\b',
        ]

        for pattern in impersonation_patterns:
            if re.search(pattern, search_text):
                points = self.WEIGHTS["company_name_impersonation"]
                score += points
                reasons.append(ScoringReason(
                    category="Company Impersonation",
                    description=f"CRITICAL: Company name impersonation detected - '{self.org_name}' misspelled (not 'SRK')",
                    points=points,
                    severity="CRITICAL"
                ))
                break  # Only count once

        return reasons, score

    def _check_display_name_spoofing(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for display name spoofing (department impersonation)"""
        reasons: List[ScoringReason] = []
        score = 0

        if not parsed_email.sender_display_name:
            return reasons, score

        display_name_lower = parsed_email.sender_display_name.lower()
        sender_domain = parsed_email.sender.split('@')[-1].lower() if parsed_email.sender else ""

        # Department keywords to check for
        department_keywords = ['srk', 'it', 'accounting', 'finance', 'hr', 'human resources',
                              'payroll', 'admin', 'support', 'helpdesk', 'security']

        has_department_keyword = any(keyword in display_name_lower for keyword in department_keywords)

        if has_department_keyword:
            # Check if sender is from external domain
            is_external = sender_domain not in self.org_domains

            if is_external:
                points = self.WEIGHTS["display_name_spoofing"]
                score += points
                reasons.append(ScoringReason(
                    category="Display Name Spoofing",
                    description=f"Display name '{parsed_email.sender_display_name}' appears to be internal department but from external domain ({sender_domain})",
                    points=points,
                    severity="HIGH"
                ))
            else:
                # Internal domain with department name - unusual but not critical
                points = self.WEIGHTS["display_name_unusual"]
                score += points
                reasons.append(ScoringReason(
                    category="Display Name Pattern",
                    description=f"Display name contains department keyword - unusual pattern for {self.org_name}",
                    points=points,
                    severity="MEDIUM"
                ))

        return reasons, score

    def _check_financial_language(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for financial request language"""
        reasons: List[ScoringReason] = []
        score = 0

        if parsed_email.financial_keywords_found:
            points = self.WEIGHTS["financial_request"]
            score += points

            keywords_str = ", ".join(parsed_email.financial_keywords_found[:3])
            reasons.append(ScoringReason(
                category="Financial Request",
                description=f"Financial request language detected: {keywords_str}",
                points=points,
                severity="HIGH"
            ))

        return reasons, score

    def _check_credential_harvesting(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for credential harvesting language"""
        reasons: List[ScoringReason] = []
        score = 0

        if parsed_email.credential_keywords_found:
            points = self.WEIGHTS["credential_harvesting"]
            score += points

            keywords_str = ", ".join(parsed_email.credential_keywords_found[:3])
            reasons.append(ScoringReason(
                category="Credential Harvesting",
                description=f"Credential harvesting language detected: {keywords_str}",
                points=points,
                severity="HIGH"
            ))

        return reasons, score

    def _check_domain_misspelling(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for common domain misspellings"""
        reasons: List[ScoringReason] = []
        score = 0

        if not parsed_email.sender:
            return reasons, score

        sender_domain = parsed_email.sender.split('@')[-1].lower()

        # Common misspellings and typosquatting patterns
        suspicious_patterns = {
            'microsft': 'microsoft',
            'micr0soft': 'microsoft',
            'paypa1': 'paypal',
            'paypai': 'paypal',
            'amazom': 'amazon',
            'arnazon': 'amazon',
            'goog1e': 'google',
            'googlc': 'google',
            'app1e': 'apple',
            'yah00': 'yahoo',
        }

        for typo, legit in suspicious_patterns.items():
            if typo in sender_domain:
                points = self.WEIGHTS["misspelled_domain"]
                score += points
                reasons.append(ScoringReason(
                    category="Domain Spoofing",
                    description=f"Misspelled domain detected: '{sender_domain}' (possible '{legit}' impersonation)",
                    points=points,
                    severity="HIGH"
                ))
                break

        return reasons, score

    def _check_url_shorteners(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for URL shorteners"""
        reasons: List[ScoringReason] = []
        score = 0

        if parsed_email.has_url_shorteners:
            points = self.WEIGHTS["url_shortener"]
            score += points
            reasons.append(ScoringReason(
                category="URL Analysis",
                description="URL shorteners detected (hide true destination)",
                points=points,
                severity="MEDIUM"
            ))

        return reasons, score

    def _check_html_forms(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for embedded HTML forms"""
        reasons: List[ScoringReason] = []
        score = 0

        if parsed_email.has_html_forms:
            points = self.WEIGHTS["html_form_embedded"]
            score += points
            reasons.append(ScoringReason(
                category="Email Content",
                description="HTML form embedded in email (direct credential theft attempt)",
                points=points,
                severity="HIGH"
            ))

        return reasons, score

    def _check_subject_tricks(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for subject line tricks"""
        reasons: List[ScoringReason] = []
        score = 0

        if parsed_email.has_subject_trick:
            points = self.WEIGHTS["subject_line_trick"]
            score += points
            reasons.append(ScoringReason(
                category="Email Headers",
                description="Subject starts with 'Re:' or 'Fwd:' but no conversation history",
                points=points,
                severity="MEDIUM"
            ))

        return reasons, score

    def _check_time_pressure(self, parsed_email: ParsedEmailData) -> Tuple[List[ScoringReason], int]:
        """Check for time pressure language"""
        reasons: List[ScoringReason] = []
        score = 0

        if parsed_email.time_pressure_keywords_found:
            points = self.WEIGHTS["time_pressure"]
            score += points

            keywords_str = ", ".join(parsed_email.time_pressure_keywords_found[:2])
            reasons.append(ScoringReason(
                category="Urgency Tactics",
                description=f"Time pressure language detected: {keywords_str}",
                points=points,
                severity="MEDIUM"
            ))

        return reasons, score

    def _get_confidence_level(self, score: int) -> ConfidenceLevel:
        """Convert numerical score to confidence level"""
        if score >= 86:
            return ConfidenceLevel.CRITICAL
        elif score >= 61:
            return ConfidenceLevel.HIGH
        elif score >= 31:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW
