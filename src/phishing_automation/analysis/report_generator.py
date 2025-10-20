import logging
import csv
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
from collections import defaultdict

from .email_parser import ParsedEmailData
from ..integrations.freshservice.models import PhishingTicketData
from ..integrations.microsoft.models import ExactEmailTrace, SenderHistoryTrace
from .confidence_scorer import PhishingConfidence

logger = logging.getLogger(__name__)


class InvestigationReport:
    """Generate comprehensive investigation reports"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate_basic_report(
        self,
        ticket_data: PhishingTicketData,
        parsed_email: Optional[ParsedEmailData] = None,
        exact_trace: Optional[ExactEmailTrace] = None,
        sender_trace: Optional[SenderHistoryTrace] = None,
        confidence: Optional[PhishingConfidence] = None,
        output_path: Optional[Path] = None
    ) -> str:
        """Generate a basic investigation report"""
        
        try:
            self.logger.info(f"Generating basic report for ticket {ticket_data.ticket.id}")
            
            # Build report content
            report_lines = []
            
            # Header
            report_lines.extend(self._generate_header(ticket_data))
            
            # Ticket Information
            report_lines.extend(self._generate_ticket_section(ticket_data))
            
            # Email Analysis (if available)
            if parsed_email:
                report_lines.extend(self._generate_email_section(parsed_email))

            # Phishing Confidence Score (CRITICAL SECTION)
            if confidence:
                report_lines.extend(self._generate_confidence_section(confidence))

            # Mail Trace Results
            if exact_trace or sender_trace:
                report_lines.extend(self._generate_mail_trace_section(exact_trace, sender_trace))

            # Investigation Summary
            report_lines.extend(self._generate_summary_section(ticket_data, parsed_email, exact_trace, sender_trace))
            
            # Footer
            report_lines.extend(self._generate_footer())
            
            # Combine all sections
            report_content = "\n".join(report_lines)
            
            # Save to file if path provided
            if output_path:
                self._save_report_to_file(report_content, output_path)
            
            self.logger.info(f"Successfully generated investigation report")
            return report_content
            
        except Exception as e:
            self.logger.error(f"Failed to generate investigation report: {e}")
            raise
    
    def _generate_header(self, ticket_data: PhishingTicketData) -> List[str]:
        """Generate report header"""
        return [
            "=" * 80,
            "PHISHING INVESTIGATION REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Report Type: Automated Phishing Analysis",
            "",
        ]
    
    def _generate_ticket_section(self, ticket_data: PhishingTicketData) -> List[str]:
        """Generate ticket information section"""
        ticket = ticket_data.ticket
        
        lines = [
            "TICKET INFORMATION",
            "-" * 40,
            f"Ticket ID: {ticket.id}",
            f"Subject: {ticket.subject}",
            f"Status: {ticket.status_name}",
            f"Priority: {ticket.priority_name}",
            f"Created: {ticket.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if ticket.created_at else 'Unknown'}",
            f"Updated: {ticket.updated_at.strftime('%Y-%m-%d %H:%M:%S UTC') if ticket.updated_at else 'Unknown'}",
            "",
        ]
        
        # Add phish alert specific information
        if ticket_data.reporter_email:
            lines.extend([
                "PHISH ALERT DETAILS",
                "-" * 40,
                f"Reporter: {ticket_data.reporter_email}",
                f"Disposition: {ticket_data.report_disposition or 'Not specified'}",
            ])
            
            if ticket_data.user_comments:
                lines.extend([
                    f"User Comments: {ticket_data.user_comments}",
                ])
            else:
                lines.append("User Comments: None provided")
            
            lines.append("")
        
        # Add .eml attachment information
        if ticket_data.has_eml_attachment():
            eml_info = ticket_data.eml_attachment
            lines.extend([
                "EML ATTACHMENT",
                "-" * 40,
                f"Filename: {eml_info.name}",
                f"Size: {eml_info.size:,} bytes ({eml_info.size / 1024:.1f} KB)",
                f"Content Type: {eml_info.content_type or 'Unknown'}",
                "",
            ])
        
        return lines
    
    def _generate_email_section(self, parsed_email: ParsedEmailData) -> List[str]:
        """Generate email analysis section"""
        lines = [
            "SUSPICIOUS EMAIL ANALYSIS",
            "-" * 40,
            f"From: {parsed_email.sender}",
            f"Subject: {parsed_email.subject}",
            f"Date Received: {parsed_email.date_received.strftime('%Y-%m-%d %H:%M:%S UTC') if parsed_email.date_received else 'Unknown'}",
            f"Message-ID: {parsed_email.message_id}",
            "",
            f"Recipients ({len(parsed_email.recipients)}):",
        ]
        
        # Add recipients
        for i, recipient in enumerate(parsed_email.recipients[:10], 1):  # Limit to first 10
            lines.append(f"  {i}. {recipient}")
        
        if len(parsed_email.recipients) > 10:
            lines.append(f"  ... and {len(parsed_email.recipients) - 10} more recipients")
        
        # Add CC recipients if any
        if parsed_email.cc_recipients:
            lines.extend([
                "",
                f"CC Recipients ({len(parsed_email.cc_recipients)}):",
            ])
            for i, cc_recipient in enumerate(parsed_email.cc_recipients[:5], 1):
                lines.append(f"  {i}. {cc_recipient}")
        
        # Add reply-to if different from sender
        if parsed_email.reply_to and parsed_email.reply_to != parsed_email.sender:
            lines.extend([
                "",
                f"Reply-To: {parsed_email.reply_to}",
                "⚠️  Reply-To differs from sender address",
            ])
        
        # Add attachment information
        if parsed_email.has_attachments:
            lines.extend([
                "",
                f"ATTACHMENTS DETECTED ({len(parsed_email.attachments)}) - NOT OPENED:",
                "-" * 30,
            ])
            
            for i, attachment in enumerate(parsed_email.attachments, 1):
                status = " [POTENTIALLY MALICIOUS]" if attachment.is_potentially_malicious else ""
                size_info = f" ({attachment.size_bytes} bytes)" if attachment.size_bytes else ""
                
                lines.append(f"  {i}. {attachment.filename}{size_info}{status}")
                lines.append(f"     Type: {attachment.content_type}")
        
        # Add security indicators
        if (parsed_email.suspicious_keywords_found or 
            parsed_email.has_external_links or 
            parsed_email.has_suspicious_headers):
            
            lines.extend([
                "",
                "SECURITY INDICATORS",
                "-" * 30,
            ])
            
            if parsed_email.suspicious_keywords_found:
                lines.append(f"Suspicious Keywords: {', '.join(parsed_email.suspicious_keywords_found)}")
            
            if parsed_email.has_external_links:
                lines.append("External Links: Detected in email content")
            
            if parsed_email.has_suspicious_headers:
                lines.append("Suspicious Headers: Detected")
        
        # Add email body preview (limited)
        if parsed_email.text_body:
            lines.extend([
                "",
                "EMAIL CONTENT PREVIEW (First 500 characters):",
                "-" * 50,
                parsed_email.text_body[:500].strip(),
            ])
            
            if len(parsed_email.text_body) > 500:
                lines.append("[CONTENT TRUNCATED - Full content available in parsed email file]")
        
        lines.append("")
        return lines

    def _generate_confidence_section(self, confidence: PhishingConfidence) -> List[str]:
        """Generate phishing confidence score section"""
        lines = [
            "=" * 80,
            "⚠️  PHISHING CONFIDENCE ASSESSMENT",
            "=" * 80,
            "",
            f"CONFIDENCE SCORE: {confidence.score}% ({confidence.confidence_level.value})",
            "",
        ]

        # Add color-coded assessment
        if confidence.confidence_level.value == "CRITICAL":
            lines.extend([
                "🔴 CRITICAL THREAT - Immediate action recommended",
                "This email exhibits multiple strong indicators of phishing.",
                "",
            ])
        elif confidence.confidence_level.value == "HIGH":
            lines.extend([
                "🟠 HIGH RISK - Likely phishing, investigate further",
                "This email shows significant phishing characteristics.",
                "",
            ])
        elif confidence.confidence_level.value == "MEDIUM":
            lines.extend([
                "🟡 MEDIUM RISK - Suspicious, requires review",
                "This email has some concerning indicators.",
                "",
            ])
        else:
            lines.extend([
                "🟢 LOW RISK - Few indicators detected",
                "Limited phishing indicators found, but always verify.",
                "",
            ])

        # Add scoring reasons
        if confidence.reasons:
            lines.append("Factors Contributing to Score:")
            lines.append("-" * 40)

            # Group by severity
            critical_reasons = [r for r in confidence.reasons if r.severity == "CRITICAL"]
            high_reasons = [r for r in confidence.reasons if r.severity == "HIGH"]
            medium_reasons = [r for r in confidence.reasons if r.severity == "MEDIUM"]
            low_reasons = [r for r in confidence.reasons if r.severity == "LOW"]

            for severity_label, reason_list in [
                ("CRITICAL", critical_reasons),
                ("HIGH", high_reasons),
                ("MEDIUM", medium_reasons),
                ("LOW", low_reasons)
            ]:
                if reason_list:
                    for reason in reason_list:
                        lines.append(f"  [{severity_label}] {reason.description} (+{reason.points} points)")

        lines.extend([
            "",
            "=" * 80,
            ""
        ])

        return lines

    def _generate_mail_trace_section(
        self, 
        exact_trace: Optional[ExactEmailTrace], 
        sender_trace: Optional[SenderHistoryTrace]
    ) -> List[str]:
        """Generate mail trace results section"""
        lines = [
            "MAIL TRACE RESULTS",
            "-" * 40,
        ]
        
        # Exact email trace results
        if exact_trace:
            lines.extend([
                "Exact Email Distribution:",
                f"  • This specific phishing email was sent to {exact_trace.unique_recipients} unique recipients",
                f"  • Total message instances: {exact_trace.total_recipients}",
                f"  • Successfully delivered: {exact_trace.delivered_count}",
                f"  • Failed delivery: {exact_trace.failed_count}",
                f"  • Pending delivery: {exact_trace.pending_count}",
                f"  • Trace time window: {exact_trace.trace_start_time.strftime('%Y-%m-%d %H:%M')} to {exact_trace.trace_end_time.strftime('%Y-%m-%d %H:%M')}",
            ])
            
            if exact_trace.export_file_path:
                lines.extend([
                    f"  • Export file: {exact_trace.export_file_path}",
                    f"  • Export size: {exact_trace.export_file_size:,} bytes ({exact_trace.export_record_count} records)",
                ])
        
        lines.append("")
        
        # Sender history trace results
        if sender_trace:
            lines.extend([
                "Sender Email History:",
                f"  • The sender has sent {sender_trace.total_emails_sent} total emails over {sender_trace.days_traced} days",
                f"  • Reached {sender_trace.unique_recipients} unique recipients",
                f"  • Used {sender_trace.unique_subjects} different subject lines",
                f"  • Successfully delivered: {sender_trace.delivered_count}",
                f"  • Failed delivery: {sender_trace.failed_count}",
            ])
            
            if sender_trace.first_email_date and sender_trace.last_email_date:
                lines.extend([
                    f"  • First email: {sender_trace.first_email_date.strftime('%Y-%m-%d %H:%M')}",
                    f"  • Latest email: {sender_trace.last_email_date.strftime('%Y-%m-%d %H:%M')}",
                ])
            
            if sender_trace.export_file_path:
                lines.extend([
                    f"  • Export file: {sender_trace.export_file_path}",
                    f"  • Export size: {sender_trace.export_file_size:,} bytes ({sender_trace.export_record_count} records)",
                ])
        
        lines.append("")
        return lines
    
    def _generate_summary_section(
        self,
        ticket_data: PhishingTicketData,
        parsed_email: Optional[ParsedEmailData],
        exact_trace: Optional[ExactEmailTrace],
        sender_trace: Optional[SenderHistoryTrace]
    ) -> List[str]:
        """Generate investigation summary"""
        lines = [
            "INVESTIGATION SUMMARY",
            "-" * 40,
        ]
        
        # Quick impact assessment
        if exact_trace:
            if exact_trace.unique_recipients > 50:
                impact_level = "HIGH"
            elif exact_trace.unique_recipients > 10:
                impact_level = "MEDIUM"
            else:
                impact_level = "LOW"
            
            lines.append(f"Impact Assessment: {impact_level} ({exact_trace.unique_recipients} recipients affected)")
        
        # Sender reputation indicators
        if sender_trace:
            if sender_trace.total_emails_sent > 100:
                sender_activity = "HIGH VOLUME"
            elif sender_trace.total_emails_sent > 20:
                sender_activity = "MODERATE VOLUME"
            else:
                sender_activity = "LOW VOLUME"
            
            lines.append(f"Sender Activity: {sender_activity} ({sender_trace.total_emails_sent} emails sent)")
        
        # Security concerns
        security_concerns = []
        
        if parsed_email:
            if parsed_email.has_attachments:
                malicious_attachments = [att for att in parsed_email.attachments if att.is_potentially_malicious]
                if malicious_attachments:
                    security_concerns.append(f"Potentially malicious attachments ({len(malicious_attachments)})")
            
            if parsed_email.suspicious_keywords_found:
                security_concerns.append(f"Suspicious keywords detected ({len(parsed_email.suspicious_keywords_found)})")
            
            if parsed_email.reply_to and parsed_email.reply_to != parsed_email.sender:
                security_concerns.append("Reply-To spoofing detected")
        
        if security_concerns:
            lines.extend([
                "",
                "Security Concerns Identified:",
            ])
            for concern in security_concerns:
                lines.append(f"  ⚠️  {concern}")
        
        lines.append("")
        return lines
    
    def _generate_footer(self) -> List[str]:
        """Generate report footer"""
        return [
            "=" * 80,
            "END OF INVESTIGATION REPORT",
            "",
            "IMPORTANT NOTES:",
            "- This is an automated analysis for initial assessment",
            "- Human review is required for final phishing determination",
            "- All email attachments were analyzed for metadata only (NOT opened)",
            "- Mail trace results are based on Exchange Online message tracking",
            "",
            "Next Steps:",
            "1. Review the suspicious email content and attachments",
            "2. Verify sender reputation and domain authenticity",
            "3. Consider blocking sender if confirmed malicious",
            "4. Notify affected users if necessary",
            "5. Update ticket with findings and recommended actions",
            "",
            f"Report generated by Phishing Alert Automation System",
            "=" * 80,
        ]
    
    def _save_report_to_file(self, report_content: str, output_path: Path):
        """Save report to file"""
        try:
            # Ensure directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write report to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            self.logger.info(f"Investigation report saved to: {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save report to {output_path}: {e}")
            raise
    
    def _read_csv_recipients(self, csv_path: str) -> Dict[str, List[str]]:
        """Read CSV and group recipients by delivery status"""
        recipients_by_status = defaultdict(list)

        try:
            csv_file = Path(csv_path)
            if not csv_file.exists():
                self.logger.warning(f"CSV file not found: {csv_path}")
                return {}

            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    recipient = row.get('RecipientAddress', '').strip()
                    status = row.get('Status', 'unknown').strip()

                    if recipient:  # Only add if recipient address exists
                        recipients_by_status[status].append(recipient)

            return dict(recipients_by_status)

        except Exception as e:
            self.logger.error(f"Failed to read CSV file {csv_path}: {e}")
            return {}

    def generate_summary_text(
        self,
        exact_trace: Optional[ExactEmailTrace],
        sender_trace: Optional[SenderHistoryTrace],
        confidence: Optional[PhishingConfidence] = None
    ) -> str:
        """Generate actionable summary text with recipient list and delivery status"""
        summary_parts = []

        # Add confidence score at the top (MOST IMPORTANT!)
        if confidence:
            summary_parts.append("=" * 60)
            summary_parts.append("⚠️  PHISHING CONFIDENCE ASSESSMENT")
            summary_parts.append("=" * 60)
            summary_parts.append(f"SCORE: {confidence.score}% ({confidence.confidence_level.value})")
            summary_parts.append("")

            # Add brief reason summary
            if confidence.reasons:
                summary_parts.append("Key Indicators:")
                for reason in confidence.reasons[:5]:  # Show top 5
                    summary_parts.append(f"  • {reason.description}")
                summary_parts.append("")
            summary_parts.append("")

        # Exact email trace summary
        if exact_trace:
            summary_parts.append("=" * 60)
            summary_parts.append("EXACT EMAIL DISTRIBUTION")
            summary_parts.append("=" * 60)
            summary_parts.append(f"This specific phishing email was sent to {exact_trace.unique_recipients} unique recipients")
            summary_parts.append("")

            # Read recipients from CSV and display by status
            if exact_trace.export_file_path:
                recipients_by_status = self._read_csv_recipients(exact_trace.export_file_path)

                if recipients_by_status:
                    # Display recipients grouped by delivery status
                    status_order = ['delivered', 'pending', 'failed', 'unknown']

                    for status in status_order:
                        if status in recipients_by_status:
                            recipients = recipients_by_status[status]
                            summary_parts.append(f"{status.upper()} ({len(recipients)}):")
                            for recipient in sorted(recipients):
                                summary_parts.append(f"  • {recipient}")
                            summary_parts.append("")

                    summary_parts.append(f"Full details: {exact_trace.export_file_path}")
                else:
                    summary_parts.append("⚠️  CSV file is empty or could not be read")
                    summary_parts.append(f"Expected export: {exact_trace.export_file_path}")
            else:
                summary_parts.append("⚠️  No export file available")

            summary_parts.append("")

        # Sender history summary
        if sender_trace:
            summary_parts.append("=" * 60)
            summary_parts.append("SENDER HISTORY (Past 10 days)")
            summary_parts.append("=" * 60)
            summary_parts.append(f"Sender: {sender_trace.sender_address}")
            summary_parts.append(f"Total emails sent: {sender_trace.total_emails_sent}")
            summary_parts.append(f"Unique recipients: {sender_trace.unique_recipients}")
            summary_parts.append(f"Subject lines used: {sender_trace.unique_subjects}")
            summary_parts.append("")

            # Read recipients from CSV and display by status
            if sender_trace.export_file_path:
                recipients_by_status = self._read_csv_recipients(sender_trace.export_file_path)

                if recipients_by_status:
                    # Display recipients grouped by delivery status
                    status_order = ['delivered', 'pending', 'failed', 'unknown']

                    for status in status_order:
                        if status in recipients_by_status:
                            recipients = recipients_by_status[status]
                            summary_parts.append(f"{status.upper()} ({len(recipients)}):")
                            for recipient in sorted(recipients):
                                summary_parts.append(f"  • {recipient}")
                            summary_parts.append("")

                    summary_parts.append(f"Full details: {sender_trace.export_file_path}")
                else:
                    summary_parts.append("⚠️  CSV file is empty or could not be read")
                    summary_parts.append(f"Expected export: {sender_trace.export_file_path}")
            else:
                summary_parts.append("⚠️  No export file available")

            summary_parts.append("")

        # Add actionable next steps
        if exact_trace or sender_trace:
            summary_parts.append("=" * 60)
            summary_parts.append("ACTION REQUIRED")
            summary_parts.append("=" * 60)
            summary_parts.append("If this is confirmed phishing:")
            summary_parts.append("1. Contact all DELIVERED recipients to warn them")
            summary_parts.append("2. Instruct users to delete the email without opening attachments")
            summary_parts.append("3. Check if any users clicked links or opened attachments")
            summary_parts.append("4. Consider blocking sender domain in email security settings")
            summary_parts.append("")

        return "\n".join(summary_parts)

    def generate_cli_summary(
        self,
        parsed_email: Optional[ParsedEmailData],
        exact_trace: Optional[ExactEmailTrace],
        sender_trace: Optional[SenderHistoryTrace],
        confidence: Optional[PhishingConfidence]
    ) -> List[str]:
        """Generate ultra-concise 3-4 line summary for CLI display"""
        lines = []

        # Line 1: Recipient information
        if exact_trace and exact_trace.unique_recipients > 0:
            lines.append(f"Email sent to {exact_trace.unique_recipients} recipients")
        elif sender_trace:
            lines.append(f"Email traced (sender history available)")
        elif parsed_email:
            lines.append(f"Email analyzed")
        else:
            lines.append("Investigation completed")

        # Line 2: Confidence score + brief reasons
        if confidence:
            # Get top 2 most important reasons
            top_reasons = sorted(confidence.reasons, key=lambda r: r.points, reverse=True)[:2]
            reason_text = ", ".join([r.description.split(':')[0] for r in top_reasons]) if top_reasons else "No indicators"

            lines.append(f"Confidence: {confidence.score}% ({confidence.confidence_level.value}) - {reason_text}")

        # Line 3: Sender history summary
        if sender_trace:
            lines.append(f"Sender history: {sender_trace.total_emails_sent} emails to {sender_trace.unique_recipients} unique recipients over {sender_trace.days_traced} days")

        return lines