from typing import Dict, Any, Optional
import logging
from pathlib import Path
from rich.console import Console

from ..utils.logger import get_logger, get_ticket_logger, log_action
from ..integrations.freshservice.client import FreshServiceClient, FreshServiceError
from ..integrations.freshservice.models import Ticket, TicketConversation, PhishingTicketData
from ..integrations.microsoft import DefenderClient, ExchangeClient, DefenderClientError, ExchangeClientError
from ..analysis import EmailParser, ParsedEmailData, EmailParsingError, InvestigationReport, PhishingConfidenceScorer
from .config import Config

logger = get_logger(__name__)
console = Console()  # Clean console output for user-facing messages


class PhishingInvestigator:
    def __init__(self, config: Config):
        self.config = config
        self.freshservice_client = None
        self.defender_client = None
        self.exchange_client = None
        self.email_parser = EmailParser()
        self.report_generator = InvestigationReport()
        self.confidence_scorer = PhishingConfidenceScorer(config=config)
        
        # Initialize FreshService client
        if config.is_freshservice_configured():
            self.freshservice_client = FreshServiceClient(
                config.freshservice_domain,
                config.freshservice_api_key
            )
        else:
            logger.warning("FreshService not configured")
        
        # Initialize Microsoft clients separately to allow partial configuration
        if config.is_microsoft_configured():
            # Initialize Exchange client (works with user email OR app registration)
            try:
                self.exchange_client = ExchangeClient(config)
                logger.info("Exchange client initialized successfully")
            except Exception as e:
                logger.warning(f"Exchange client initialization failed: {e}")
                self.exchange_client = None
            
            # Initialize Defender client (requires app registration only)
            if config.microsoft_tenant_id and config.microsoft_client_id and config.microsoft_client_secret:
                try:
                    self.defender_client = DefenderClient(config)
                    logger.info("Defender client initialized successfully")
                except Exception as e:
                    logger.warning(f"Defender client initialization failed: {e}")
                    self.defender_client = None
            else:
                logger.info("Defender client skipped (requires app registration)")
                self.defender_client = None
        else:
            logger.warning("Microsoft not configured")
            self.exchange_client = None
            self.defender_client = None
    
    def investigate_ticket(self, ticket_id: int) -> Dict[str, Any]:
        """
        Main investigation method - now with full end-to-end functionality
        """
        ticket_logger = get_ticket_logger(ticket_id)
        ticket_logger.info(f"Starting investigation of ticket {ticket_id}")
        
        log_action(ticket_id, "INVESTIGATION_STARTED")
        
        try:
            # Create ticket folder for outputs
            ticket_folder = Path(self.config.reports_dir) / f"TICKET_{ticket_id}"
            ticket_folder.mkdir(parents=True, exist_ok=True)

            # Phase 1: Basic ticket retrieval
            console.print(f"[cyan]Retrieving ticket {ticket_id}...[/cyan]")
            ticket_data = self._retrieve_ticket_data(ticket_id)
            log_action(ticket_id, "TICKET_DATA_RETRIEVED")
            
            # Phase 2: Email data collection and analysis
            parsed_email = None
            logger.info(f"[ORCHESTRATOR] Checking for .eml attachment...")
            logger.info(f"[ORCHESTRATOR] ticket_data.eml_attachment = {ticket_data.eml_attachment}")
            logger.info(f"[ORCHESTRATOR] has_eml_attachment() = {ticket_data.has_eml_attachment()}")

            if ticket_data.has_eml_attachment():
                logger.info(f"[ORCHESTRATOR] [FOUND] .eml attachment found: {ticket_data.get_eml_attachment_name()}")
                console.print("[green]Found suspected phishing email attachment[/green]")
                parsed_email = self._collect_and_parse_email_data(ticket_data, ticket_folder)
                if parsed_email:
                    console.print(f"[yellow]Suspected sender: {parsed_email.sender}[/yellow]")
                log_action(ticket_id, "EMAIL_DATA_PARSED")
            else:
                logger.warning(f"[ORCHESTRATOR] [NOT FOUND] No .eml attachment found in ticket {ticket_id}")
                console.print("[yellow]No email attachment found in ticket[/yellow]")
            
            # Phase 2: Mail trace execution
            exact_trace = None
            sender_trace = None

            if parsed_email and self.exchange_client:
                console.print("[cyan]Running mail trace...[/cyan]")
                exact_trace, sender_trace = self._perform_mail_traces(parsed_email, ticket_folder)
                log_action(ticket_id, "MAIL_TRACES_COMPLETED")
            else:
                logger.warning("Skipping mail traces - missing email data or Exchange client")

            # Phase 3: Phishing confidence scoring
            confidence = None
            if parsed_email:  # Need at least parsed email to score
                console.print("[cyan]Calculating confidence score...[/cyan]")
                confidence = self._calculate_phishing_confidence(parsed_email, exact_trace, sender_trace)
                log_action(ticket_id, "CONFIDENCE_CALCULATED", f"Score: {confidence.score}%")

            # Phase 4: Report generation
            console.print("[cyan]Generating investigation report...[/cyan]")
            report_content = self._generate_investigation_report(
                ticket_data, parsed_email, exact_trace, sender_trace, confidence, ticket_folder
            )
            log_action(ticket_id, "REPORT_GENERATED")
            
            # Return investigation results
            results = {
                "status": "success",
                "ticket_id": ticket_id,
                "ticket_folder": str(ticket_folder),
                "has_email_data": parsed_email is not None,
                "has_mail_traces": exact_trace is not None or sender_trace is not None,
                "report_path": str(ticket_folder / "investigation_report.txt"),
                "parsed_email": parsed_email,
                "confidence": confidence
            }

            # Add trace summaries if available
            if exact_trace:
                results["exact_email_recipients"] = exact_trace.unique_recipients
                results["exact_email_export"] = exact_trace.export_file_path

            if sender_trace:
                results["sender_total_emails"] = sender_trace.total_emails_sent
                results["sender_unique_recipients"] = sender_trace.unique_recipients
                results["sender_export"] = sender_trace.export_file_path
            
            log_action(ticket_id, "INVESTIGATION_COMPLETED")
            logger.info(f"Investigation completed successfully for ticket {ticket_id}")
            
            return results
            
        except Exception as e:
            logger.error(f"Investigation failed for ticket {ticket_id}: {e}")
            log_action(ticket_id, "INVESTIGATION_FAILED", str(e))
            raise
    
    def _retrieve_ticket_data(self, ticket_id: int) -> PhishingTicketData:
        """Retrieve ticket and conversation data from FreshService"""
        if not self.freshservice_client:
            raise ValueError("FreshService not configured")
        
        logger.info(f"Retrieving ticket data for {ticket_id}")
        
        # Get ticket details
        ticket_raw = self.freshservice_client.get_ticket(ticket_id)
        ticket = Ticket(**ticket_raw)
        
        # Get conversations
        conversations_raw = self.freshservice_client.get_ticket_conversations(ticket_id)
        conversations = [TicketConversation(**conv) for conv in conversations_raw]
        
        # Create consolidated ticket data
        ticket_data = PhishingTicketData(
            ticket=ticket,
            conversations=conversations
        )
        
        # Extract email details if present
        ticket_data.extract_email_details()
        
        # Validate this is a phishing-related ticket
        if not ticket.is_phishing_related():
            logger.warning(f"Ticket {ticket_id} may not be phishing-related")
        
        return ticket_data
    
    def _collect_and_parse_email_data(self, ticket_data: PhishingTicketData, ticket_folder: Path) -> Optional[ParsedEmailData]:
        """Securely download and parse the .eml attachment"""
        temp_eml_path = None
        try:
            logger.info("[SECURE] Starting secure email data collection")
            
            # Check if we have an attachment to download
            if not ticket_data.eml_attachment:
                logger.warning("No .eml attachment found in ticket data")
                return None
            
            # Securely download to temp directory
            logger.info(f"[SECURE] Downloading attachment: {ticket_data.eml_attachment.name}")
            temp_eml_path, parsed_data_path = self.freshservice_client.download_attachment_securely(
                attachment_url=ticket_data.eml_attachment.download_url,
                attachment_name=ticket_data.eml_attachment.name,
                save_folder=ticket_folder
            )
            
            if not temp_eml_path:
                logger.error("[SECURE] Failed to download attachment securely")
                return None
            
            logger.info(f"[SECURE] Parsing .eml file from temp location")
            
            # Parse the .eml file from temp location
            parsed_email = self.email_parser.parse_eml_file(temp_eml_path)
            
            # Save parsed data to permanent location (safe text only)
            if parsed_data_path:
                self.email_parser.save_parsed_data_to_file(parsed_email, parsed_data_path)
                logger.info(f"[SECURE] Saved parsed data to: {parsed_data_path}")
            
            # Log security summary
            logger.info(f"[SECURE] Email parsed successfully")
            logger.info(f"  Sender: {parsed_email.sender}")
            logger.info(f"  Subject: {parsed_email.subject}")
            logger.info(f"  Recipients: {len(parsed_email.recipients)}")
            
            if parsed_email.attachments:
                logger.warning(f"[SECURE] Email contained {len(parsed_email.attachments)} attachments (NOT extracted):")
                for att in parsed_email.attachments:
                    logger.warning(f"  - {att.filename} ({att.size_bytes} bytes) - NOT DOWNLOADED")
            
            return parsed_email
            
        except EmailParsingError as e:
            logger.error(f"[SECURE] Email parsing failed: {e}")
            return None
        except FreshServiceError as e:
            logger.error(f"[SECURE] Failed to download .eml attachment: {e}")
            return None
        except Exception as e:
            logger.error(f"[SECURE] Unexpected error during email collection: {e}")
            return None
        finally:
            # ALWAYS clean up temp file
            if temp_eml_path:
                logger.info("[SECURE] Cleaning up temporary files")
                self.freshservice_client.cleanup_temp_directory(temp_eml_path)
                logger.info("[SECURE] Temporary files removed")
    
    def _perform_mail_traces(self, parsed_email: ParsedEmailData, ticket_folder: Path) -> tuple[Optional[Any], Optional[Any]]:
        """Perform both exact email trace and sender history trace"""
        exact_trace = None
        sender_trace = None
        
        try:
            logger.info("Performing mail traces")
            
            # Check if we have the required data
            if not parsed_email.date_received or not parsed_email.subject:
                logger.warning("Skipping mail traces - missing date or subject")
                return None, None
            
            # Use combined trace method to minimize auth prompts
            logger.info(f"Running combined mail traces for: {parsed_email.sender[:50]}...")
            logger.info(f"Subject: '{parsed_email.subject[:50]}'")

            # Run both traces in a single PowerShell session
            # For phishing investigation, focus on sender behavior patterns:
            # - 48-hour window for exact trace (catches forwarded/delayed phishing reports)
            # - 10-day sender history (focuses on recent phishing campaigns)
            exact_trace, sender_trace = self.exchange_client.trace_combined(
                sender=parsed_email.sender,
                subject=parsed_email.subject,
                received_time=parsed_email.date_received,
                tolerance_minutes=2880,  # 48 hours - accounts for reporting delays, forwarding, timezone differences
                days_back=10,  # 10 days - captures recent phishing campaigns only
                ticket_folder=ticket_folder
            )
            
            if exact_trace:
                logger.info(f"Exact email trace completed: {exact_trace.unique_recipient_count} unique recipients")
            else:
                logger.warning("Exact email trace returned no results")
                
            if sender_trace:
                logger.info(f"Sender history trace completed: {sender_trace.total_emails_sent} total emails")
            else:
                logger.warning("Sender history trace returned no results")
            
        except ExchangeClientError as e:
            logger.error(f"Mail trace failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during mail traces: {e}")
        
        return exact_trace, sender_trace

    def _calculate_phishing_confidence(
        self,
        parsed_email: ParsedEmailData,
        exact_trace: Optional[Any],
        sender_trace: Optional[Any]
    ):
        """Calculate phishing confidence score"""
        try:
            logger.info("Calculating phishing confidence score...")

            confidence = self.confidence_scorer.calculate_confidence(
                parsed_email=parsed_email,
                exact_trace=exact_trace,
                sender_trace=sender_trace
            )

            logger.info(f"Phishing confidence: {confidence.score}% ({confidence.confidence_level.value})")
            logger.info(f"Indicators found: {len(confidence.reasons)}")

            return confidence

        except Exception as e:
            logger.error(f"Failed to calculate phishing confidence: {e}")
            return None

    def _generate_investigation_report(
        self,
        ticket_data: PhishingTicketData,
        parsed_email: Optional[ParsedEmailData],
        exact_trace: Optional[Any],
        sender_trace: Optional[Any],
        confidence: Optional[Any],
        ticket_folder: Path
    ) -> str:
        """Generate comprehensive investigation report"""
        try:
            logger.info("Generating investigation report")
            
            # Generate report
            report_path = ticket_folder / "investigation_report.txt"
            report_content = self.report_generator.generate_basic_report(
                ticket_data=ticket_data,
                parsed_email=parsed_email,
                exact_trace=exact_trace,
                sender_trace=sender_trace,
                confidence=confidence,
                output_path=report_path
            )
            
            # Also generate the specific summary format requested by user
            if exact_trace or sender_trace:
                summary_text = self.report_generator.generate_summary_text(exact_trace, sender_trace, confidence)
                
                # Save summary separately
                summary_path = ticket_folder / "mail_trace_summary.txt"
                with open(summary_path, 'w', encoding='utf-8') as f:
                    f.write("MAIL TRACE SUMMARY\n")
                    f.write("==================\n\n")
                    f.write(summary_text)
                
                logger.info(f"Mail trace summary saved to: {summary_path}")
            
            logger.info(f"Investigation report generated: {report_path}")
            return report_content
            
        except Exception as e:
            logger.error(f"Failed to generate investigation report: {e}")
            raise
    
    def validate_configuration(self) -> Dict[str, bool]:
        """Validate system configuration and connectivity"""
        results = {
            "freshservice_configured": self.config.is_freshservice_configured(),
            "freshservice_connected": False,
            "microsoft_configured": self.config.is_microsoft_configured(),
            "directories_ready": False
        }
        
        # Test FreshService connection
        if self.freshservice_client:
            try:
                results["freshservice_connected"] = self.freshservice_client.validate_connection()
            except Exception as e:
                logger.error(f"FreshService connection test failed: {e}")
        
        # Check directories
        try:
            self.config.setup_directories()
            results["directories_ready"] = True
        except Exception as e:
            logger.error(f"Directory setup failed: {e}")
        
        return results