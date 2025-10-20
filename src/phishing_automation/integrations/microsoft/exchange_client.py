import logging
import subprocess
import json
import csv
import tempfile
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

# Only import MicrosoftAuthenticator if needed for app-based auth
try:
    from .auth import MicrosoftAuthenticator
except ImportError:
    MicrosoftAuthenticator = None
from .models import (
    MailTraceResult, ExactEmailTrace, SenderHistoryTrace, 
    PowerShellExecutionResult, ConnectionTestResult,
    MailTraceStatus
)
from ...core.config import Config

logger = logging.getLogger(__name__)


class ExchangeClientError(Exception):
    pass


class ExchangeClient:
    """Exchange Online PowerShell client for mail trace operations (READ-ONLY)"""
    
    def __init__(self, config: Config):
        self.config = config
        
        # Only initialize MicrosoftAuthenticator if app credentials are configured
        self.authenticator = None
        if (config.microsoft_tenant_id and config.microsoft_client_id and 
            config.microsoft_client_secret and MicrosoftAuthenticator):
            try:
                self.authenticator = MicrosoftAuthenticator(config)
            except Exception as e:
                logger.warning(f"MicrosoftAuthenticator initialization failed: {e}")
        
        # PowerShell connection state
        self._is_connected = False
        self._connection_checked = False
    
    def _execute_powershell(
        self, 
        command: str, 
        timeout: int = 300
    ) -> PowerShellExecutionResult:
        """Execute PowerShell command with Exchange Online module"""
        start_time = datetime.now()
        
        try:
            logger.debug(f"Executing PowerShell command: {command[:100]}...")
            
            # Create PowerShell script with error handling
            ps_script = f"""
            try {{
                # Import Exchange Online module
                Import-Module ExchangeOnlineManagement -ErrorAction Stop
                
                # Check if already connected to Exchange Online
                $ExistingSession = Get-PSSession | Where-Object {{$_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.State -eq 'Opened'}}
                
                if (-not $ExistingSession) {{
                    Write-Output "No existing Exchange Online session found, attempting to connect..."
                    # Try to connect using the user email if available
                    $UserEmail = '{self.config.microsoft_user_email if self.config.microsoft_user_email else ""}'
                    if ($UserEmail) {{
                        Connect-ExchangeOnline -UserPrincipalName $UserEmail -ShowBanner:$false -ErrorAction Stop
                        Write-Output "Connected to Exchange Online as $UserEmail"
                    }} else {{
                        Write-Error "No user email configured for Exchange Online connection"
                        exit 1
                    }}
                }} else {{
                    Write-Output "Using existing Exchange Online session"
                }}
                
                # Execute the command
                {command}
            }}
            catch {{
                Write-Error $_.Exception.Message
                exit 1
            }}
            """
            
            # Execute PowerShell
            process = subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            result = PowerShellExecutionResult(
                command=command,
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time_seconds=execution_time,
                start_time=start_time,
                end_time=end_time
            )
            
            if result.is_success():
                logger.debug(f"PowerShell command completed successfully in {execution_time:.2f}s")
            else:
                logger.error(f"PowerShell command failed: {stderr}")
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"PowerShell command timed out after {timeout} seconds")
            end_time = datetime.now()
            return PowerShellExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                execution_time_seconds=timeout,
                start_time=start_time,
                end_time=end_time
            )
        except Exception as e:
            logger.error(f"Failed to execute PowerShell command: {e}")
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            return PowerShellExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time_seconds=execution_time,
                start_time=start_time,
                end_time=end_time
            )
    
    def connect_to_exchange_online(self) -> bool:
        """Connect to Exchange Online using interactive or app-based authentication"""
        try:
            logger.info("Checking Exchange Online connection...")
            
            # First, check if already connected
            check_connection_command = """
            try {
                Get-OrganizationConfig -ErrorAction Stop | Out-Null
                Write-Output "CONNECTED"
            }
            catch {
                Write-Output "NOT_CONNECTED"
            }
            """
            
            result = self._execute_powershell(check_connection_command)
            
            if result.is_success() and "CONNECTED" in result.stdout:
                logger.info("Already connected to Exchange Online")
                self._is_connected = True
                self._connection_checked = True
                return True
            
            # Not connected, attempt to connect based on configuration
            if self.config.microsoft_user_email:
                # Use interactive user authentication
                logger.info(f"Attempting interactive authentication for {self.config.microsoft_user_email}")
                connect_command = f"""
                try {{
                    Connect-ExchangeOnline -UserPrincipalName '{self.config.microsoft_user_email}' -ShowBanner:$false
                    Get-OrganizationConfig -ErrorAction Stop | Out-Null
                    Write-Output "Successfully connected"
                }}
                catch {{
                    Write-Error "Failed to connect: $_"
                    exit 1
                }}
                """
            elif self.config.microsoft_tenant_id and self.config.microsoft_client_id:
                # Use app-based authentication (if configured)
                logger.info("Attempting app-based authentication")
                connect_command = f"""
                try {{
                    # App-based auth would require certificate or client secret flow
                    # For now, we'll indicate it's not yet implemented
                    Write-Error "App-based authentication not yet fully implemented. Please use interactive authentication."
                    exit 1
                }}
                catch {{
                    Write-Error "Failed to connect: $_"
                    exit 1
                }}
                """
            else:
                # No credentials configured, provide instructions
                logger.warning("No Microsoft credentials configured")
                logger.info("Please either:")
                logger.info("1. Add MICROSOFT_USER_EMAIL to your .env file, OR")
                logger.info("2. Manually run: Connect-ExchangeOnline -UserPrincipalName 'your.email@company.com'")
                self._is_connected = False
                self._connection_checked = True
                return False
            
            result = self._execute_powershell(connect_command)
            
            if result.is_success():
                self._is_connected = True
                self._connection_checked = True
                logger.info("Successfully connected to Exchange Online")
                return True
            else:
                logger.error(f"Failed to connect to Exchange Online: {result.stderr}")
                logger.info("You may need to manually run: Connect-ExchangeOnline -UserPrincipalName 'your.email@company.com'")
                self._is_connected = False
                self._connection_checked = True
                return False
                
        except Exception as e:
            logger.error(f"Exchange Online connection error: {e}")
            self._is_connected = False
            self._connection_checked = True
            return False
    
    def _check_connection(self) -> bool:
        """Check if connected to Exchange Online"""
        # Note: Each PowerShell script includes its own connection logic to avoid
        # redundant authentication prompts. This method primarily validates that
        # the configuration is present to attempt a connection.

        # Check if user email is configured for authentication
        if not self.config.microsoft_user_email:
            logger.warning("No MICROSOFT_USER_EMAIL configured in environment")
            logger.info("Exchange mail trace requires user authentication")
            return False

        # Connection will be established/validated within each PowerShell execution
        # This avoids multiple authentication prompts in a single session
        return True
    
    def trace_exact_email(
        self,
        sender: str,
        subject: str,
        received_time: datetime,
        tolerance_minutes: int = 5,
        ticket_folder: Optional[Path] = None
    ) -> ExactEmailTrace:
        """Trace recipients of the exact phishing email (READ-ONLY)"""
        try:
            logger.info(f"Tracing exact email - Sender: {sender}, Subject: {subject[:50]}...")
            
            if not self._check_connection():
                raise ExchangeClientError("Not connected to Exchange Online")
            
            # Calculate time window in UTC
            start_time_utc = (received_time - timedelta(minutes=tolerance_minutes)).astimezone() if received_time.tzinfo else received_time - timedelta(minutes=tolerance_minutes)
            end_time_utc = (received_time + timedelta(minutes=tolerance_minutes)).astimezone() if received_time.tzinfo else received_time + timedelta(minutes=tolerance_minutes)

            # Build PowerShell command for exact email trace
            # Use ISO format for dates to avoid ambiguity
            start_date_str = start_time_utc.strftime("%Y-%m-%dT%H:%M:%S")
            end_date_str = end_time_utc.strftime("%Y-%m-%dT%H:%M:%S")

            # Escape single quotes in subject
            escaped_subject = subject.replace("'", "''")
            escaped_sender = sender.replace("'", "''")

            command = f"""
            # Parse dates as UTC
            $StartDate = [datetime]::Parse("{start_date_str}").ToUniversalTime()
            $EndDate = [datetime]::Parse("{end_date_str}").ToUniversalTime()

            Write-Output "Tracing emails from sender: {escaped_sender[:50] if len(escaped_sender) > 50 else escaped_sender}..."
            Write-Output "Time window (UTC): $($StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndDate.ToString('yyyy-MM-dd HH:mm:ss'))"

            # Initialize variables
            $AllMessages = @()

            # Use Get-MessageTraceV2 as primary (Get-MessageTrace is deprecated as of Sept 2025)
            try {{
                Write-Output "Using Get-MessageTraceV2 (Get-MessageTrace is deprecated)..."

                # Get-MessageTraceV2 doesn't use PageSize/Page parameters - returns all results
                $AllMessages = Get-MessageTraceV2 -SenderAddress '{escaped_sender}' `
                                                  -StartDate $StartDate `
                                                  -EndDate $EndDate `
                                                  -ErrorAction Stop

                if ($AllMessages) {{
                    Write-Output "Retrieved $($AllMessages.Count) messages using Get-MessageTraceV2"
                }}
            }}
            catch {{
                Write-Output "Get-MessageTraceV2 failed: $($_.Exception.Message)"
                Write-Output "Falling back to Get-MessageTrace (legacy)..."

                # Fallback to Get-MessageTrace with pagination
                $Page = 1
                $PageSize = 5000
                $AllMessages = @()

                do {{
                    Write-Output "Fetching page $Page..."

                    $Messages = Get-MessageTrace -SenderAddress '{escaped_sender}' `
                                                  -StartDate $StartDate `
                                                  -EndDate $EndDate `
                                                  -PageSize $PageSize `
                                                  -Page $Page `
                                                  -ErrorAction Stop

                    if ($Messages) {{
                        $AllMessages += $Messages
                        Write-Output "Retrieved $($Messages.Count) messages from page $Page"
                        $Page++
                    }}
                }} while ($Messages.Count -eq $PageSize)
            }}

            Write-Output ""
            Write-Output "===== MAIL TRACE RESULTS ====="
            Write-Output "Total messages found: $($AllMessages.Count)"

            if ($AllMessages.Count -gt 0) {{
                Write-Output ""
                Write-Output "Sample of results:"
                Write-Output "  First message received: $($AllMessages[0].Received)"
                Write-Output "  First message subject: $($AllMessages[0].Subject)"
                Write-Output "  First message recipient: $($AllMessages[0].RecipientAddress)"
                Write-Output ""
                Write-Output "===JSON_START==="
                $AllMessages | ConvertTo-Json -Depth 100 -Compress
                Write-Output "===JSON_END==="
            }} else {{
                Write-Output "No messages found from sender in this time window"
                Write-Output "===JSON_START==="
                @() | ConvertTo-Json
                Write-Output "===JSON_END==="
            }}
            """
            
            result = self._execute_powershell(command)
            
            if not result.is_success():
                raise ExchangeClientError(f"Mail trace failed: {result.stderr}")
            
            # Parse results
            trace_results = self._parse_mail_trace_results(result.stdout)
            
            # Calculate summary statistics
            unique_recipients = set()
            delivered_count = 0
            failed_count = 0
            pending_count = 0
            
            for trace in trace_results:
                unique_recipients.add(trace.recipient_address.lower())
                
                if trace.status == MailTraceStatus.DELIVERED:
                    delivered_count += 1
                elif trace.status == MailTraceStatus.FAILED:
                    failed_count += 1
                elif trace.status == MailTraceStatus.PENDING:
                    pending_count += 1
            
            # Export to CSV if ticket folder provided
            export_file_path = None
            export_file_size = None
            export_record_count = len(trace_results)
            
            if ticket_folder and trace_results:
                export_file_path = self._export_trace_results(
                    trace_results, 
                    ticket_folder / "mail_trace_exact_email.csv"
                )
                if export_file_path and Path(export_file_path).exists():
                    export_file_size = Path(export_file_path).stat().st_size
            
            # Create exact email trace summary
            exact_trace = ExactEmailTrace(
                total_recipients=len(trace_results),
                unique_recipients=len(unique_recipients),
                delivered_count=delivered_count,
                failed_count=failed_count,
                pending_count=pending_count,
                trace_start_time=start_time,
                trace_end_time=end_time,
                sender_address=sender,
                subject=subject,
                message_id=trace_results[0].message_id if trace_results else "",
                received_time=received_time,
                export_file_path=export_file_path,
                export_file_size=export_file_size,
                export_record_count=export_record_count
            )
            
            logger.info(f"Exact email trace completed: {len(unique_recipients)} unique recipients")
            return exact_trace
            
        except Exception as e:
            logger.error(f"Failed to trace exact email: {e}")
            raise ExchangeClientError(f"Exact email trace failed: {e}")
    
    def trace_sender_history(
        self,
        sender: str,
        days_back: int = 30,
        ticket_folder: Optional[Path] = None
    ) -> SenderHistoryTrace:
        """Trace all emails from sender's history (READ-ONLY)"""
        try:
            logger.info(f"Tracing sender history - Sender: {sender}, Days back: {days_back}")
            
            if not self._check_connection():
                raise ExchangeClientError("Not connected to Exchange Online")

            # Escape sender address for PowerShell
            escaped_sender = sender.replace("'", "''")

            # Build PowerShell command for sender history trace
            # Match the working Get-MailTraceBySender.ps1 script exactly:
            # Calculate dates IN PowerShell, not in Python
            command = f"""
            # Calculate date range in UTC (same as working script)
            $EndDate = (Get-Date).ToUniversalTime()
            $StartDate = $EndDate.AddDays(-{days_back})

            Write-Output "Tracing sender history for {escaped_sender[:50] if len(escaped_sender) > 50 else escaped_sender}"
            Write-Output "Date range (UTC): $($StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndDate.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Output "This may take several minutes depending on the volume..."

            # Initialize variables
            $AllMessages = @()

            # Use Get-MessageTraceV2 as primary (Get-MessageTrace is deprecated as of Sept 2025)
            try {{
                Write-Output "Using Get-MessageTraceV2 (Get-MessageTrace is deprecated)..."

                # Get-MessageTraceV2 doesn't use PageSize/Page parameters - returns all results
                $AllMessages = Get-MessageTraceV2 -SenderAddress '{escaped_sender}' `
                                                  -StartDate $StartDate `
                                                  -EndDate $EndDate `
                                                  -ErrorAction Stop

                if ($AllMessages) {{
                    Write-Output "Retrieved $($AllMessages.Count) messages using Get-MessageTraceV2"
                }}
            }}
            catch {{
                Write-Output "Get-MessageTraceV2 failed: $($_.Exception.Message)"
                Write-Output "Falling back to Get-MessageTrace (legacy)..."

                # Fallback to Get-MessageTrace with pagination
                $Page = 1
                $PageSize = 5000
                $AllMessages = @()

                do {{
                    Write-Output "Fetching page $Page..."

                    $Messages = Get-MessageTrace -SenderAddress '{escaped_sender}' `
                                                  -StartDate $StartDate `
                                                  -EndDate $EndDate `
                                                  -PageSize $PageSize `
                                                  -Page $Page `
                                                  -ErrorAction Stop

                    if ($Messages) {{
                        $AllMessages += $Messages
                        Write-Output "Retrieved $($Messages.Count) messages from page $Page"
                        $Page++
                    }}
                }} while ($Messages.Count -eq $PageSize)
            }}

            Write-Output ""
            Write-Output "===== MAIL TRACE RESULTS ====="
            Write-Output "Total messages found: $($AllMessages.Count)"

            if ($AllMessages.Count -gt 0) {{
                Write-Output ""
                Write-Output "Sample of results:"
                Write-Output "  First message received: $($AllMessages[0].Received)"
                Write-Output "  First message subject: $($AllMessages[0].Subject)"
                Write-Output "  First message recipient: $($AllMessages[0].RecipientAddress)"
                Write-Output ""
                Write-Output "===JSON_START==="
                $AllMessages | ConvertTo-Json -Depth 100 -Compress
                Write-Output "===JSON_END==="
            }} else {{
                Write-Output "No messages found from sender in this time window"
                Write-Output "===JSON_START==="
                @() | ConvertTo-Json
                Write-Output "===JSON_END==="
            }}
            """
            
            result = self._execute_powershell(command, timeout=600)  # Longer timeout for history
            
            if not result.is_success():
                raise ExchangeClientError(f"Sender history trace failed: {result.stderr}")
            
            # Parse results
            trace_results = self._parse_mail_trace_results(result.stdout)
            
            # Calculate summary statistics
            unique_recipients = set()
            unique_subjects = set()
            delivered_count = 0
            failed_count = 0
            pending_count = 0
            first_email_date = None
            last_email_date = None
            
            for trace in trace_results:
                unique_recipients.add(trace.recipient_address.lower())
                unique_subjects.add(trace.subject)
                
                if trace.status == MailTraceStatus.DELIVERED:
                    delivered_count += 1
                elif trace.status == MailTraceStatus.FAILED:
                    failed_count += 1
                elif trace.status == MailTraceStatus.PENDING:
                    pending_count += 1
                
                # Track date range
                if first_email_date is None or trace.received < first_email_date:
                    first_email_date = trace.received
                if last_email_date is None or trace.received > last_email_date:
                    last_email_date = trace.received
            
            # Export to CSV if ticket folder provided
            export_file_path = None
            export_file_size = None
            export_record_count = len(trace_results)
            
            if ticket_folder and trace_results:
                export_file_path = self._export_trace_results(
                    trace_results, 
                    ticket_folder / "mail_trace_sender_history.csv"
                )
                if export_file_path and Path(export_file_path).exists():
                    export_file_size = Path(export_file_path).stat().st_size
            
            # Calculate Python-side time range for return object
            # (matches what PowerShell calculated)
            end_time_utc = datetime.utcnow()
            start_time_utc = end_time_utc - timedelta(days=days_back)

            # Create sender history trace summary
            history_trace = SenderHistoryTrace(
                total_recipients=len(trace_results),
                unique_recipients=len(unique_recipients),
                delivered_count=delivered_count,
                failed_count=failed_count,
                pending_count=pending_count,
                trace_start_time=start_time_utc,
                trace_end_time=end_time_utc,
                sender_address=sender,
                subject=f"Multiple subjects ({len(unique_subjects)} unique)",
                days_traced=days_back,
                total_emails_sent=len(trace_results),
                unique_subjects=len(unique_subjects),
                first_email_date=first_email_date,
                last_email_date=last_email_date,
                export_file_path=export_file_path,
                export_file_size=export_file_size,
                export_record_count=export_record_count
            )
            
            logger.info(f"Sender history trace completed: {len(trace_results)} emails to {len(unique_recipients)} recipients")
            return history_trace
            
        except Exception as e:
            logger.error(f"Failed to trace sender history: {e}")
            raise ExchangeClientError(f"Sender history trace failed: {e}")
    
    def trace_combined(
        self,
        sender: str,
        subject: str,
        received_time: datetime,
        tolerance_minutes: int = 5,
        days_back: int = 30,
        ticket_folder: Optional[Path] = None
    ) -> tuple[Optional[ExactEmailTrace], Optional[SenderHistoryTrace]]:
        """Run both mail traces in a single PowerShell session to minimize auth prompts"""
        try:
            logger.info(f"Running combined mail traces for sender: {sender[:50]}...")
            
            # Calculate Python-side time windows for return objects
            exact_start = received_time - timedelta(minutes=tolerance_minutes)
            exact_end = received_time + timedelta(minutes=tolerance_minutes)
            history_end = datetime.utcnow()
            history_start = history_end - timedelta(days=days_back)

            # Escape strings for PowerShell
            escaped_subject = subject.replace("'", "''")
            escaped_sender = sender.replace("'", "''")

            # Build combined PowerShell script
            # Use PowerShell-native date calculation (matching working script)
            combined_command = f"""
            Write-Output "===== STARTING COMBINED MAIL TRACES ====="

            # Exact Email Trace
            # Note: Not used for now - sender history is primary for phishing investigation

            # Sender History Trace (Primary for phishing pattern detection)
            Write-Output "===== SENDER HISTORY TRACE ====="

            # Calculate date range in UTC (same as working Get-MailTraceBySender.ps1 script)
            $HistoryEnd = (Get-Date).ToUniversalTime()
            $HistoryStart = $HistoryEnd.AddDays(-{days_back})

            Write-Output "Date range: $($HistoryStart.ToString('yyyy-MM-dd HH:mm:ss')) to $($HistoryEnd.ToString('yyyy-MM-dd HH:mm:ss'))"

            # Use Get-MessageTraceV2 (Get-MessageTrace is deprecated as of Sept 2025)
            try {{
                Write-Output "Using Get-MessageTraceV2..."
                $HistoryResults = Get-MessageTraceV2 -SenderAddress '{escaped_sender}' -StartDate $HistoryStart -EndDate $HistoryEnd -ErrorAction Stop

                if ($HistoryResults) {{
                    Write-Output "Retrieved $($HistoryResults.Count) messages"
                    Write-Output "HISTORY_TRACE_RESULTS:"
                    $HistoryResults | ConvertTo-Json -Depth 100 -Compress
                }} else {{
                    Write-Output "HISTORY_TRACE_RESULTS:"
                    @() | ConvertTo-Json
                }}
            }}
            catch {{
                Write-Output "Get-MessageTraceV2 failed: $($_.Exception.Message)"
                Write-Output "HISTORY_TRACE_RESULTS:"
                @() | ConvertTo-Json
            }}

            Write-Output "===== TRACES COMPLETED ====="
            """
            
            # Execute combined command (single auth prompt)
            result = self._execute_powershell(combined_command, timeout=600)
            
            if not result.is_success():
                logger.error(f"Combined mail trace failed: {result.stderr}")
                return None, None
            
            # Parse the output for both traces
            output_lines = result.stdout.split('\n')
            exact_json = []
            history_json = []
            current_section = None
            
            for line in output_lines:
                if "EXACT_TRACE_RESULTS:" in line:
                    current_section = "exact"
                    continue
                elif "HISTORY_TRACE_RESULTS:" in line:
                    current_section = "history"
                    continue
                elif "=====" in line:
                    current_section = None
                    continue
                
                if current_section == "exact":
                    exact_json.append(line)
                elif current_section == "history":
                    history_json.append(line)
            
            # Process exact trace results
            exact_trace = None
            if exact_json:
                exact_output = '\n'.join(exact_json)
                exact_results = self._parse_mail_trace_results(exact_output)

                if exact_results:
                    # Calculate summary statistics
                    unique_recipients = set()
                    delivered_count = 0
                    failed_count = 0
                    pending_count = 0

                    for result in exact_results:
                        unique_recipients.add(result.recipient_address.lower())

                        if result.status == MailTraceStatus.DELIVERED:
                            delivered_count += 1
                        elif result.status == MailTraceStatus.FAILED:
                            failed_count += 1
                        elif result.status == MailTraceStatus.PENDING:
                            pending_count += 1

                    # Export to CSV if ticket folder provided
                    export_file_path = None
                    export_file_size = None
                    export_record_count = len(exact_results)

                    if ticket_folder:
                        export_file_path = self._export_trace_results(
                            exact_results,
                            ticket_folder / "mail_trace_exact_email_combined.csv"
                        )
                        if export_file_path and Path(export_file_path).exists():
                            export_file_size = Path(export_file_path).stat().st_size

                    # Create ExactEmailTrace object with correct fields
                    exact_trace = ExactEmailTrace(
                        total_recipients=len(exact_results),
                        unique_recipients=len(unique_recipients),
                        delivered_count=delivered_count,
                        failed_count=failed_count,
                        pending_count=pending_count,
                        trace_start_time=exact_start,
                        trace_end_time=exact_end,
                        sender_address=sender,
                        subject=subject,
                        message_id=exact_results[0].message_id if exact_results else "",
                        received_time=received_time,
                        export_file_path=export_file_path,
                        export_file_size=export_file_size,
                        export_record_count=export_record_count
                    )
                    logger.info(f"Exact trace found {len(unique_recipients)} unique recipients")
            
            # Process history trace results
            history_trace = None
            if history_json:
                history_output = '\n'.join(history_json)
                history_results = self._parse_mail_trace_results(history_output)

                if history_results:
                    # Calculate summary statistics
                    unique_recipients = set()
                    unique_subjects = set()
                    delivered_count = 0
                    failed_count = 0
                    pending_count = 0
                    first_email_date = None
                    last_email_date = None

                    for result in history_results:
                        unique_recipients.add(result.recipient_address.lower())
                        unique_subjects.add(result.subject)

                        if result.status == MailTraceStatus.DELIVERED:
                            delivered_count += 1
                        elif result.status == MailTraceStatus.FAILED:
                            failed_count += 1
                        elif result.status == MailTraceStatus.PENDING:
                            pending_count += 1

                        # Track date range
                        if first_email_date is None or result.received < first_email_date:
                            first_email_date = result.received
                        if last_email_date is None or result.received > last_email_date:
                            last_email_date = result.received

                    # Export to CSV if ticket folder provided
                    export_file_path = None
                    export_file_size = None
                    export_record_count = len(history_results)

                    if ticket_folder:
                        export_file_path = self._export_trace_results(
                            history_results,
                            ticket_folder / "mail_trace_sender_history_combined.csv"
                        )
                        if export_file_path and Path(export_file_path).exists():
                            export_file_size = Path(export_file_path).stat().st_size

                    # Create SenderHistoryTrace object with correct fields
                    history_trace = SenderHistoryTrace(
                        total_recipients=len(history_results),
                        unique_recipients=len(unique_recipients),
                        delivered_count=delivered_count,
                        failed_count=failed_count,
                        pending_count=pending_count,
                        trace_start_time=history_start,
                        trace_end_time=history_end,
                        sender_address=sender,
                        subject=f"Multiple subjects ({len(unique_subjects)} unique)",
                        days_traced=days_back,
                        total_emails_sent=len(history_results),
                        unique_subjects=len(unique_subjects),
                        first_email_date=first_email_date,
                        last_email_date=last_email_date,
                        export_file_path=export_file_path,
                        export_file_size=export_file_size,
                        export_record_count=export_record_count
                    )
                    logger.info(f"History trace found {len(history_results)} emails to {len(unique_recipients)} unique recipients")

            return exact_trace, history_trace
            
        except Exception as e:
            logger.error(f"Combined mail trace failed: {e}")
            return None, None
    
    def _parse_mail_trace_results(self, powershell_output: str) -> List[MailTraceResult]:
        """Parse PowerShell JSON output to MailTraceResult objects"""
        try:
            # Look for JSON between delimiter markers
            if "===JSON_START===" in powershell_output and "===JSON_END===" in powershell_output:
                start_idx = powershell_output.index("===JSON_START===") + len("===JSON_START===")
                end_idx = powershell_output.index("===JSON_END===")
                json_text = powershell_output[start_idx:end_idx].strip()
            else:
                # Fallback to old method if delimiters not found (backward compatibility)
                lines = powershell_output.strip().split('\n')
                json_lines = []
                in_json = False

                for line in lines:
                    if line.strip().startswith('[') or line.strip().startswith('{'):
                        in_json = True
                    if in_json:
                        json_lines.append(line)
                    if line.strip().endswith(']') or line.strip().endswith('}'):
                        break

                if not json_lines:
                    logger.warning("No JSON found in PowerShell output")
                    logger.info(f"PowerShell output (first 1000 chars): {powershell_output[:1000]}")

                    # Check if the output indicates no messages found
                    if "No messages found" in powershell_output or "Total messages found: 0" in powershell_output:
                        logger.info("Mail trace returned 0 results (no messages matched criteria)")
                        return []

                    return []

                json_text = '\n'.join(json_lines)

            if not json_text or json_text == '[]':
                logger.info("Mail trace returned empty results")
                return []

            data = json.loads(json_text)
            
            # Handle both single object and array
            if isinstance(data, dict):
                data = [data]
            
            results = []
            for item in data:
                try:
                    # Map PowerShell fields to our model
                    mapped_item = {
                        'MessageTraceId': item.get('MessageTraceId', ''),
                        'Received': item.get('Received', ''),
                        'SenderAddress': item.get('SenderAddress', ''),
                        'RecipientAddress': item.get('RecipientAddress', ''),
                        'Subject': item.get('Subject', ''),
                        'Status': self._map_status(item.get('Status', 'unknown')),
                        'ToIP': item.get('ToIP'),
                        'FromIP': item.get('FromIP'),
                        'Size': item.get('Size'),
                        'MessageId': item.get('MessageId'),
                        'StartDate': item.get('StartDate'),
                        'EndDate': item.get('EndDate'),
                        'Organization': item.get('Organization')
                    }
                    
                    result = MailTraceResult(**mapped_item)
                    results.append(result)
                    
                except Exception as e:
                    logger.warning(f"Failed to parse mail trace item: {e}")
                    continue
            
            return results
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from PowerShell output: {e}")
            logger.error(f"PowerShell output (first 5000 chars): {powershell_output[:5000]}")
            logger.error(f"PowerShell output (last 1000 chars): {powershell_output[-1000:]}")
            return []
        except Exception as e:
            logger.error(f"Failed to parse mail trace results: {e}")
            return []
    
    def _map_status(self, status_str: str) -> MailTraceStatus:
        """Map PowerShell status strings to our enum"""
        status_map = {
            'delivered': MailTraceStatus.DELIVERED,
            'failed': MailTraceStatus.FAILED,
            'pending': MailTraceStatus.PENDING,
            'expanded': MailTraceStatus.EXPANDED
        }
        return status_map.get(status_str.lower(), MailTraceStatus.UNKNOWN)
    
    def _export_trace_results(self, results: List[MailTraceResult], file_path: Path) -> Optional[str]:
        """Export mail trace results to CSV file"""
        try:
            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'MessageTraceId', 'Received', 'SenderAddress', 'RecipientAddress',
                    'Subject', 'Status', 'Size', 'FromIP', 'ToIP', 'MessageId'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    writer.writerow({
                        'MessageTraceId': result.message_trace_id,
                        'Received': result.received.isoformat() if result.received else '',
                        'SenderAddress': result.sender_address,
                        'RecipientAddress': result.recipient_address,
                        'Subject': result.subject,
                        'Status': result.status if result.status else '',  # Already a string due to use_enum_values=True
                        'Size': result.size or '',
                        'FromIP': result.from_ip or '',
                        'ToIP': result.to_ip or '',
                        'MessageId': result.message_id or ''
                    })
            
            logger.info(f"Exported {len(results)} mail trace records to {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Failed to export mail trace results: {e}")
            return None
    
    def test_connection(self) -> ConnectionTestResult:
        """Test connection to Exchange Online (READ-ONLY)"""
        start_time = datetime.now()
        
        try:
            logger.info("Testing Exchange Online connection...")
            
            # Test connection
            is_connected = self.connect_to_exchange_online()
            
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            error_message = None
            if not is_connected:
                error_message = "Failed to connect to Exchange Online. Manual authentication may be required."
            
            return ConnectionTestResult(
                service_name="Exchange Online",
                is_connected=is_connected,
                response_time_ms=response_time,
                test_time=start_time,
                error_message=error_message
            )
            
        except Exception as e:
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            return ConnectionTestResult(
                service_name="Exchange Online",
                is_connected=False,
                response_time_ms=response_time,
                test_time=start_time,
                error_message=str(e)
            )