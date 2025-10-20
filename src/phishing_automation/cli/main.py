#!/usr/bin/env python3

import click
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ..utils.logger import get_logger, log_action
from ..core.config import Config
from ..core.orchestrator import PhishingInvestigator
from ..integrations.microsoft import (
    DefenderClient, ExchangeClient, DefenderClientError, ExchangeClientError
)

logger = get_logger(__name__)
console = Console()


def display_banner():
    banner_text = """
 ____  _     _     _     _               _         _                        _   _
|  _ \\| |__ (_)___| |__ (_)_ __   __ _  / \\  _   _| |_ ___  _ __ ___   __ _| |_(_) ___  _ __
| |_) | '_ \\| / __| '_ \\| | '_ \\ / _` |/  / | | | | __/ _ \\| '_ ` _ \\ / _` | __| |/ _ \\| '_ \\
|  __/| | | | \\__ \\ | | | | | | | (_| /\\_  | |_| | || (_) | | | | | | (_| | |_| | (_) | | | |
|_|   |_| |_|_|___/_| |_|_|_| |_|\\__, \\/  \\  \\__,_|\\__\\___/|_| |_| |_|\\__,_|\\__|_|\\___/|_| |_|
                                |___/

    Phishing Alert Investigation Automation System v1.0.0
    """
    
    console.print(Panel(
        Text(banner_text, style="cyan bold"),
        title="🔒 Security Tool",
        subtitle="Defensive Security Automation",
        border_style="blue"
    ))


def display_main_menu():
    console.print("\n[bold cyan]Main Menu[/bold cyan]")
    console.print("1. Investigate Phishing Ticket")
    console.print("2. View Recent Investigations") 
    console.print("3. System Status")
    console.print("4. Test Microsoft Integrations")
    console.print("5. Configuration")
    console.print("6. Exit")


@click.group()
@click.option('--config-file', default='.env', help='Configuration file path')
@click.pass_context
def cli(ctx, config_file):
    ctx.ensure_object(dict)
    try:
        ctx.obj['config'] = Config.load_from_file(config_file)
        logger.info("Application started")
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--ticket-id', type=int, help='FreshService ticket ID to investigate')
@click.pass_context
def investigate(ctx, ticket_id):
    config = ctx.obj['config']
    
    if not ticket_id:
        ticket_id = Prompt.ask("Enter FreshService ticket ID", default="")
        if not ticket_id or not ticket_id.isdigit():
            console.print("[red]Invalid ticket ID provided[/red]")
            return
        ticket_id = int(ticket_id)
    
    try:
        investigator = PhishingInvestigator(config)
        console.print(f"\n[bold blue]Starting investigation of ticket {ticket_id}[/bold blue]")
        
        # Get username - works on both Windows and Unix
        username = os.getenv('USERNAME') or os.getenv('USER') or 'unknown'
        log_action(ticket_id, "INVESTIGATION_STARTED", f"User: {username}")
        
        # Run full investigation
        with console.status("[bold green]Investigating phishing alert..."):
            results = investigator.investigate_ticket(ticket_id)
        
        # Display concise summary
        console.print("\n[bold green]✓ Investigation completed for ticket {0}[/bold green]".format(results['ticket_id']))
        console.print("")

        # Generate and display ultra-concise summary
        from ..analysis.report_generator import InvestigationReport
        report_gen = InvestigationReport()

        # Get data from results
        parsed_email = results.get('parsed_email')
        confidence = results.get('confidence')

        # Display sender email first (critical for blocking)
        if parsed_email:
            console.print(f"Sender: {parsed_email.sender}")

        # Reconstruct trace objects if available
        exact_trace = None
        sender_trace = None

        # We'll import the models to reconstruct if needed
        if results.get('has_mail_traces'):
            # We have the data in results, just display it directly
            summary_lines = []

            # Line 1: Recipients
            if results.get('exact_email_recipients') is not None:
                summary_lines.append(f"Email sent to {results['exact_email_recipients']} recipients")
            elif results.get('sender_total_emails') is not None:
                summary_lines.append(f"Email traced (sender history available)")
            else:
                summary_lines.append("Investigation completed")

            # Line 2: Confidence
            if confidence:
                top_reasons = sorted(confidence.reasons, key=lambda r: r.points, reverse=True)[:2]
                reason_text = ", ".join([r.description.split(':')[0] for r in top_reasons]) if top_reasons else "No indicators"
                summary_lines.append(f"Confidence: {confidence.score}% ({confidence.confidence_level.value}) - {reason_text}")

            # Line 3: Sender history
            if results.get('sender_total_emails') is not None:
                days = 10  # Default from orchestrator
                summary_lines.append(f"Sender history: {results['sender_total_emails']} emails to {results['sender_unique_recipients']} unique recipients over {days} days")

            # Display the concise summary
            for line in summary_lines:
                console.print(line)

        else:
            # No mail traces, simpler summary
            console.print("Investigation completed")
            if confidence:
                top_reasons = sorted(confidence.reasons, key=lambda r: r.points, reverse=True)[:2]
                reason_text = ", ".join([r.description.split(':')[0] for r in top_reasons]) if top_reasons else "No indicators"
                console.print(f"Confidence: {confidence.score}% ({confidence.confidence_level.value}) - {reason_text}")

        # Show file references
        console.print("")
        console.print(f"[dim]📁 Full report: {results['report_path']}[/dim]")
        if results.get('sender_export'):
            console.print(f"[dim]📊 Mail trace: {results['sender_export']}[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error during investigation: {e}[/red]")
        logger.error(f"Investigation failed for ticket {ticket_id}: {e}")


@cli.command()
def interactive():
    display_banner()
    
    try:
        config = Config.load_from_file('.env')
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        console.print("[yellow]Please ensure .env file exists and is properly configured[/yellow]")
        return
    
    while True:
        display_main_menu()
        
        choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3", "4", "5", "6"], default="6")
        
        if choice == "1":
            ticket_id = Prompt.ask("Enter FreshService ticket ID")
            if ticket_id and ticket_id.isdigit():
                try:
                    investigator = PhishingInvestigator(config)
                    console.print(f"\n[bold blue]Starting investigation of ticket {ticket_id}[/bold blue]")
                    
                    # Run investigation with progress indicator
                    with console.status("[bold green]Investigating phishing alert..."):
                        results = investigator.investigate_ticket(int(ticket_id))
                    
                    # Display concise summary (same as command-line version)
                    console.print("\n[bold green]✓ Investigation completed for ticket {0}[/bold green]".format(results['ticket_id']))
                    console.print("")

                    # Get data from results
                    parsed_email = results.get('parsed_email')
                    confidence = results.get('confidence')

                    # Display sender email first (critical for blocking)
                    if parsed_email:
                        console.print(f"Sender: {parsed_email.sender}")

                    # Generate concise summary
                    if results.get('has_mail_traces'):
                        summary_lines = []

                        # Line 1: Recipients
                        if results.get('exact_email_recipients') is not None:
                            summary_lines.append(f"Email sent to {results['exact_email_recipients']} recipients")
                        elif results.get('sender_total_emails') is not None:
                            summary_lines.append(f"Email traced (sender history available)")
                        else:
                            summary_lines.append("Investigation completed")

                        # Line 2: Confidence
                        if confidence:
                            top_reasons = sorted(confidence.reasons, key=lambda r: r.points, reverse=True)[:2]
                            reason_text = ", ".join([r.description.split(':')[0] for r in top_reasons]) if top_reasons else "No indicators"
                            summary_lines.append(f"Confidence: {confidence.score}% ({confidence.confidence_level.value}) - {reason_text}")

                        # Line 3: Sender history
                        if results.get('sender_total_emails') is not None:
                            days = 10  # Default from orchestrator
                            summary_lines.append(f"Sender history: {results['sender_total_emails']} emails to {results['sender_unique_recipients']} unique recipients over {days} days")

                        # Display the summary
                        for line in summary_lines:
                            console.print(line)
                    else:
                        console.print("Investigation completed")
                        if confidence:
                            top_reasons = sorted(confidence.reasons, key=lambda r: r.points, reverse=True)[:2]
                            reason_text = ", ".join([r.description.split(':')[0] for r in top_reasons]) if top_reasons else "No indicators"
                            console.print(f"Confidence: {confidence.score}% ({confidence.confidence_level.value}) - {reason_text}")

                    # Show file references
                    console.print("")
                    console.print(f"[dim]📁 Full report: {results['report_path']}[/dim]")
                    if results.get('sender_export'):
                        console.print(f"[dim]📊 Mail trace: {results['sender_export']}[/dim]")
                    
                except Exception as e:
                    console.print(f"[red]Investigation failed: {e}[/red]")
            else:
                console.print("[red]Invalid ticket ID[/red]")
        
        elif choice == "2":
            console.print("\n[bold cyan]Recent Investigations[/bold cyan]")
            console.print("[yellow]Investigation history functionality will be implemented in Phase 4[/yellow]")
        
        elif choice == "3":
            display_system_status(config)
        
        elif choice == "4":
            display_microsoft_integration_menu(config)
        
        elif choice == "5":
            display_configuration_menu(config)
        
        elif choice == "6":
            if Confirm.ask("\nAre you sure you want to exit?"):
                console.print("\n[green]Thank you for using Phishing Alert Automation![/green]")
                log_action(0, "APPLICATION_EXIT", "User exited application")
                break
        
        console.print("\n" + "="*50)


def display_system_status(config):
    console.print("\n[bold cyan]System Status[/bold cyan]")
    
    status_table = Table(title="Service Status", show_header=True, header_style="bold magenta")
    status_table.add_column("Service", style="cyan")
    status_table.add_column("Status", style="green")
    status_table.add_column("Details", style="yellow")
    
    # Check FreshService connection
    try:
        from ..integrations.freshservice.client import FreshServiceClient
        fs_client = FreshServiceClient(config.freshservice_domain, config.freshservice_api_key)
        if fs_client.validate_connection():
            status_table.add_row("FreshService", "✅ Connected", f"Domain: {config.freshservice_domain}")
        else:
            status_table.add_row("FreshService", "❌ Failed", "Connection test failed")
    except Exception as e:
        status_table.add_row("FreshService", "❌ Error", str(e))
    
    # Check Microsoft integrations
    try:
        if config.is_microsoft_configured():
            # Test Defender connection
            try:
                defender_client = DefenderClient(config)
                defender_result = defender_client.test_connection()
                
                if defender_result.is_connected:
                    status_table.add_row("Microsoft Defender", "✅ Connected", 
                                        f"Response: {defender_result.response_time_ms:.0f}ms")
                else:
                    status_table.add_row("Microsoft Defender", "❌ Failed", 
                                        defender_result.error_message or "Connection failed")
            except Exception as e:
                status_table.add_row("Microsoft Defender", "❌ Error", str(e))
            
            # Test Exchange Online connection
            try:
                exchange_client = ExchangeClient(config)
                exchange_result = exchange_client.test_connection()
                
                if exchange_result.is_connected:
                    status_table.add_row("Exchange Online", "✅ Connected", 
                                        f"Response: {exchange_result.response_time_ms:.0f}ms")
                else:
                    status_table.add_row("Exchange Online", "❌ Failed", 
                                        exchange_result.error_message or "Connection failed")
            except Exception as e:
                status_table.add_row("Exchange Online", "❌ Error", str(e))
        else:
            status_table.add_row("Microsoft Services", "⚠️ Not Configured", "Missing Microsoft credentials")
    except Exception as e:
        status_table.add_row("Microsoft Services", "❌ Error", str(e))
    
    # Check directories
    logs_dir = Path("logs")
    reports_dir = Path("reports")
    
    status_table.add_row("Logs Directory", "✅ Ready" if logs_dir.exists() else "⚠️ Missing", str(logs_dir.absolute()))
    status_table.add_row("Reports Directory", "✅ Ready" if reports_dir.exists() else "⚠️ Missing", str(reports_dir.absolute()))
    
    console.print(status_table)


def display_microsoft_integration_menu(config):
    """Display Microsoft integration testing menu"""
    console.print("\n[bold cyan]Microsoft Integration Testing[/bold cyan]")
    
    if not config.is_microsoft_configured():
        console.print("[red]❌ Microsoft credentials not configured![/red]")
        console.print("[yellow]Please configure Microsoft tenant ID, client ID, and client secret in your .env file.[/yellow]")
        return
    
    while True:
        console.print("\n[bold cyan]Microsoft Integration Options[/bold cyan]")
        console.print("1. Test Defender API Connection")
        console.print("2. Test Exchange Online Connection") 
        console.print("3. Test Mail Trace (Demo)")
        console.print("4. Test Email Submission Search")
        console.print("5. Back to Main Menu")
        
        choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3", "4", "5"], default="5")
        
        if choice == "1":
            test_defender_connection(config)
        elif choice == "2":
            test_exchange_connection(config)
        elif choice == "3":
            test_mail_trace_demo(config)
        elif choice == "4":
            test_email_submission_search(config)
        elif choice == "5":
            break


def test_defender_connection(config):
    """Test Microsoft Defender API connection"""
    console.print("\n[bold blue]Testing Microsoft Defender Connection...[/bold blue]")
    
    try:
        with console.status("[bold green]Connecting to Microsoft Defender API..."):
            defender_client = DefenderClient(config)
            result = defender_client.test_connection()
        
        if result.is_connected:
            console.print(f"[green]✅ Microsoft Defender connection successful![/green]")
            console.print(f"[dim]Response time: {result.response_time_ms:.0f}ms[/dim]")
        else:
            console.print(f"[red]❌ Microsoft Defender connection failed[/red]")
            if result.error_message:
                console.print(f"[red]Error: {result.error_message}[/red]")
    
    except Exception as e:
        console.print(f"[red]❌ Error testing Defender connection: {e}[/red]")


def test_exchange_connection(config):
    """Test Exchange Online connection"""
    console.print("\n[bold blue]Testing Exchange Online Connection...[/bold blue]")
    
    try:
        with console.status("[bold green]Connecting to Exchange Online..."):
            exchange_client = ExchangeClient(config)
            result = exchange_client.test_connection()
        
        if result.is_connected:
            console.print(f"[green]✅ Exchange Online connection successful![/green]")
            console.print(f"[dim]Response time: {result.response_time_ms:.0f}ms[/dim]")
        else:
            console.print(f"[red]❌ Exchange Online connection failed[/red]")
            if result.error_message:
                console.print(f"[red]Error: {result.error_message}[/red]")
                console.print("[yellow]Note: Exchange Online may require manual Connect-ExchangeOnline in PowerShell[/yellow]")
    
    except Exception as e:
        console.print(f"[red]❌ Error testing Exchange connection: {e}[/red]")


def test_mail_trace_demo(config):
    """Demo mail trace functionality with user input"""
    console.print("\n[bold blue]Mail Trace Demo[/bold blue]")
    
    if not Confirm.ask("This will test mail trace functionality. Continue?"):
        return
    
    sender = Prompt.ask("Enter sender email address (or press Enter for demo)", default="test@example.com")
    days_back = Prompt.ask("Enter days to look back", default="7")
    
    try:
        days_back = int(days_back)
    except ValueError:
        days_back = 7
    
    try:
        console.print(f"\n[bold blue]Testing sender history trace for: {sender}[/bold blue]")
        
        with console.status(f"[bold green]Tracing emails from {sender} (last {days_back} days)..."):
            exchange_client = ExchangeClient(config)
            
            # Test sender history trace
            history_result = exchange_client.trace_sender_history(
                sender=sender,
                days_back=days_back
            )
        
        console.print(f"[green]✅ Sender history trace completed![/green]")
        
        # Display results summary
        results_table = Table(title=f"Sender History: {sender}", show_header=True)
        results_table.add_column("Metric", style="cyan")
        results_table.add_column("Value", style="yellow")
        
        results_table.add_row("Total Emails", str(history_result.total_emails_sent))
        results_table.add_row("Unique Recipients", str(history_result.unique_recipients))
        results_table.add_row("Unique Subjects", str(history_result.unique_subjects))
        results_table.add_row("Delivered", str(history_result.delivered_count))
        results_table.add_row("Failed", str(history_result.failed_count))
        
        if history_result.first_email_date:
            results_table.add_row("First Email", history_result.first_email_date.strftime("%Y-%m-%d %H:%M"))
        if history_result.last_email_date:
            results_table.add_row("Last Email", history_result.last_email_date.strftime("%Y-%m-%d %H:%M"))
        
        console.print(results_table)
        
        if history_result.export_file_path:
            console.print(f"[dim]Export file: {history_result.export_file_path}[/dim]")
    
    except ExchangeClientError as e:
        console.print(f"[red]❌ Mail trace failed: {e}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error during mail trace demo: {e}[/red]")


def test_email_submission_search(config):
    """Test email submission search functionality"""
    console.print("\n[bold blue]Email Submission Search Demo[/bold blue]")
    
    if not Confirm.ask("This will test email submission search. Continue?"):
        return
    
    sender = Prompt.ask("Enter sender email to search (optional)", default="")
    subject = Prompt.ask("Enter subject to search (optional)", default="")
    
    try:
        console.print(f"\n[bold blue]Searching email submissions...[/bold blue]")
        
        with console.status("[bold green]Searching Microsoft Defender submissions..."):
            defender_client = DefenderClient(config)
            
            # Search submissions
            submissions = defender_client.search_email_submissions(
                sender=sender if sender else None,
                subject=subject if subject else None,
                limit=10
            )
        
        console.print(f"[green]✅ Email submission search completed![/green]")
        console.print(f"Found {len(submissions)} submissions")
        
        if submissions:
            # Display results in a table
            submissions_table = Table(title="Email Submissions", show_header=True)
            submissions_table.add_column("Sender", style="cyan", max_width=30)
            submissions_table.add_column("Subject", style="yellow", max_width=40) 
            submissions_table.add_column("Status", style="green")
            submissions_table.add_column("Verdict", style="red")
            submissions_table.add_column("Date", style="dim")
            
            for sub in submissions[:5]:  # Show first 5
                submissions_table.add_row(
                    sub.sender,
                    sub.subject[:40] + "..." if len(sub.subject) > 40 else sub.subject,
                    sub.status.value if sub.status else "unknown",
                    sub.verdict.value if sub.verdict else "pending",
                    sub.received_date.strftime("%m/%d %H:%M") if sub.received_date else ""
                )
            
            console.print(submissions_table)
            
            if len(submissions) > 5:
                console.print(f"[dim]... and {len(submissions) - 5} more submissions[/dim]")
        else:
            console.print("[yellow]No submissions found matching criteria[/yellow]")
    
    except DefenderClientError as e:
        console.print(f"[red]❌ Email submission search failed: {e}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error during email submission search: {e}[/red]")


def display_configuration_menu(config):
    console.print("\n[bold cyan]Configuration[/bold cyan]")
    
    config_table = Table(title="Current Configuration", show_header=True, header_style="bold magenta")
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value", style="yellow")
    config_table.add_column("Status", style="green")
    
    config_table.add_row("FreshService Domain", config.freshservice_domain or "Not Set", 
                        "✅" if config.freshservice_domain else "❌")
    config_table.add_row("FreshService API Key", "*****" if config.freshservice_api_key else "Not Set",
                        "✅" if config.freshservice_api_key else "❌")
    
    # Microsoft configuration
    config_table.add_row("Microsoft Tenant ID", config.microsoft_tenant_id or "Not Set",
                        "✅" if config.microsoft_tenant_id else "❌")
    config_table.add_row("Microsoft Client ID", config.microsoft_client_id or "Not Set",
                        "✅" if config.microsoft_client_id else "❌")
    config_table.add_row("Microsoft Client Secret", "*****" if config.microsoft_client_secret else "Not Set",
                        "✅" if config.microsoft_client_secret else "❌")
    
    config_table.add_row("Log Level", config.log_level, "✅")
    config_table.add_row("Reports Directory", config.reports_dir, "✅")
    
    console.print(config_table)
    
    missing_config = []
    if not config.freshservice_api_key or not config.freshservice_domain:
        missing_config.append("FreshService")
    if not config.is_microsoft_configured():
        missing_config.append("Microsoft")
    
    if missing_config:
        console.print(f"\n[yellow]⚠️ Missing required configuration for: {', '.join(missing_config)}. Please update your .env file.[/yellow]")


@cli.command()
def status():
    try:
        config = Config.load_from_file('.env')
        display_system_status(config)
    except Exception as e:
        console.print(f"[red]Error checking system status: {e}[/red]")


def main():
    if len(sys.argv) == 1:
        # No arguments provided, run interactive mode
        interactive()
    else:
        # CLI arguments provided, use click command processing
        cli()


if __name__ == "__main__":
    main()