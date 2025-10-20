# Phishing Alert Automation System

A defensive security tool for automating phishing alert investigations while maintaining human oversight for critical decisions.

## Current Status: Phase 1 Complete

✅ **Completed Features:**
- Project structure and module organization
- FreshService API integration with full CRUD operations
- Comprehensive logging system with audit trails
- Interactive CLI framework with rich formatting
- Configuration management with environment variable support
- Error handling and validation

🔄 **Next Phase (Phase 2):**
- Microsoft Defender API integration
- Exchange Online PowerShell integration
- Email data collection and mail trace functionality

## Quick Start

### 1. Setup Environment

```bash
# Clone/navigate to project directory
cd phishing_alert_automation

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.template .env

# Edit .env with your credentials
nano .env
```

### 2. Configure .env File

```env
FRESHSERVICE_API_KEY=your_api_key_here
FRESHSERVICE_DOMAIN=your_company.freshservice.com
LOG_LEVEL=INFO
REPORTS_DIR=./reports
LOGS_DIR=./logs
```

### 3. Run Application

```bash
# Interactive mode
python -m phishing_automation.cli.main

# Command line mode
python -m phishing_automation.cli.main investigate --ticket-id 12345

# Check system status
python -m phishing_automation.cli.main status
```

## Project Structure

```
src/phishing_automation/
├── cli/                    # Command line interface
│   └── main.py            # Main CLI application
├── core/                   # Core business logic
│   ├── config.py          # Configuration management
│   └── orchestrator.py    # Main investigation orchestrator
├── integrations/           # External service integrations
│   ├── freshservice/      # FreshService API client
│   │   ├── client.py      # API client implementation
│   │   └── models.py      # Data models
│   └── microsoft/         # Microsoft integrations (Phase 2)
├── analysis/              # Phishing analysis engine (Phase 3)
├── utils/                 # Utility modules
│   └── logger.py         # Logging system
└── __init__.py

logs/                      # Application logs
reports/                   # Investigation reports
tests/                     # Unit tests (Phase 5)
```

## Features

### Current (Phase 1)
- **FreshService Integration**: Full API client with ticket retrieval, updates, and note additions
- **Logging System**: Multi-level logging with audit trails and ticket-specific logs
- **CLI Interface**: Interactive menu system with rich formatting and status displays
- **Configuration**: Secure environment-based configuration with validation
- **Error Handling**: Comprehensive error handling and validation

### Planned (Future Phases)
- **Microsoft Integrations**: Defender API and Exchange Online PowerShell
- **Analysis Engine**: Automated phishing detection with confidence scoring
- **Report Generation**: Comprehensive investigation reports
- **Human Review**: Interactive review interface for decision making

## Configuration

### Required Settings
- `FRESHSERVICE_API_KEY`: Your FreshService API key
- `FRESHSERVICE_DOMAIN`: Your FreshService domain (e.g., company.freshservice.com)

### Optional Settings
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `REPORTS_DIR`: Directory for investigation reports
- `LOGS_DIR`: Directory for application logs
- `HTTP_PROXY`, `HTTPS_PROXY`: Proxy configuration if required

## Security

This is a **defensive security tool** designed to:
- ✅ Investigate reported phishing attempts
- ✅ Analyze suspicious emails safely
- ✅ Generate security reports
- ✅ Maintain audit trails
- ✅ Require human approval for actions

## Development

### Phase Implementation
- **Phase 1** (✅ Complete): Foundation and FreshService integration
- **Phase 2** (🔄 Next): Microsoft integrations
- **Phase 3**: Analysis engine
- **Phase 4**: Reporting and interface
- **Phase 5**: Testing and refinement  
- **Phase 6**: Deployment

### Adding New Features
1. Follow existing module structure
2. Add proper logging and error handling
3. Update configuration if needed
4. Add CLI commands as appropriate
5. Maintain security focus

## Logging

The system provides multiple logging levels:
- **General logs**: `logs/phishing_automation_YYYYMMDD.log`
- **Error logs**: `logs/errors_YYYYMMDD.log`
- **Ticket-specific logs**: `logs/ticket_[ID]_YYYYMMDD_HHMMSS.log`
- **Audit logs**: `logs/audit_YYYYMMDD.log`

## Support

For issues or questions:
1. Check the logs directory for detailed error information
2. Verify configuration settings
3. Test system status using the CLI status command
4. Review the project plan document for implementation details