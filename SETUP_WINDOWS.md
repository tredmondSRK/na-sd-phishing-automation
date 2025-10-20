# Windows Setup Guide

This guide provides step-by-step instructions for setting up and testing the Phishing Alert Automation System on Windows.

## Prerequisites

- Python 3.8 or higher installed on Windows
- Access to FreshService API credentials
- Command Prompt or PowerShell access

## Quick Setup Steps

### 1. Copy Project Files
Copy all project files from the VM to your Windows machine, including:
- All source code in the `src/` directory
- `requirements.txt`
- `setup.py` 
- `env.md` (you'll rename this to `.env`)
- All other project files and folders

### 2. Create Virtual Environment

Open **Command Prompt** or **PowerShell** and navigate to your project directory:

```cmd
cd C:\your\path\to\phishing_alert_automation
```

Create and activate a virtual environment:

#### Using Command Prompt:
```cmd
# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate
```

#### Using PowerShell:
```powershell
# Create virtual environment
python -m venv venv

# You may need to allow script execution first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Activate it
venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

With your virtual environment activated:

```cmd
pip install -r requirements.txt
```

### 4. Configure Environment Variables

#### Option A: Rename env.md to .env
```cmd
# Rename the file
ren env.md .env

# Edit with notepad
notepad .env
```

#### Option B: Create .env manually
1. Create a new file called `.env` in your project root
2. Copy the content from `env.md` into it
3. Update with your actual credentials

#### Required Configuration:
```
FRESHSERVICE_API_KEY=your_actual_api_key_here
FRESHSERVICE_DOMAIN=yourcompany.freshservice.com
```

### 5. Test the Installation

Run the application to verify everything works:

```cmd
# Make sure virtual environment is activated
venv\Scripts\activate

# Run the interactive CLI
python -m src.phishing_automation.cli.main

# Or test specific commands
python -m src.phishing_automation.cli.main status
```

## Troubleshooting

### PowerShell Execution Policy Issues
If you get execution policy errors in PowerShell:

```powershell
# Check current policy
Get-ExecutionPolicy

# Set policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then try activating again
venv\Scripts\Activate.ps1
```

### Python Module Import Issues
If you get import errors:

```cmd
# Make sure you're in the project root directory
dir

# Verify virtual environment is activated (should see (venv) in prompt)
venv\Scripts\activate

# Try using full module path
python -m src.phishing_automation.cli.main
```

### Missing Dependencies
If you get missing package errors:

```cmd
# Update pip first
python -m pip install --upgrade pip

# Reinstall requirements
pip install -r requirements.txt

# If specific package fails, install individually
pip install requests python-dotenv rich pandas python-dateutil click pydantic cryptography
```

### Configuration Issues
If you get configuration errors:

1. Verify your `.env` file exists in the project root
2. Check that it contains the required settings
3. Ensure no extra spaces around the `=` signs
4. Test connection with the status command:
   ```cmd
   python -m src.phishing_automation.cli.main status
   ```

### Virtual Environment Not Working
If virtual environment activation fails:

```cmd
# Try recreating it
rmdir /s venv
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Testing the Application

### 1. Check System Status
```cmd
python -m src.phishing_automation.cli.main status
```
This will show you:
- FreshService connection status
- Directory setup
- Configuration validation

### 2. Interactive Mode
```cmd
python -m src.phishing_automation.cli.main
```
This opens the interactive menu where you can:
- View system status
- Check configuration
- Test basic functionality

### 3. Command Line Mode
```cmd
# View help
python -m src.phishing_automation.cli.main --help

# Test with a ticket ID (won't process yet - Phase 2 feature)
python -m src.phishing_automation.cli.main investigate --ticket-id 12345
```

## Next Steps

Once you have successfully tested Phase 1:

1. **Verify FreshService Connection**: Use the status command to ensure API connectivity
2. **Test Logging**: Check that log files are created in the `logs/` directory
3. **Report Any Issues**: Note any Windows-specific problems for resolution
4. **Ready for Phase 2**: Microsoft Defender and Exchange Online integrations

## File Structure After Setup

Your Windows directory should look like this:
```
phishing_alert_automation/
├── .env                    # Your configuration (renamed from env.md)
├── requirements.txt
├── setup.py
├── README.md
├── SETUP_WINDOWS.md
├── venv/                   # Virtual environment
├── src/                    # Source code
├── logs/                   # Created when app runs
├── reports/                # Created when app runs
└── other project files...
```

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Verify all files copied correctly from VM
3. Ensure virtual environment is activated
4. Check logs in the `logs/` directory for detailed error information