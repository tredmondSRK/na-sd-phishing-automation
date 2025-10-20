# FreshService Configuration
FRESHSERVICE_API_KEY=Enter your API key here
FRESHSERVICE_DOMAIN=srkconsulting.freshservice.com

# Company information
ORGANIZATION_NAME=SRK Consulting
ORGANIZATION_DOMAINS=srk.com,srk.com.mx,srk.uy,srk.com.ar,srk.com.au,srk.cn,srk.com.hk,srk
  .com.mn,srk.co.in,srk.cl,srk.com.pe,srk.co,srk.com.br,srk.co.uk,srkexploration.com,srk.com
  .kz,srk.com.se,srk.es,srk.eu,srk.kz,srknordic.com,srkturkiye.com,srk.ru.com,srk.com.gh,srk
  .co.za,srk.global

# Option 1: Interactive User Authentication (RECOMMENDED)
# This will prompt for login when connecting to Exchange Online
MICROSOFT_USER_EMAIL=Enter your mail trace permission email here

# Option 2: Azure AD App Registration (Advanced)
# Only use if you have an app registration set up in Azure AD
# MICROSOFT_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# MICROSOFT_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# MICROSOFT_CLIENT_SECRET=your_client_secret_here

# Application Configuration
LOG_LEVEL=INFO
# Change to DEBUG to see detailed attachment and connection information
# LOG_LEVEL=DEBUG
REPORTS_DIR=./reports
LOGS_DIR=./logs

# Optional: Proxy Configuration (if required)
# HTTP_PROXY=http://proxy.company.com:8080
# HTTPS_PROXY=http://proxy.company.com:8080