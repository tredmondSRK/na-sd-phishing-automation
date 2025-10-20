from setuptools import setup, find_packages

setup(
    name="phishing-automation",
    version="1.0.0",
    description="Phishing Alert Automation System",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "python-dotenv>=1.0.0", 
        "rich>=13.5.0",
        "pandas>=2.0.0",
        "python-dateutil>=2.8.0",
        "click>=8.1.0",
        "pydantic>=2.0.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "phishing-automation=phishing_automation.cli.main:main",
        ],
    },
)