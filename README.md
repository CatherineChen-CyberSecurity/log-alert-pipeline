# log-alert-pipeline
## Purpose
This is an offline analysis program. The program pulls alert events every five minutes and analyzes the logs within them. It performs customized analysis on the logs and sends email alerts.

## Project Structure
The log-alert-pipeline project is organized into a clear and logical structure to promote maintainability and scalability. Below is an overview of the main directories and files:

## Requirements
- Python 3.13.3

## How to use
```
# optional step, create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# install dependencies
pip install -r requirements.txt
python main.py
```

```
log-alert-pipeline/
├── src/
│   ├── __init__.py                  # Marks the 'src' directory as a Python package.
│   ├── main.py                      # The main execution file; orchestrates the flow of the application.
│   ├── wazuh_client.py              # Wazuh data retrieval
│   ├── alert_analyzer.py            # Contains the core logic for filtering and identifying suspicious activities.
│   ├── log_parser.py                # Parser wazuh data.
│   ├── email_notifier.py            # Handles the sending of email alerts to specified recipients.
│   ├── rule_engine.py               # Rule engine
│   └── utils.py                     # Utility functions, such as date/time handling and logging configurations.
├── config/
│   ├── settings.yaml                # Main configuration
│   ├── rules.yaml                   # Analysis rules
│   └── email_template.html          # Email template
├── logs/
│   ├── app.log                      # Application's operational logs.
│   └── error.log                    # Error logs
├── tests/
│   ├── __init__.py                  # Marks the 'tests' directory as a Python package.
│   ├── test_wazuh_client.py         # Unit tests for the Wazuh client module.
│   ├── test_analyzer.py             # Unit tests for the alert analysis logic.
│   └── test_notifier.py             # Unit tests for the email notification module.
├── docker/                          # Docker configuration directory
│   ├── Dockerfile                   # Application image build
│   ├── docker-compose.yml           # Container orchestration
│   ├── docker-compose.dev.yml       # Development environment
│   └── entrypoint.sh                # Container startup script
├── .gitignore                       # Specifies intentionally untracked files to ignore by Git.
├── .dockerignore                    # Docker ignore file
├── requirements.txt                 # Python package dependencies.
└── README.md                        # Project overview documentation.

---
## Documentation
- [Operation Manual (PDF)](docs/Operation-Manual.pdf)