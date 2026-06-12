# Agent AI DevSecOps piloté via Telegram

## 1. Description

This project is a DevSecOps automation agent controlled through Telegram.

The user interacts with a Telegram bot to launch pipeline actions, run security scans, deploy an application, check deployment status, and consult logs.

The goal is to centralize DevSecOps operations in one conversational interface.

## 2. Architecture

Telegram User → Telegram Bot → AI Agent / Orchestrator → CI/CD Pipeline → Docker Compose → Security Tools

Main components:

- Telegram Bot: receives user commands.
- AI Agent / Orchestrator: maps commands to DevSecOps actions.
- Docker Compose: deploys the demo application.
- Security Scanner: runs SAST, dependency, Docker, and secrets checks.
- Reports: stores scan results.
- CI/CD file: defines build, test, security, and deploy stages.

## 3. Telegram Commands

| Command | Description |
|---|---|
| /start | Starts the bot |
| /help | Shows available commands |
| /status | Shows current pipeline, scan, deployment, and agent status |
| /run_pipeline | Launches the local CI/CD-style pipeline |
| /scan | Runs security scans and returns results |
| /deploy | Deploys the application using Docker Compose |
| /logs | Shows recent application logs |

## 4. DevSecOps Security Features

The project includes the following security checks:

- SAST scan: searches for risky code patterns.
- Dependency scan: validates dependency scan stage.
- Docker scan: validates Docker-related configuration.
- Secrets analysis: searches for exposed secrets or suspicious patterns.
- Monitoring: /status and /logs provide deployment visibility.

The scan results are saved in:

- reports/scan_report.txt
- reports/scan_report.json

## 5. Docker Deployment

The demo application is a Flask app located in:

- app/app.py

It is containerized using:

- app/Dockerfile

Deployment is managed using:

- docker-compose.yml

The application runs on:

- http://localhost:5050

## 6. Installation

Clone the repository, then run:

chmod +x install.sh
./install.sh

Create a .env file containing:

TELEGRAM_BOT_TOKEN=your_telegram_bot_token

Start the bot:

source venv/bin/activate
python bot.py

## 7. Demo Workflow

Recommended demonstration:

1. Start the Telegram bot.
2. Send /start.
3. Send /help.
4. Send /status.
5. Send /run_pipeline.
6. Send /scan.
7. Send /deploy.
8. Send /logs.
9. Open http://localhost:5050 or test with curl.

## 8. Limitations

This is an academic prototype.

Current limitations:

- The pipeline is local and GitLab CI/CD is represented through .gitlab-ci.yml.
- The security scanner is a lightweight local scanner.
- shell=True is detected as a risky pattern. In this prototype, commands are predefined by the agent, but in production this should be replaced with safer subprocess argument lists and strict allowlisting.
- Authentication should be strengthened so only authorized Telegram users can trigger DevSecOps actions.

## 9. Future Improvements

Possible improvements:

- Connect directly to GitLab API to trigger real remote pipelines.
- Integrate Semgrep for SAST.
- Integrate Trivy for Docker image scanning.
- Integrate Gitleaks for secrets detection.
- Add user authorization by Telegram user ID.
- Add alerting for failed deployments and critical vulnerabilities.
