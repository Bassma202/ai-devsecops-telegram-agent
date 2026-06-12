# Architecture - AI DevSecOps Telegram Agent

## Project Goal

This project is an academic DevSecOps prototype controlled entirely through Telegram.

The goal is to centralize DevSecOps actions such as:

- checking system status
- launching a CI/CD pipeline
- running security scans
- deploying the application
- consulting logs
- checking application health

## Global Architecture

Telegram User → Telegram Bot → AI Agent / Orchestrator → CI/CD Pipeline → Docker Compose → Security Tools → Reports → Monitoring

## Components

### 1. Telegram User

The user interacts with the system only through Telegram commands.

### 2. Telegram Bot

The Telegram bot is the interface of the system. It receives commands such as:

- `/start`
- `/help`
- `/status`
- `/run_pipeline`
- `/scan`
- `/deploy`
- `/logs`

### 3. AI Agent / Orchestrator

The Python script `bot.py` acts as the automation agent.

It receives Telegram commands and triggers predefined DevSecOps actions.

Examples:

- `/run_pipeline` simulates a CI/CD pipeline
- `/scan` launches the security scanner
- `/deploy` deploys the application using Docker Compose
- `/logs` retrieves application logs
- `/status` checks Docker status and application health

### 4. CI/CD Pipeline

The file `.gitlab-ci.yml` represents the CI/CD pipeline structure.

It includes stages such as:

- build
- security scan
- deployment preparation

In this academic prototype, the pipeline is demonstrated locally through the Telegram bot.

### 5. Docker Deployment

The application is containerized using Docker.

The file `docker-compose.yml` builds and runs the application container.

The application is exposed locally on:

```text
http://localhost:5050