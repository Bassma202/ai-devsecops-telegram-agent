import os
import subprocess
import requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

GITLAB_PROJECT_ID = os.getenv("GITLAB_PROJECT_ID")
GITLAB_TRIGGER_TOKEN = os.getenv("GITLAB_TRIGGER_TOKEN")
GITLAB_REF = os.getenv("GITLAB_REF", "main")
GITLAB_ACCESS_TOKEN = os.getenv("GITLAB_ACCESS_TOKEN")


def run_command(command):
    """
    Runs a predefined system command and returns:
    - return code
    - command output

    Note:
    This prototype uses shell=True for simplicity.
    In production, this should be replaced with safer subprocess argument lists.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout if result.stdout else result.stderr
        return result.returncode, output[:3000]

    except subprocess.TimeoutExpired:
        return 1, "Command timed out."


def trigger_gitlab_pipeline():
    """
    Triggers a real GitLab CI/CD pipeline using GitLab's pipeline trigger API.
    """
    if not GITLAB_PROJECT_ID or not GITLAB_TRIGGER_TOKEN:
        return None, "GitLab variables are missing. Using local pipeline simulation."

    url = f"https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/trigger/pipeline"

    try:
        response = requests.post(
            url,
            data={
                "token": GITLAB_TRIGGER_TOKEN,
                "ref": GITLAB_REF
            },
            timeout=15
        )

        if response.status_code in [200, 201]:
            pipeline_data = response.json()
            pipeline_id = pipeline_data.get("id", "unknown")
            pipeline_status = pipeline_data.get("status", "created")
            pipeline_web_url = pipeline_data.get("web_url", "not available")

            return True, (
                "✅ GitLab pipeline triggered successfully.\n\n"
                f"Pipeline ID: {pipeline_id}\n"
                f"Status: {pipeline_status}\n"
                f"Branch: {GITLAB_REF}\n"
                f"URL: {pipeline_web_url}"
            )

        return False, (
            "⚠️ GitLab pipeline trigger failed.\n\n"
            f"HTTP status: {response.status_code}\n"
            f"Response: {response.text[:1000]}"
        )

    except requests.exceptions.RequestException as error:
        return False, (
            "⚠️ Could not connect to GitLab API.\n\n"
            f"Error: {error}"
        )


def get_latest_gitlab_pipeline_status():
    """
    Gets the latest GitLab pipeline status for the configured branch.
    If the project is private, GITLAB_ACCESS_TOKEN may be required.
    """
    if not GITLAB_PROJECT_ID:
        return False, "GitLab project ID is missing in .env."

    url = f"https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/pipelines"

    headers = {}
    if GITLAB_ACCESS_TOKEN:
        headers["PRIVATE-TOKEN"] = GITLAB_ACCESS_TOKEN

    try:
        response = requests.get(
            url,
            headers=headers,
            params={
                "ref": GITLAB_REF,
                "per_page": 1,
                "order_by": "id",
                "sort": "desc"
            },
            timeout=15
        )

        if response.status_code != 200:
            return False, (
                "Could not retrieve GitLab pipeline status.\n\n"
                f"HTTP status: {response.status_code}\n"
                f"Response: {response.text[:1000]}"
            )

        pipelines = response.json()

        if not pipelines:
            return False, "No GitLab pipelines found for this branch."

        latest_pipeline = pipelines[0]

        pipeline_id = latest_pipeline.get("id", "unknown")
        status = latest_pipeline.get("status", "unknown")
        ref = latest_pipeline.get("ref", GITLAB_REF)
        web_url = latest_pipeline.get("web_url", "not available")
        created_at = latest_pipeline.get("created_at", "unknown")

        status_icon = {
            "success": "✅",
            "failed": "❌",
            "running": "🏃",
            "pending": "⏳",
            "created": "🆕",
            "canceled": "🚫",
            "skipped": "⏭️"
        }.get(status, "ℹ️")

        return True, (
            "📡 Latest GitLab Pipeline Status\n\n"
            f"{status_icon} Status: {status}\n"
            f"Pipeline ID: {pipeline_id}\n"
            f"Branch: {ref}\n"
            f"Created at: {created_at}\n"
            f"URL: {web_url}"
        )

    except requests.exceptions.RequestException as error:
        return False, (
            "Could not connect to GitLab API.\n\n"
            f"Error: {error}"
        )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 DevSecOps AI Agent started.\n\n"
        "Use /help to see available commands."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Available commands:\n\n"
        "/start - Start the bot\n"
        "/status - Show system status and app health\n"
        "/run_pipeline - Launch real GitLab CI/CD pipeline\n"
        "/pipeline_status - Show latest GitLab pipeline status\n"
        "/scan - Launch security scans\n"
        "/deploy - Deploy the application\n"
        "/logs - Show recent logs\n"
        "/help - Show help"
    )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    code, docker_status = run_command(
        "docker ps --filter name=devsecops-demo-app --format '{{.Status}}'"
    )

    deployment_status = docker_status.strip() if docker_status.strip() else "not running"

    try:
        response = requests.get("http://localhost:5050/health", timeout=5)

        if response.status_code == 200:
            health_data = response.json()
            app_health = health_data.get("status", "unknown")
            health_message = f"healthy ({app_health})"
        else:
            health_message = f"unhealthy - HTTP {response.status_code}"

    except requests.exceptions.RequestException:
        health_message = "unreachable"

    await update.message.reply_text(
        "📊 System Status\n\n"
        f"🐳 Docker container: {deployment_status}\n"
        f"💚 Application health: {health_message}\n"
        "🌐 Health endpoint: http://localhost:5050/health"
    )


async def run_pipeline(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🚀 Pipeline launch requested...")

    gitlab_result, gitlab_message = trigger_gitlab_pipeline()

    if gitlab_result is True:
        await update.message.reply_text(
            "🚀 Real GitLab CI/CD Pipeline\n\n"
            f"{gitlab_message}\n\n"
            "Use /pipeline_status after a few seconds to check the final result."
        )
        return

    fallback_steps = [
        "✅ build Docker image",
        "✅ validate docker-compose.yml",
        "✅ prepare deployment"
    ]

    fallback_message = (
        "⚠️ GitLab pipeline was not triggered.\n"
        "Using local demo pipeline simulation instead.\n\n"
        f"Reason:\n{gitlab_message}\n\n"
        "Local pipeline stages:\n"
        + "\n".join(fallback_steps)
        + "\n\nNotification: pipeline demo completed"
    )

    await update.message.reply_text(fallback_message)


async def pipeline_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📡 Checking latest GitLab pipeline status...")

    success, message = get_latest_gitlab_pipeline_status()

    if success:
        await update.message.reply_text(message)
    else:
        await update.message.reply_text(
            "⚠️ GitLab pipeline status check failed.\n\n"
            f"{message}"
        )


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔎 Launching security scan...")

    code, output = run_command("python security/security_scan.py")

    if code == 0:
        await update.message.reply_text(
            "🛡️ Security Scan Completed\n\n"
            f"{output}\n\n"
            "📄 Reports generated:\n"
            "- reports/scan_report.txt\n"
            "- reports/scan_report.json"
        )
    else:
        await update.message.reply_text(
            "❌ Security scan failed.\n\n"
            f"{output}"
        )


async def deploy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🚀 Deploying application with Docker Compose...")

    code, output = run_command("docker compose up -d --build")

    if code == 0:
        await update.message.reply_text(
            "✅ Deployment completed successfully.\n\n"
            "🌐 Application URL: http://localhost:5050\n"
            "💚 Health endpoint: http://localhost:5050/health"
        )
    else:
        await update.message.reply_text(
            "❌ Deployment failed.\n\n"
            f"{output}"
        )


async def logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    code, output = run_command("docker compose logs --tail=50")

    if output.strip():
        await update.message.reply_text(
            "📜 Recent Application Logs\n\n"
            f"{output}"
        )
    else:
        await update.message.reply_text("No logs found.")


def main():
    if not TELEGRAM_BOT_TOKEN:
        print("Error: TELEGRAM_BOT_TOKEN not found in .env file.")
        return

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("run_pipeline", run_pipeline))
    app.add_handler(CommandHandler("pipeline_status", pipeline_status))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("deploy", deploy))
    app.add_handler(CommandHandler("logs", logs))

    print("DevSecOps Telegram bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()