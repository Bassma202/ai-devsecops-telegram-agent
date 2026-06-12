import os
import subprocess
import requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


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
        "/run_pipeline - Launch CI/CD pipeline\n"
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
    await update.message.reply_text("🚀 Starting CI/CD pipeline simulation...")

    pipeline_steps = [
        "✅ Stage 1: Build completed successfully",
        "✅ Stage 2: Validation completed successfully",
        "✅ Stage 3: Security preparation completed successfully",
        "✅ Stage 4: Pipeline finished successfully"
    ]

    message = "🚀 CI/CD Pipeline Result\n\n" + "\n".join(pipeline_steps)

    await update.message.reply_text(message)


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
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("deploy", deploy))
    app.add_handler(CommandHandler("logs", logs))

    print("DevSecOps Telegram bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()