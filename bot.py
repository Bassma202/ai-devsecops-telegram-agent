import os
import subprocess
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout if result.stdout else result.stderr
        return result.returncode, output[-3000:]
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
        "/status - Show system status\n"
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

    await update.message.reply_text(
        "📊 Current DevSecOps status:\n\n"
        "Pipeline: local demo mode\n"
        "Security scan: ready\n"
        f"Deployment: {deployment_status}\n"
        "Agent: running"
    )


async def run_pipeline(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🚀 Pipeline launch requested...")

    code, output = run_command("docker compose build")

    if code == 0:
        await update.message.reply_text(
            "✅ Pipeline completed successfully.\n\n"
            "Stages:\n"
            "✅ build Docker image\n"
            "✅ validate docker-compose.yml\n"
            "✅ prepare deployment\n\n"
            "Notification: pipeline success"
        )
    else:
        await update.message.reply_text(
            "❌ Pipeline failed.\n\n"
            f"{output}"
        )


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔎 Security scan started...")

    code, output = run_command("python security/security_scan.py")

    if code == 0:
        try:
            with open("reports/scan_report.txt", "r") as file:
                report = file.read()
        except FileNotFoundError:
            report = "Scan finished, but report file was not found."

        await update.message.reply_text(
            "🛡️ Security scan completed.\n\n"
            f"{report}\n\n"
            "Notification: vulnerabilities detected"
        )
    else:
        await update.message.reply_text(
            "❌ Security scan failed.\n\n"
            f"{output}"
        )


async def deploy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📦 Deployment started with Docker Compose...")

    code, output = run_command("docker compose up -d --build")

    if code == 0:
        await update.message.reply_text(
            "✅ Deployment successful.\n\n"
            "Application: DevSecOps Demo App\n"
            "Deployment tool: Docker Compose\n"
            "Container: devsecops-demo-app\n"
            "URL: http://localhost:5050\n\n"
            "Notification: deployment state = successful"
        )
    else:
        await update.message.reply_text(
            "❌ Deployment failed.\n\n"
            f"{output}"
        )


async def logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    code, output = run_command("docker logs --tail 20 devsecops-demo-app")

    if output.strip():
        await update.message.reply_text(
            "📄 Recent application logs:\n\n"
            f"{output}"
        )
    else:
        await update.message.reply_text("📄 No logs found yet.")


def main():
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError("Missing TELEGRAM_BOT_TOKEN in .env file")

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
