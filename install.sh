#!/bin/bash

echo "Installing DevSecOps Telegram Agent..."

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

echo "Installation completed."
echo "Before running the bot, create a .env file containing:"
echo "TELEGRAM_BOT_TOKEN=your_token_here"
echo ""
echo "Run the bot with:"
echo "python bot.py"
