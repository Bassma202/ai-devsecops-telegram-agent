#!/usr/bin/env python3
"""Entrypoint for the hardened FORGE Telegram ChatOps bot."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from forge.telegram_bot import run_telegram_bot

if __name__ == "__main__":
    run_telegram_bot()
