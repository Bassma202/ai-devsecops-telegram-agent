# Security Policy — FORGE

## Supported Scope
FORGE is a local DevSecOps and software supply-chain security engineering laboratory.

## Credential & Secret Handling
- Never commit `.env` files, Telegram bot tokens, or private Ed25519 `.pem` keys.
- Telegram ChatOps enforces **default-deny**: `FORGE_ALLOWED_TELEGRAM_USER_IDS` must be set to numeric Telegram operator IDs before the bot will start.
- All audit logs pass through `redact_sensitive()` to strip token and credential patterns before display or persistence.

## Reporting a Vulnerability
Open a private security advisory on GitHub (`Bassma202/ai-devsecops-telegram-agent`) or contact the repository maintainer directly.
