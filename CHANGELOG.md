# Changelog

All notable changes to ByteENDE are documented here.

## [1.0.0] — 2026-10-23

Initial public release.

### Added
- Web panel: Encode/Decode, Hash, JWT, AES-256-GCM, QR tools; API-key management; a full Customize settings page (accent themes, density, effects, defaults, import/export).
- REST API under `/api/v1/*`, secured with per-key Bearer tokens, scopes and per-key rate limiting.
- Security hardening: CSRF protection, login lockout, secure cookies, HTTP security headers, PBKDF2-hashed credentials, AES-256-GCM authenticated encryption.
- Cross-platform launchers (`run.sh`, `run.bat`) and a Flask application-factory / blueprint architecture.
- Original AliXByte "AX" branding across the panel, favicon and documentation.

### Removed
- The standalone CLI. ByteENDE is now web-only: the dashboard and the REST API are the two supported interfaces.
