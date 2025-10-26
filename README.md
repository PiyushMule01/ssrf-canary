# SSRF Canary

A lightweight Flask-based application for detecting and monitoring Server-Side Request Forgery (SSRF) attempts through canary tokens.

## Features

- **Token Generation**: Create unique canary tokens with customizable expiration
- **Request Monitoring**: Log all HTTP requests to canary endpoints
- **SSRF Detection**: Automatically flag suspicious requests from private IPs or cloud metadata endpoints
- **Multi-Channel Alerts**: Send notifications via webhook and email
- **Rate Limiting**: Built-in protection against abuse
- **Reverse DNS Enrichment**: Automatically resolve IP addresses to hostnames

## Quick Start

### Prerequisites

- Python 3.7+
- pip

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ssrf-canary.git
cd ssrf-canary
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file (copy from `.env.example`):
```bash
cp .env.example .env
```

4. Configure your environment variables in `.env`

5. Run the application:
```bash
python app.py
```

The server will start on `http://0.0.0.0:8443` by default.

## Configuration

Configure the application using environment variables in your `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///ssrf_canary.db` |
| `ALERT_WEBHOOK` | Webhook URL for alerts | None |
| `ALERT_EMAIL` | Email address for alerts | None |
| `SMTP_HOST` | SMTP server hostname | None |
| `SMTP_PORT` | SMTP server port | `25` |
| `SMTP_USER` | SMTP username | None |
| `SMTP_PASS` | SMTP password | None |
| `APP_HOST` | Application host | `0.0.0.0` |
| `APP_PORT` | Application port | `8443` |
| `BASE_URL` | Base URL for canary links | `https://canary.example.com` |
| `TOKEN_EXPIRY_SECONDS` | Default token expiration | `604800` (7 days) |
| `RATE_LIMIT_MAX` | Max requests per window | `20` |
| `RATE_LIMIT_WINDOW` | Rate limit window (seconds) | `60` |

## API Documentation

### Create Token
```bash
POST /create_token
Content-Type: application/json

{
  "owner": "project-name",
  "expires_in": 604800
}
```

**Response:**
```json
{
  "token": "abc123...",
  "url": "https://canary.example.com/c/abc123...",
  "expires_at": "2025-11-02T12:00:00"
}
```

### List Tokens
```bash
GET /tokens
```

### Deactivate Token
```bash
POST /tokens/{token}/deactivate
```

### List Events
```bash
GET /events?page=1&per=50
```

### Canary Endpoint
```bash
GET|POST|PUT|PATCH|DELETE /c/{token}
```
All requests to this endpoint are logged and trigger alerts.

## Use Cases

- **API Security Testing**: Embed canary URLs in API responses to detect unauthorized access
- **SSRF Detection**: Identify applications making unintended requests to internal resources
- **Data Exfiltration Monitoring**: Track if sensitive data is being accessed from unexpected locations
- **Security Research**: Monitor callback attempts during penetration testing

## Security Considerations

- Always use HTTPS in production
- Keep your `.env` file secure and never commit it to version control
- Use strong, unique tokens for sensitive deployments
- Regularly review event logs for suspicious activity
- Consider running behind a reverse proxy (nginx, Caddy)

## Development

### Database Migrations

The application uses SQLAlchemy and automatically creates tables on first run. For production, consider using Alembic for migrations.

### Running Tests
```bash
# Coming soon
pytest
```

## Deployment

### Docker
```bash
docker build -t ssrf-canary .
docker run -p 8443:8443 --env-file .env ssrf-canary
```

### Production Considerations

- Use a production-grade database (PostgreSQL, MySQL)
- Deploy behind a reverse proxy with SSL/TLS
- Set up proper logging and monitoring
- Configure firewall rules appropriately
- Use a process manager (systemd, supervisor)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Acknowledgments

Built with Flask, SQLAlchemy, and ❤️ for security researchers.

## Disclaimer

This tool is intended for authorized security testing and monitoring only. Users are responsible for ensuring compliance with applicable laws and regulations.
