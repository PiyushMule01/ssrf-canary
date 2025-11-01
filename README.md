# SSRF Canary

Lightweight Flask application for detecting and monitoring Server-Side Request Forgery (SSRF) by generating unique canary tokens and logging any requests made to their endpoints.

## Features

* Token generation with configurable expiry
* HTTP canary endpoint that logs method, headers, body preview and requester IP
* Heuristics to flag requests from private or cloud metadata IPs
* Webhook and email alerting (configurable)
* Basic rate limiting to reduce noise
* SQLite persistence (tokens + events)
* Simple admin endpoints for token and event management

## Quick start

### Prerequisites

* Python 3.7+
* pip

### Install & run

1. Clone the repo and open its folder:

```bash
git clone https://github.com/<your-username>/ssrf-canary.git
cd ssrf-canary
```

2. Create and activate a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Copy the example env and edit values:

```bash
cp .env.example .env
# edit .env -> set BASE_URL=http://localhost:8443 for local testing
```

5. Start the app:

```bash
python ssrf_canary_server.py
```

Default server address: `http://0.0.0.0:8443`.

## API

All endpoints return JSON.

### Create Token

**Request**

```
POST /create_token
Content-Type: application/json

{
  "owner": "project-name",
  "expires_in": 604800
}
```

* `owner` (string): identifier for the token (e.g., project, test name)
* `expires_in` (integer, optional): seconds until token expiry (default 604800 = 7 days)

**Important**: the request **must** include `Content-Type: application/json` and a valid JSON body. If the body is empty or not JSON, the server may respond with an error like:

```json
{ "error": "enter content" }
```

(Use `curl` or Postman with `Content-Type: application/json` to avoid this.)

**Example (curl)**

```bash
curl -X POST http://localhost:8443/create_token \
     -H "Content-Type: application/json" \
     -d '{"owner":"project-name","expires_in":604800}'
```

**Response**

```json
{
  "token": "a1b2c3d4e5f6...",
  "url": "http://localhost:8443/c/a1b2c3d4e5f6...",
  "expires_at": "2025-11-02T12:00:00"
}
```

### List Tokens

```
GET /tokens
```

### Deactivate Token

```
POST /tokens/{token}/deactivate
```

### List Events

```
GET /events?page=1&per=50
```

* `page` and `per` control pagination.

### Canary Endpoint (what attackers call)

```
GET|POST|PUT|PATCH|DELETE /c/{token}
```

All requests to this endpoint are logged as events. The server records method, headers, a short body preview, remote IP (uses `X-Forwarded-For` first if present), and flags suspicious requests based on IP heuristics.

## Example workflow

1. Create a token:

```bash
curl -X POST http://localhost:8443/create_token \
     -H "Content-Type: application/json" \
     -d '{"owner":"test"}'
```

2. Embed the returned URL (e.g., `http://localhost:8443/c/<token>`) in an application or payload that might be SSRF-vulnerable.

3. When the app/server calls that URL, the event appears:

```bash
curl http://localhost:8443/events
```

## Configuration

Use `.env` (copy `.env.example`) to set:

* `DATABASE_URL` — DB connection string (default uses SQLite file)
* `BASE_URL` — public base used for building canary URLs (set to tunnel/ngrok URL if using tunnels)
* `ALERT_WEBHOOK` — webhook URL for alerts (Slack, Teams, Discord)
* `ALERT_EMAIL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` — for email alerts
* `APP_HOST`, `APP_PORT` — host/port to bind
* `TOKEN_EXPIRY_SECONDS`, `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW`

## Running behind a tunnel (ngrok)

Expose your local server to the internet for testing:

```bash
ngrok http 8443
```

Set `BASE_URL` in `.env` to the ngrok URL (e.g., `https://abcd1234.ngrok.io`) and re-create tokens so they show the public URL.

## Deployment

* Use a production WSGI server (gunicorn) and a reverse proxy (nginx/Caddy) with TLS.
* Use a production database (Postgres/MySQL) for durability.
* Secure admin endpoints with authentication before exposing publicly.

## Security & legal

* Only test systems you own or have authorization to test.
* Do not use canaries to provoke access to third-party private systems.
* Keep `.env` out of version control.

## Development

* The app auto-creates DB tables on first run (SQLite by default). For production migrations use Alembic.
* Tests: add unit tests (pytest) in `tests/` as the next step.

## Docker

Build:

```bash
docker build -t ssrf-canary .
```

Run:

```bash
docker run -p 8443:8443 --env-file .env ssrf-canary
```

## Contributing

Contributions welcome. Open issues or submit PRs for features such as DNS-based canaries, authentication, or improved alerting.

## License

MIT License. See `LICENSE` file.

## Acknowledgements

Built with Flask and SQLAlchemy — intended for authorized security research only.

