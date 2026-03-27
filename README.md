# Passleak Connector for OpenCTI

The **Passleak Connector** integrates the Passleak leaked credentials database with OpenCTI. It monitors approved domains and imports discovered credential leaks as STIX 2.1 objects.

## What it imports

For each approved domain in your Passleak account, the connector fetches monitoring events and creates:

- **Incident** — one per leak source (`source` field), linked to the domain
- **Malware** — one per stealer family (`stealer_type`: lumma, redline, banshee, etc.), linked to the incident
- **UserAccount** — one per leaked credential (email or login + password), linked to the incident and domain

Incremental fetching: on each run only new events are loaded (offset-based state per domain).

## Requirements

- OpenCTI Platform 5.10.x or higher
- Passleak account with at least one approved domain
- Passleak API key (`plk_...`)

## Configuration

| Docker envvar          | Mandatory | Default                     | Description                                     |
|------------------------|-----------|-----------------------------|-------------------------------------------------|
| `OPENCTI_URL`          | Yes       | —                           | OpenCTI platform URL                            |
| `OPENCTI_TOKEN`        | Yes       | —                           | OpenCTI admin token                             |
| `CONNECTOR_ID`         | Yes       | —                           | Unique UUIDv4 for this connector instance       |
| `CONNECTOR_NAME`       | Yes       | —                           | Display name, e.g. `Passleak Feed`              |
| `CONNECTOR_SCOPE`      | Yes       | `application/json`          | Connector scope                                 |
| `CONNECTOR_LOG_LEVEL`  | No        | `info`                      | Log verbosity: `debug`, `info`, `warn`, `error` |
| `PASSLEAK_API_KEY`     | Yes       | —                           | Passleak API key (`plk_...`)                    |
| `PASSLEAK_BASEURL`     | No        | `https://api.passleak.com/` | Passleak API base URL                           |
| `PASSLEAK_INTERVAL`    | No        | `86400`                     | Polling interval in seconds                     |
| `PASSLEAK_CONTIMEOUT`  | No        | `30`                        | Connection timeout in seconds                   |
| `PASSLEAK_READTIMEOUT` | No        | `60`                        | Read timeout in seconds                         |
| `PASSLEAK_RETRY`       | No        | `5`                         | Connection retry attempts                       |

## Quick start

```bash
cp src/config.yml.sample src/config.yml
# Edit src/config.yml with your settings, or use environment variables

docker compose up -d
```

## Running tests

```bash
cd src
python3 -m pytest tests/ -v

# Integration test against real API:
PASSLEAK_API_KEY=plk_... python3 tests/test_integration.py
```
