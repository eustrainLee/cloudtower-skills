---
name: exporting-traffic-visualization-flows
description: >
  Export large batches of summarized traffic-visualization flow rows from CloudTower as CSV.
  Best suited when you need broad cluster-wide flow snapshots rather than deep interactive TQL.
  Use when the user needs flow exports for downstream analysis or a plain file download.
---

# Exporting traffic visualization flows

Common cases: inspect or summarize the CSV with your own tools, or deliver the file as-is. Prefer **`export-traffic-visualization-flows.py --help`** for flags and defaults.

**After you download the CSV on the async path, you must delete the server-side async request** (see Workflow).

## Quick start

Export one hour of traffic visualization flow data for a specific cluster associated with an observability service.

**Always pass these three flags:** **`--obs`** (observability instance), **`--from_time`**, and **`--to_time`**. They are required to scope the export; do not omit them when running the script for this use case.

```bash
python3 export-traffic-visualization-flows.py \
  --env=/path/to/.env \
  --obs=my-observability-service-name \
  --clusters=my-cluster-name \
  --from_time=2026-01-01T11:00:00Z \
  --to_time=2026-01-01T12:00:00Z
```

Use real values. Timestamps are RFC3339 (timezone `Z` or numeric offset). **`--obs`** accepts a single name, id, or management IP (no comma-separated list).

## Workflow

1. Authenticate against CloudTower (e.g. `.env` with `TOWER_URL` and token or username/password).
2. Scope the run: observability instance, clusters, UTC window, optional filters (`--help`).
3. If the export is asynchronous: poll until ready, download the file, then **immediately delete that async request** using the script’s delete operation (`--help` for the flag). Treat **download + delete** as one unit of work—**do not stop after download**, even when the next step is CSV analysis. Optional **`--sync-export`** with **`--output`** performs download and delete in one process; reserve it for very small result sets. Tune polling and timeout via `--help` if needed.

### Examples: status, download, delete

After you start an async export (without `--sync-export`), the JSON response includes:

- **`id`** — async **request** id (UUID). Use this for **`--request-status`** and **`--delete-request`**.
- **`task_status.id`** — **export task** id (long hex string). Use this for **`--download-task`** once **`task_status.ready`** is true.

Replace placeholders with values from that response. Each command needs **`--env`** and **`--obs`** (same instance as the export).

**Poll status** (repeat until `task_status.ready` is true and there is no error):

```bash
python3 export-traffic-visualization-flows.py \
  --env=/path/to/.env \
  --obs=my-observability-service-name \
  --request-status=REQUEST_UUID
```

**Download CSV** (only after the task is ready):

```bash
python3 export-traffic-visualization-flows.py \
  --env=/path/to/.env \
  --obs=my-observability-service-name \
  --download-task=TASK_ID \
  --output=/path/to/flows.csv
```

**Delete the async request** (required after a successful download; use the **request** UUID, not the task id):

```bash
python3 export-traffic-visualization-flows.py \
  --env=/path/to/.env \
  --obs=my-observability-service-name \
  --delete-request=REQUEST_UUID
```

## Progress checklist

```
- [ ] Credentials and Tower base URL ready
- [ ] Instance, clusters, time window (and filters if needed)
- [ ] Async path: status, download, **then delete request** (never skip delete after download; or use `--sync-export` only when data is tiny)
```
