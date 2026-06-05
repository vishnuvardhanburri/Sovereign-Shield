# Performance Report

## Performance Objective

Sovereign Shield should preserve fast request acceptance while moving AI-heavy execution out of synchronous request paths.

Target posture:

- Request acceptance for AI-heavy work: under 250 ms
- General API p95: under 300 ms
- Authentication: under 250 ms
- License validation: under 100 ms
- Dashboard load: under 1 second where cached or aggregated endpoints are available
- Control room load: under 2 seconds

## Current Performance Architecture

The repository includes asynchronous job handling for heavy AI request paths. This design reduces request-response blocking and supports:

- Job acceptance endpoint
- Worker execution
- Status endpoint
- Result endpoint
- Cancellation support
- Timeout handling
- Retry handling
- Audit logging

## AI-Heavy Paths

The following paths are performance-sensitive and should remain asynchronous or carefully bounded:

- `/api/v2/chat`
- `/api/v2/chat/stream`
- `/ask`
- `/api/v2/enterprise/model-benchmark`
- `/shadow-ai/scan`

## Dashboard Performance

Dashboard routes should avoid fan-out patterns where one page requires many API calls. Preferred approach:

- Aggregated control-room endpoint
- Cached risk heatmap
- Cached readiness snapshot
- Bounded report listing
- Pagination for ledger and alert rows
- No unbounded in-browser processing of large evidence files

## Database And State Risks

Performance review should verify:

- No unbounded full-table scans on ledger-like stores
- Pagination for audit events
- Bounded in-memory risk heatmap
- Redis use for shared session and risk state in multi-node mode
- Indexing for production database tables
- Background generation for expensive reports

## Verification Evidence

Recent local verification performed during repositioning work included:

- Python syntax checks for changed backend scripts
- Static frontend lint
- Static frontend build
- Full Python test suite before the final endpoint rename: 94 passed

Recommended buyer-side performance evidence:

- p50, p95, p99 API latency
- Throughput under concurrent users
- Worker queue depth
- Worker completion rate
- CPU and memory under load
- Ollama latency by model
- Dashboard route waterfall
- Container startup time

## Open Performance Actions

| Area | Recommended Action |
| --- | --- |
| Load testing | Run k6 or Locust tests against production-like stack |
| Worker telemetry | Emit queue depth, retries, failures, and duration metrics |
| Dashboard aggregation | Keep UI pages under two API calls where practical |
| Database tuning | Add production indexes based on query plan output |
| Ollama sizing | Benchmark each buyer-selected model and hardware profile |

