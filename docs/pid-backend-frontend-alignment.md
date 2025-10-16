# Canvas & Clay PID – Backend/Frontend Alignment

## Context
- Current dev setup: Flask backend served on port 5000 and SvelteKit frontend consuming APIs via `fetch`.


## Problem Statement
Frontend `fetch` targets `http://localhost:5001/api/hello`, while the Flask app defaults to port 5000. Result: the primary integration button fails in development. Additionally, `/health` always reports `"status": "healthy"` even if the database probe throws, hiding real outages from monitoring.

## Goals & Success Metrics
- Frontend automatically points to the correct backend base URL per environment (dev/prod) without manual code edits.
- `/health` surfaces degraded status when the database is unavailable, aligning JSON payload and HTTP status with reality.
- Automated tests cover the failure path of the health endpoint.

## Scope
- Update frontend configuration (likely via environment-driven Vite/SvelteKit config) to reference the backend URL.
- Adjust backend `/health` endpoint to reflect database failures and ensure tests cover both success and failure cases.
- Update documentation/runbooks where the integration touchpoints are referenced.

## Non-Goals
- Implement the queued security TODOs (auth, CORS hardening, rate limiting, etc.).
- Introduce new deployment environments or CI/CD changes beyond ensuring tests run locally.

## Workstreams

### 1. **Frontend base URL fix** ✅ COMPLETED
   - ✅ Introduced `PUBLIC_API_BASE_URL` environment variable (SvelteKit requirement for browser-exposed vars)
   - ✅ Updated `frontend/src/routes/+page.svelte` to use `$env/static/public` for API calls
   - ✅ Created `frontend/.env.example` with sensible defaults for local dev
   - ✅ Created `frontend/.env` for local development (gitignored)
   - ✅ Documented configuration in `README.md` with copy commands and env variable explanation
   - **Commit:** `026c34d` - "feat: implement environment-driven API base URL for frontend"

### 2. **Backend health endpoint hardening** ✅ COMPLETED
   - ✅ Updated `/health` endpoint to return HTTP 503 + `"status": "degraded"` on database failure
   - ✅ Maintained HTTP 200 + `"status": "healthy"` for successful connections
   - ✅ Added `test_health_endpoint_success()` to verify healthy state
   - ✅ Added `test_health_endpoint_database_failure()` with mocked database exception
   - ✅ Improved endpoint documentation with return value specifications
   - **Commit:** `8f25a5b` - "feat: harden health endpoint to reflect database failures"

### 3. **Documentation & DX** ✅ COMPLETED
   - ✅ Updated `README.md` Quick Start to include frontend `.env.example` copy step
   - ✅ Added "Environment Configuration" section explaining both backend and frontend env files
   - ✅ Documented `PUBLIC_` prefix requirement for SvelteKit
   - ✅ Updated this PID with completion status and commit references

## Branching & Workflow
1. Ensure you are back on the latest main:
   ```bash
   git checkout main
   git pull origin main
   ```
2. Create a dedicated fix branch for Cursor collaboration:
   ```bash
   git checkout -b fix/cursor-backend-frontend-alignment
   ```
3. Implement changes iteratively, committing logical chunks that Cursor (and teammates) can review.
4. Push the branch and open a PR once tests pass:
   ```bash
   git push -u origin fix/cursor-backend-frontend-alignment
   ```

## Testing Strategy
- Backend: run `pytest` locally; add coverage for health endpoint failure.
- Frontend: run `npm run test` and manual sanity test of the button against the corrected API URL.

## Risks & Mitigations
- **Risk:** Environment configs drift between Cursor prompts and actual `.env` files.  
  **Mitigation:** Store canonical example in `frontend/.env.example` and reference it in docs.
- **Risk:** Health endpoint change could break monitoring dashboards expecting `"healthy"`.  
  **Mitigation:** Communicate the change and update alert rules to watch for `"degraded"`/HTTP 503.

## Deliverables ✅ ALL COMPLETED
- ✅ Updated frontend fetch logic driven by `PUBLIC_API_BASE_URL` configuration
- ✅ Hardened `/health` endpoint with HTTP 503 responses and `"degraded"` status on DB failures
- ✅ Comprehensive test coverage for both success and failure paths
- ✅ Documentation updates: README.md, frontend/.env.example, and this PID

## Implementation Summary
**Branch:** `docs/pid-alignment`  
**Commits:** 3 total
1. `4d2fd09` - Initial PID document
2. `026c34d` - Frontend environment-driven API configuration
3. `8f25a5b` - Backend health endpoint hardening with tests

**Next Steps:**
1. Push branch to GitHub: `git push origin docs/pid-alignment`
2. Verify CI/CD tests pass (especially the new health endpoint failure test)
3. Merge PR to main once approved
