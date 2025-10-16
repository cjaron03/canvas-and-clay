# Canvas & Clay PID – Backend/Frontend Alignment

## Context
- Current dev setup: Flask backend served on port 5000 and SvelteKit frontend consuming APIs via `fetch`.
- Tooling: Cursor for AI pair programming, Vite dev server for frontend, pytest for backend tests.

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
1. **Frontend base URL fix**
   - Introduce environment variable (e.g., `VITE_API_BASE_URL`) and use it within `+page.svelte`.
   - Provide sensible default for local dev; document overrides for Cursor prompts.
2. **Backend health endpoint hardening**
   - Propagate database failure to the response JSON and HTTP status (e.g., 503).
   - Expand `backend/tests/test_app.py` with a failure-path test using a mocked database session/engine.
3. **Documentation & DX**
   - Record the configuration steps in `README.md` or relevant docs.
   - Note Cursor prompt guidance so AI tooling references the new env-driven approach.

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

## Deliverables
- Updated frontend fetch logic driven by configuration.
- Hardened `/health` endpoint with accompanying tests.
- Documentation updates (PID, README snippet, env example) ready for Cursor-assisted development.
