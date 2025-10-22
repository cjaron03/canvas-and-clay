# Docker Build Optimization Plan

## Overview
This document capture the agreed improvements for both backend and frontend Docker workflows. Follow the steps below to implement and verify the changes without altering existing runtime behaviour (Flask dev server on backend, `npm run preview` on frontend).

## 1. Repository Hygiene
- Add tailored `.dockerignore` files to `backend/` and `frontend/` that exclude `node_modules`, `__pycache__`, build outputs, tests, docs, and VCS metadata to minimise build context.
- Document any new ignores in the respective READMEs so contributors understand the structure.

## 2. Backend Image Optimisation (`backend/Dockerfile`)
1. Switch the base image to `python:3.12-slim` for faster wheel installs while keeping glibc compatibility.
2. Introduce a multi-stage build:
   - Builder stage installs dependencies using `pip install -r requirements.txt` with a BuildKit cache mount (`--mount=type=cache,target=/root/.cache/pip`).
   - Final stage copies only the installed packages and project source.
3. Set environment variables such as `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUNBUFFERED=1` to reduce runtime overhead.
4. Ensure build-time packages are not present in the final image.
5. Keep the existing Flask development server entrypoint; only supporting optimisations should change.

## 3. Frontend Image Optimisation (`frontend/Dockerfile`)
1. Convert to a multi-stage build:
   - Builder stage runs `npm ci` using a BuildKit cache mount (`--mount=type=cache,target=/root/.npm`) and executes `npm run build`.
   - Runtime stage copies the built output and necessary `node_modules` from the builder.
2. Continue using `node:20-alpine` for the runtime layer; set `NODE_ENV=production` if the preview server tolerates it.
3. Preserve the `npm run preview -- --host 0.0.0.0 --port 5173` command.
4. Maintain the `PUBLIC_API_BASE_URL` `ARG`/`ENV` pattern and document default values as part of the build setup.

## 4. Docker Compose Adjustments (`infra/docker-compose.yml`)
- Remove the inline `npm install` from the frontend service command to avoid repeated dependency reinstalls. Rely on the mounted workspace and optionally a named volume for `node_modules`.
- Verify the backend service still uses the Flask development server as before.
- If volumes change, update any documentation or scripts referencing them.

## 5. CI/CD Pipeline Updates (`.github/workflows/ci.yml`)
1. Ensure Docker BuildKit is explicitly enabled (e.g., `DOCKER_BUILDKIT=1`) for build steps when necessary.
2. Apply BuildKit cache hints to backend and frontend builds (`cache-from/cache-to` or `docker/build-push-action` options) to reuse layers across runs.
3. Remove redundant frontend image builds so the workflow only builds once with caching enabled.
4. Keep existing lint/test stages intact; verify they operate against the optimised images when `docker-test` runs.

## 6. Documentation & Developer Experience
- Update the root `README.md` (and any onboarding docs) with instructions for enabling BuildKit locally (`docker info` check, `DOCKER_BUILDKIT=1` usage, `~/.docker/config.json` snippet).
- Note the new multi-stage structure and `.dockerignore` files to prevent regressions.
- Record any follow-up tasks or environment variable defaults in the PID or related decision logs.

## 7. Validation Checklist
1. Build backend and frontend images locally with BuildKit enabled and confirm layer caching behaviour.
2. Run `docker compose up` from `infra/` to confirm workflow parity (backend still on port 5000 exposed as 5001, frontend accessible on 5173).
3. Execute CI locally or via a dry-run to ensure the new caching configuration functions on the pipeline.
4. Capture before/after image sizes and build times for visibility; update documentation if the numbers are used in reporting.

## 8. Follow-Up
- If future improvements target runtime servers (Gunicorn or a Svelte adapter), capture those in a separate proposal so they can be scheduled independently of these build optimisations.
- Monitor subsequent builds and adjust cache sizes or `.dockerignore` entries as needed to keep container performance high.
