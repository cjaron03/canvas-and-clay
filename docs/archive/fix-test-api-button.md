# Fixing the "Test API" Button - COMPLETED

**Status**: Fixed in commit 3480546 - "Enable CORS for API routes and document Test API fix (#30)"

Use this guide when the frontend "Test API" button silently fails after a fresh setup. The underlying issue is that the Flask backend does not expose the permissive CORS headers needed by the SvelteKit frontend when running on different ports.

## Prerequisites
- You can run the project with `docker compose up` from `infra/`.
- Git is configured with an upstream remote.

## Steps

1. **Create a feature branch**
   ```bash
   git checkout -b fix/frontend-cors-test-api
   ```

2. **Update `backend/app.py`**
   - Add the import near the top:
     ```python
     from flask_cors import CORS
     ```
   - Immediately after `app = Flask(__name__)`, enable CORS for the API routes that the frontend uses:
     ```python
     app = Flask(__name__)
     CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})
     ```
     Adjust the allowed origin if your frontend runs from a different URL in other environments.

3. **Restart only the backend container**
   ```bash
   docker compose -f infra/docker-compose.yml restart backend
   ```
   Restarting ensures the Flask process reloads with the new configuration.

4. **Verify the fix**
   - Reload `http://localhost:5173/` in the browser.
   - Open the developer console (Develop → Show Web Inspector in Safari).
   - Click **Test API** and confirm the alert displays the JSON payload from `/api/hello`.
   - Confirm no new CORS errors appear in the console.

5. **Commit and push**
   ```bash
   git add backend/app.py docs/fix-test-api-button.md
   git commit -m "Enable CORS for API routes and document Test API fix"
   git push --set-upstream origin fix/frontend-cors-test-api
   ```

6. **Open a pull request**
   - Link to the Safari console error (`Access-Control-Allow-Origin` blocked).
   - Reference the documentation in `docs/fix-test-api-button.md`.
   - Request review from the backend owner.

## Troubleshooting
- If the console still shows CORS errors, ensure the container picked up the change (you may need `docker compose down && docker compose up --build` if hot reload is disabled).
- To allow multiple origins, pass a list to the `origins` key, e.g. `["http://localhost:5173", "http://127.0.0.1:5173"]`.

