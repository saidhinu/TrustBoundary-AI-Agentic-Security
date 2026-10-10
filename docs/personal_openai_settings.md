# OpenAI Settings: optional per-visitor BYOK (v1.5.0)

**Default:** Offline hybrid (heuristics + local ML); no key needed, and no OpenAI request occurs. The deterministic role/provenance/tool gate is independent of the classifier.

## Steps

1. From the repository root: `pip install -r requirements.txt` and `python -m uvicorn trustboundary.api:app --port 8000`.
2. Open `http://127.0.0.1:8000`, choose **Settings**.
3. Set **OpenAI assisted**, enter a **new, private OpenAI project API key** and model `gpt-4o-mini`.
4. Select **Test connection**. The backend calls the OpenAI chat-completions endpoint with a synthetic benign settlement sentence. A successful result validates that this key/model can make that request at the time; API charges may occur.
5. Select **Use key in this tab**, return to **Attack Lab**, leave Force offline fallback unchecked, and inspect a scenario. The result's classifier mode should be `heuristic_local_ml_plus_llm` when the remote classification succeeded.
6. Switch back to Offline or select **Clear key**. Refreshing or closing the tab clears the key automatically.

## Privacy, security, and fallback

- The API key is held in the current browser tab's JavaScript memory only. It is not saved to localStorage, sessionStorage, cookies, SQLite, logs written by the application, or GitHub source.
- The key travels in `X-OpenAI-API-Key` over a same-origin HTTPS request to FastAPI. Only the server calls the OpenAI API. Request handling uses `Cache-Control: no-store`, and no untrusted user key from an earlier request can be reused on another visitor's request.
- The server receives the requested content, key, and model. **Only synthetic content** is appropriate for this prototype.
- Provider errors/timeouts fall back to local detection and show `heuristic_fallback_llm_unavailable`. Test connection will show a generic error for 401/403/429/5xx or timeout, without revealing the key or raw provider error.
- The offline evaluation dashboard **does not test OpenAI** even when a key is enabled. Hosted model gains must be independently evaluated; 124 automated tests cover the integration via mock responses only.
- Public deployment requires authentication, HTTPS, rate limiting, tenant isolation, CSP, safe reverse-proxy logging and independent penetration testing. Users should never enter secrets into an untrusted host. GitHub code hosting does not constitute a running backend deployment.
- A key posted in a chat, issue, screenshot or code repository should be **revoked and replaced before use**. The shared key was not used to test this project.

## API endpoints

- `POST /settings/test` — JSON `{"model":"gpt-4o-mini"}` + private `X-OpenAI-API-Key` header. Returns connection status and metadata, never the key.
- `POST /scan` or `POST /agent/compare` — same optional private key header plus `X-OpenAI-Model`, with the usual synthetic request JSON. Without headers, the system remains offline.
- `GET /health` — indicates personal key support, **not** whether a particular visitor's private key is valid.
