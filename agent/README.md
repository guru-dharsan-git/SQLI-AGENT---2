# LLM SQLi Agent

This folder is the post-scan agent stage.

Flow:

1. Read `sqli_targets.json`.
2. Ask the configured LLM whether each parameter is suitable for SQLi probing.
3. Skip parameters that do not plausibly affect database lookup, search, or authentication logic.
4. Ask the LLM for one non-destructive payload at a time.
5. Send baseline and probe requests.
6. Summarize the response signal, such as SQL errors, status changes, or login bypass behavior.
7. Ask the LLM to decide one action:
   - `escalate`
   - `not_decidable`
   - `stop`
8. Stop when the response matches baseline closely instead of trying random payloads.
9. Write `agent_results.json`.

The code does not contain a SQLi payload list. Payload strings come from the LLM response.
The runner rejects destructive SQL and command-style payloads before sending them.

Install dependencies:

```powershell
venv\Scripts\python.exe -m pip install -r requirements.txt
```

Configure NVIDIA:

```powershell
$env:LLM_PROVIDER = "nvidia"
$env:NVIDIA_API_KEY = "your-api-key"
```

The default NVIDIA endpoint is `https://integrate.api.nvidia.com/v1`, and the
default model is `meta/llama-3.3-70b-instruct`. To override it:

```powershell
$env:NVIDIA_MODEL = "meta/llama-3.1-8b-instruct"
```

Gemini is still supported through the official `google-genai` Python SDK:

```powershell
$env:LLM_PROVIDER = "gemini"
$env:GEMINI_API_KEY = "your-api-key"
```

Run:

```powershell
venv\Scripts\python.exe -m agent.runner
```

For a quick first pass:

```powershell
venv\Scripts\python.exe -m agent.runner --limit 1 --max-payloads 1
```

Remote targets are blocked by default. The intended target is the local lab app.
