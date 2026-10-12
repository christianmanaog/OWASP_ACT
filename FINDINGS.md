# Vulnerability Findings — <your name> & <partner name>

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A05:2025 – Injection | POST /login (lines 115-117) | Injects SQL via the username parameter to bypass auth | Use parameterized query: `("SELECT ... WHERE username = ?", (creds.username,))` |
| 2 | A04:2025 – Cryptographic Failures | POST /register (lines 105-108) & init_db (lines 63-65) | Reads plaintext passwords from database dumps | Hash passwords using `hashlib.sha256` + `SECRET_KEY` salt before storage |
| 3 | A07:2025 – Authentication Failures | POST /login & current_user (lines 86-90, 122) | Sends predictable `Authorization: Bearer 1` to impersonate admin | Issue and verify HMAC-signed tokens (`{user_id}:{signature}`) using `SECRET_KEY` |
| 4 | A01:2025 – Broken Access Control | GET /notes/{note_id} (lines 133-138) | Modifies note_id in URL to read other users' private notes | Query and verify note ownership: `WHERE id = ? AND owner_id = ?` |
| 5 | A01:2025 – Broken Access Control | GET /admin/users (lines 155-161) | Sends unauthenticated request; try/except pass grants full admin dump | Enforce `if not user or not user["is_admin"]: raise HTTPException(403)` and omit passwords |
| 6 | A02:2025 – Security Misconfiguration | Exception handler (lines 94-99) | Triggers 500 error to view full file paths and stack trace | Return generic error message `{"error": "Internal error"}` without traceback |

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?

In a production application, Broken Access Control combined with Insecure Authentication (Bugs 3 and 5) would likely inflict the greatest catastrophic damage. Because auth tokens were predictable sequential IDs and the admin check failed open on unauthenticated requests, any remote attacker could trivially attain full administrative privileges and dump sensitive records without credentials. Unlike bugs that require targeted interaction or specialized knowledge, predictable authentication completely destroys tenant isolation and perimeter security.
