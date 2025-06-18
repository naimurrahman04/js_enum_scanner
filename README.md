# js_enum_scanner
# JavaScript Endpoint & Parameter Scanner

A powerful Python tool for JavaScript-based recon in web penetration testing. It scans a target URL for:

- Endpoints in JavaScript files (external + inline)
- Query parameters
- API tokens or keys
- GraphQL usage detection
- Parameter fuzzing on discovered endpoints

---

## 🛠 Features

- ✅ Crawls and analyzes external + inline JS
- ✅ Identifies tokens/keys (`api_key`, `auth`, `access_token`, etc.)
- ✅ Detects parameter names via regex
- ✅ Scans for GraphQL usage
- ✅ Multi-threaded JS fetching for speed
- ✅ Fuzzes endpoints with common/custom parameters
- ✅ JSON report output

---

## ⚙️ Requirements

```bash
pip install requests
