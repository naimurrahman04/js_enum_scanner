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
```

---

## 🚀 Usage

```bash
python3 js_enum_scanner.py <target_url> [--tokens=...] [--params=...] [--threads=...]
```

### Options:

| Argument      | Description                                       | Default        |
|---------------|---------------------------------------------------|----------------|
| `url`         | Target URL to scan                                | —              |
| `--tokens`    | Custom token keywords (comma-separated)           | Built-in list  |
| `--params`    | Custom parameter names (comma-separated)          | Built-in list  |
| `--threads`   | Number of threads for JS file fetching            | 5              |

### Example

```bash
python3 js_enum_scanner.py https://example.com \
  --tokens="jwt,key,auth_token" \
  --params="email,password,search" \
  --threads=10
```

---

## 🧪 Output

Saves a `scan_report_<timestamp>.json` file with the following structure:

```json
{
  "url": "https://example.com",
  "endpoints": ["/api/v1/user", ...],
  "parameters": ["id", "token", ...],
  "tokens": ["auth=12345", "api_key=abcdef", ...],
  "graphql_used": true
}
```

---

## 👨‍💻 Author

Built for offensive security testing and recon workflows.

---

## ⚠️ Disclaimer

This tool is for authorized security testing and educational use only. Do not use it against systems you do not own or have permission to test.
