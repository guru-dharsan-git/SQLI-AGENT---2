# SQL Injection Assessment Report

SQL injection vulnerabilities were identified from local probe evidence.

## Findings

### SQL Injection in /rest/products/search
- Severity: critical
- Confidence: 0.9
- Endpoint: GET /rest/products/search
- Endpoint type: search
- Attack style: string_search_error_probe
- Parameter: q
- Payload: ` OR 'a'='a`
- Evidence: Probe response exposed SQLITE_ERROR.
- Recommendation: Use parameterized queries, avoid string-built SQL, and validate inputs server-side.

### SQL Injection in /rest/user/login
- Severity: critical
- Confidence: 0.9
- Endpoint: POST /rest/user/login
- Endpoint type: auth_login
- Attack style: auth_boolean_bypass
- Parameter: email
- Payload: `' OR '' = '' --`
- Evidence: Baseline login failed with 401, while probe returned 200 with authentication data.
- Recommendation: Use parameterized queries, avoid string-built SQL, and validate inputs server-side.

## Capability Coverage

- Confirmed surfaces: 2
- Confirmed techniques: authentication_bypass, error_based_sqli
- DBMS hints: sqlite
- Unverified capabilities: non-sensitive in-band read confirmation was not proven
- Potential impact: authentication logic can be bypassed for the affected endpoint; database query structure is influenced by user input
