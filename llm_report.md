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
- Payload: ` OR '1'='1`
- Evidence: Error: SQLITE_ERROR: near &quot;1&quot;: syntax error</h2>       <ul id="stacktrace"></ul>     </div>   </body> </html> 
- Recommendation: Use parameterized queries, avoid string-built SQL, and validate inputs server-side.

### SQL Injection in /rest/user/login
- Severity: critical
- Confidence: 0.9
- Endpoint: POST /rest/user/login
- Endpoint type: auth_login
- Attack style: auth_boolean_bypass
- Parameter: email
- Payload: `' OR 1=1 --`
- Evidence: Baseline returned 401, probe returned 200 with authentication data.
- Recommendation: Use parameterized queries, avoid string-built SQL, and validate inputs server-side.

## Not Decidable Targets

### GET /api/Challenges
- Parameter: key
- Reason: endpoint appears to serve metadata

### GET /api/Challenges
- Parameter: name
- Reason: endpoint appears to serve metadata

### GET /api/Products/1
- Parameter: d
- Reason: Skipped by suitability gate: parameter 'd' is a query parameter and does not fit the route purpose and recommended attack style.

### GET /api/Products/24
- Parameter: d
- Reason: Skipped by suitability gate: The parameter 'd' is a query parameter and the endpoint_context recommends avoiding union_enum and auth_bypass payload styles.

### GET /api/Products/42
- Parameter: d
- Reason: Skipped by suitability gate: parameter 'd' is a query parameter and does not plausibly influence a database query, lookup, search, or authentication check

### GET /api/Products/6
- Parameter: d
- Reason: Skipped by suitability gate: The parameter 'd' is a query parameter and the recommended attack style is 'numeric_identifier_probe' for product detail endpoints.

### GET /rest/user/change-password
- Parameter: current
- Reason: Endpoint type is sensitive_write and recommended_attack_style is skip_low_value.

### GET /rest/user/security-question
- Parameter: email
- Reason: Endpoint is used to retrieve security question and likely uses authentication lookup, but recommended_attack_style is auth_boolean_bypass which suggests probing is not recommended.

### GET /api/Products/1
- Parameter: product_id
- Reason: No SQL error, auth bypass, timing, content-type, or meaningful body change.

### GET /api/Products/24
- Parameter: product_id
- Reason: Enough evidence was gathered, no useful signal remains, or endpoint is not suitable.

### GET /api/Products/42
- Parameter: product_id
- Reason: Max attempts reached.

### GET /api/Products/6
- Parameter: product_id
- Reason: Baseline and probe are effectively identical and there is no SQL error, auth bypass, timing, content-type, or meaningful body change.

### POST /rest/user/login
- Parameter: password
- Reason: Skipped by suitability gate: Skipped password field because an identity field is available for authentication-query testing.

### GET /rest/user/whoami
- Parameter: fields
- Reason: Stopped because the response matched baseline closely; there was no useful error or behavior signal to adapt from.

## Capability Coverage

- Confirmed surfaces: 2
- Confirmed techniques: authentication_bypass, error_based_sqli
- DBMS hints: sqlite
- Unverified capabilities: non-sensitive in-band read confirmation was not proven
- Potential impact: authentication logic can be bypassed for the affected endpoint; database query structure is influenced by user input
