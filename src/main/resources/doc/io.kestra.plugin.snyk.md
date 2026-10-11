# Snyk

The Snyk plugin integrates Kestra with the Snyk REST API.

## ListIssues

io.kestra.plugin.snyk.ListIssues retrieves issues for a Snyk organization.

The task supports optional severity filtering, cursor pagination, and Kestra fetch modes FETCH_ONE, FETCH, and STORE.

### Connection

Provide a Snyk API token:

~~~yaml
token: "{{ secret('SNYK_API_TOKEN') }}"
~~~

Authentication is sent as:

~~~text
Authorization: token <API_TOKEN>
~~~

The default REST base URL is https://api.snyk.io/rest. Regional endpoints can be supplied through baseUrl.

The default API version is 2024-10-15. The Kestra property is named apiVersion; the request sends it to Snyk as the version query parameter because version is reserved by Kestra.

### List all issues

~~~yaml
id: snyk_list_issues
namespace: company.team

tasks:
  - id: list_issues
    type: io.kestra.plugin.snyk.ListIssues
    token: "{{ secret('SNYK_API_TOKEN') }}"
    orgId: "{{ secret('SNYK_ORG_ID') }}"
~~~

### Filter by severity

~~~yaml
id: snyk_list_high_risk
namespace: company.team

tasks:
  - id: list_issues
    type: io.kestra.plugin.snyk.ListIssues
    token: "{{ secret('SNYK_API_TOKEN') }}"
    orgId: "{{ secret('SNYK_ORG_ID') }}"
    severities:
      - CRITICAL
      - HIGH
~~~

### Regional endpoint

~~~yaml
id: snyk_list_eu
namespace: company.team

tasks:
  - id: list_issues
    type: io.kestra.plugin.snyk.ListIssues
    token: "{{ secret('SNYK_API_TOKEN') }}"
    orgId: "{{ secret('SNYK_ORG_ID') }}"
    baseUrl: "https://api.eu.snyk.io/rest"
~~~

### Fetch types

FETCH is the default and returns all issues in outputs.list_issues.rows.

FETCH_ONE requests one result from the first page and returns outputs.list_issues.row without following the next cursor.

STORE follows all pages and writes the rows to Kestra internal storage. The URI is available as outputs.list_issues.uri.

All modes expose outputs.list_issues.size as the number of returned issues.

~~~yaml
id: snyk_store_issues
namespace: company.team

tasks:
  - id: list_issues
    type: io.kestra.plugin.snyk.ListIssues
    token: "{{ secret('SNYK_API_TOKEN') }}"
    orgId: "{{ secret('SNYK_ORG_ID') }}"
    fetchType: STORE
~~~

### API behavior

The task calls GET /orgs/{org_id}/issues.

The first request sends version, limit, and optional effective_severity_level array filters.

FETCH and STORE follow the links.next cursor supplied by Snyk instead of reconstructing cursor values locally.

Unknown additive response fields are ignored by the response models.

### Security gate example

~~~yaml
id: snyk_security_gate
namespace: company.team

tasks:
  - id: list_issues
    type: io.kestra.plugin.snyk.ListIssues
    token: "{{ secret('SNYK_API_TOKEN') }}"
    orgId: "{{ secret('SNYK_ORG_ID') }}"
    severities:
      - CRITICAL
      - HIGH
    fetchType: FETCH

  - id: log_count
    type: io.kestra.plugin.core.log.Log
    message: "Found {{ outputs.list_issues.size }} critical/high Snyk issue(s)"
~~~
