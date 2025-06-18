package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
)

type HeaderCheckResult struct {
	Name           string `json:"name"`
	Status         string `json:"status"`   // present, missing, warning, error
	Severity       string `json:"severity"` // critical, high, medium, low, info
	Description    string `json:"description,omitempty"`
	Value          string `json:"value,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

type ScanResult struct {
	URL            string              `json:"url"`
	Score          int                 `json:"score"`
	Grade          string              `json:"grade"`
	Headers        []HeaderCheckResult `json:"headers"`
	MissingHeaders []HeaderCheckResult `json:"missing_headers"`
	Improvements   []string            `json:"improvements"`
	SummaryTable   string              `json:"summary_table,omitempty"`
	DetailedReport string              `json:"detailed_report,omitempty"`
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Allow-Credentials", "false")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	targetURL := query.Get("url")

	if targetURL == "" {
		http.Error(w, "URL parameter is required", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	_, err := url.ParseRequestURI(targetURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	result, err := scanHeaders(targetURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error scanning URL: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func scanHeaders(targetURL string) (*ScanResult, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	var results []HeaderCheckResult
	results = append(results, checkCSP(headers))
	results = append(results, checkHSTS(headers))
	results = append(results, checkXContentTypeOptions(headers))
	results = append(results, checkXFrameOptions(headers))
	results = append(results, checkXXSSProtection(headers))
	results = append(results, checkReferrerPolicy(headers))
	results = append(results, checkPermissionsPolicy(headers))
	results = append(results, checkExpectCT(headers))
	results = append(results, checkServer(headers))
	results = append(results, checkCacheControl(headers))
	results = append(results, checkCrossOriginEmbedderPolicy(headers))
	results = append(results, checkCrossOriginOpenerPolicy(headers))
	results = append(results, checkCrossOriginResourcePolicy(headers))

	// Generate missing headers list
	var missingHeaders []HeaderCheckResult
	for _, h := range results {
		if h.Status == "missing" {
			missingHeaders = append(missingHeaders, h)
		}
	}

	// Generate improvements list
	var improvements []string
	for _, h := range results {
		if h.Status != "present" && h.Recommendation != "" {
			improvements = append(improvements, fmt.Sprintf("%s: %s", h.Name, h.Recommendation))
		}
	}

	result := &ScanResult{
		URL:            targetURL,
		Headers:        results,
		MissingHeaders: missingHeaders,
		Improvements:   improvements,
	}

	result.Score, result.Grade = calculateScore(result.Headers)
	result.SummaryTable = generateSummaryTable(results)
	result.DetailedReport = generateDetailedReport(results)

	return result, nil
}

func calculateScore(headers []HeaderCheckResult) (int, string) {
	totalPossible := 0
	score := 0

	weights := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}

	for _, header := range headers {
		totalPossible += weights[header.Severity]

		switch header.Status {
		case "present":
			score += weights[header.Severity]
		case "warning":
			score += weights[header.Severity] / 2
		case "error":
			score += 0
		}
	}

	// Convert to percentage
	percentage := (score * 100) / totalPossible

	// Assign grade
	var grade string
	switch {
	case percentage >= 90:
		grade = "A+"
	case percentage >= 80:
		grade = "A"
	case percentage >= 70:
		grade = "B"
	case percentage >= 60:
		grade = "C"
	case percentage >= 50:
		grade = "D"
	default:
		grade = "F"
	}

	return percentage, grade
}

func generateSummaryTable(headers []HeaderCheckResult) string {
	var buf strings.Builder
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "HEADER\tSTATUS\tSEVERITY\tVALUE")
	fmt.Fprintln(w, "------\t------\t--------\t-----")

	for _, h := range headers {
		status := h.Status
		switch status {
		case "present":
			status = "✅ " + status
		case "missing":
			status = "❌ " + status
		case "warning":
			status = "⚠️ " + status
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", h.Name, status, h.Severity, truncate(h.Value, 40))
	}

	w.Flush()
	return buf.String()
}

func generateDetailedReport(headers []HeaderCheckResult) string {
	var buf strings.Builder

	fmt.Fprintln(&buf, "DETAILED SECURITY HEADER ANALYSIS")
	fmt.Fprintln(&buf, "=================================")
	fmt.Fprintln(&buf)

	for _, h := range headers {
		fmt.Fprintf(&buf, "### %s\n", h.Name)
		fmt.Fprintf(&buf, "- Status: %s\n", h.Status)
		fmt.Fprintf(&buf, "- Severity: %s\n", h.Severity)
		if h.Value != "" {
			fmt.Fprintf(&buf, "- Current Value: %s\n", h.Value)
		}
		fmt.Fprintf(&buf, "- Description: %s\n", h.Description)
		if h.Recommendation != "" {
			fmt.Fprintf(&buf, "- Recommendation: %s\n", h.Recommendation)
		}
		fmt.Fprintln(&buf)
	}

	return buf.String()
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

// Enhanced header check functions with more detailed analysis

func checkCSP(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Content-Security-Policy",
		Severity:    "critical",
		Description: "Prevents a wide range of attacks including XSS, clickjacking, and other code injection attacks by restricting resources the browser is allowed to load.",
	}

	if val, ok := headers["content-security-policy"]; ok {
		result.Status = "present"
		result.Value = val
		result.Recommendation = "Regularly review your CSP to ensure it follows the principle of least privilege."

		// Detailed checks
		checks := map[string]string{
			"unsafe-inline": "Avoid 'unsafe-inline' as it negates much of CSP's XSS protection",
			"unsafe-eval":   "Avoid 'unsafe-eval' as it allows execution of dynamic code",
			"*":             "Avoid wildcard (*) sources as they're too permissive",
			"data:":         "Limit use of 'data:' URIs as they can be dangerous",
			"blob:":         "Limit use of 'blob:' URIs as they can be dangerous",
		}

		var warnings []string
		for pattern, message := range checks {
			if strings.Contains(val, pattern) {
				warnings = append(warnings, message)
			}
		}

		if len(warnings) > 0 {
			result.Status = "warning"
			result.Recommendation += " Issues detected: " + strings.Join(warnings, "; ")
		}
	} else {
		result.Status = "missing"
		result.Recommendation = `Implement a strong CSP. Example: "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';"`
	}

	return result
}

func checkHSTS(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Strict-Transport-Security",
		Severity:    "critical",
		Description: "Ensures all communication is sent over HTTPS and prevents SSL stripping attacks.",
	}

	if val, ok := headers["strict-transport-security"]; ok {
		result.Status = "present"
		result.Value = val

		maxAge := extractMaxAge(val)
		hasIncludeSubdomains := strings.Contains(val, "includeSubDomains")
		hasPreload := strings.Contains(val, "preload")

		switch {
		case maxAge == 0:
			result.Status = "error"
			result.Recommendation = "HSTS max-age must be specified"
		case maxAge < 31536000:
			result.Status = "warning"
			result.Recommendation = fmt.Sprintf("HSTS max-age should be at least 31536000 (1 year), currently %d", maxAge)
		default:
			result.Recommendation = "HSTS max-age is properly configured"
		}

		if !hasIncludeSubdomains {
			result.Status = "warning"
			result.Recommendation += ". Consider adding includeSubDomains"
		}

		if hasPreload {
			result.Recommendation += ". Note: preload directive commits your domain to HSTS preload lists"
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
	}

	return result
}

func checkXContentTypeOptions(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "X-Content-Type-Options",
		Severity:    "high",
		Description: "Prevents MIME type sniffing which can transform non-executable content into executable content.",
	}

	if val, ok := headers["x-content-type-options"]; ok {
		if strings.ToLower(val) == "nosniff" {
			result.Status = "present"
			result.Value = val
			result.Recommendation = "Properly configured with 'nosniff'."
		} else {
			result.Status = "error"
			result.Value = val
			result.Recommendation = "Must be set to 'nosniff'."
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Add header: X-Content-Type-Options: nosniff"
	}

	return result
}

func checkXFrameOptions(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "X-Frame-Options",
		Severity:    "high",
		Description: "Protects against clickjacking attacks by controlling whether your site can be framed by others.",
	}

	if val, ok := headers["x-frame-options"]; ok {
		val = strings.ToLower(val)
		if val == "deny" || val == "sameorigin" {
			result.Status = "present"
			result.Value = val
			result.Recommendation = "Properly configured."
		} else {
			result.Status = "error"
			result.Value = val
			result.Recommendation = "Must be set to either 'DENY' or 'SAMEORIGIN'."
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)"
	}

	return result
}

func checkXXSSProtection(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "X-XSS-Protection",
		Severity:    "medium",
		Description: "Enables XSS filtering protection in older browsers (modern browsers use CSP instead).",
	}

	if val, ok := headers["x-xss-protection"]; ok {
		if strings.Contains(val, "1; mode=block") {
			result.Status = "present"
			result.Value = val
			result.Recommendation = "Properly configured with '1; mode=block'."
		} else if strings.Contains(val, "0") {
			result.Status = "error"
			result.Value = val
			result.Recommendation = "XSS protection is explicitly disabled (0)."
		} else {
			result.Status = "warning"
			result.Value = val
			result.Recommendation = "Should be set to '1; mode=block'."
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Consider adding header: X-XSS-Protection: 1; mode=block (though CSP is preferred for XSS protection)"
	}

	return result
}

func checkReferrerPolicy(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Referrer-Policy",
		Severity:    "medium",
		Description: "Controls how much referrer information is included with requests to protect user privacy.",
	}

	validPolicies := map[string]bool{
		"no-referrer":                     true,
		"no-referrer-when-downgrade":      true,
		"same-origin":                     true,
		"origin":                          true,
		"strict-origin":                   true,
		"origin-when-cross-origin":        true,
		"strict-origin-when-cross-origin": true,
		"unsafe-url":                      true,
	}

	if val, ok := headers["referrer-policy"]; ok {
		val = strings.ToLower(val)
		if validPolicies[val] {
			result.Status = "present"
			result.Value = val

			switch val {
			case "strict-origin-when-cross-origin":
				result.Recommendation = "Recommended policy that provides good balance of privacy and functionality."
			case "strict-origin":
				result.Recommendation = "Good privacy-focused policy."
			case "no-referrer":
				result.Recommendation = "Most restrictive policy that sends no referrer information."
			case "unsafe-url":
				result.Status = "warning"
				result.Recommendation = "'unsafe-url' leaks full URLs in referrer headers."
			default:
				result.Recommendation = "Consider using 'strict-origin-when-cross-origin' for better privacy."
			}
		} else {
			result.Status = "error"
			result.Value = val
			result.Recommendation = "Invalid policy. Use one of: no-referrer, no-referrer-when-downgrade, same-origin, origin, strict-origin, origin-when-cross-origin, strict-origin-when-cross-origin"
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Add header: Referrer-Policy: strict-origin-when-cross-origin (recommended)"
	}

	return result
}

func checkPermissionsPolicy(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Permissions-Policy",
		Severity:    "high",
		Description: "Controls which browser features and APIs can be used in the browser (replaces Feature-Policy).",
	}

	if val, ok := headers["permissions-policy"]; ok {
		result.Status = "present"
		result.Value = val
		result.Recommendation = "Review your policy to ensure only necessary features are enabled."

		// Check for dangerous features
		dangerousFeatures := []string{
			"geolocation=*",
			"camera=*",
			"microphone=*",
			"payment=*",
		}

		var warnings []string
		for _, feature := range dangerousFeatures {
			if strings.Contains(val, feature) {
				warnings = append(warnings, fmt.Sprintf("Dangerous feature %s is allowed for all origins", feature))
			}
		}

		if len(warnings) > 0 {
			result.Status = "warning"
			result.Recommendation += " Issues: " + strings.Join(warnings, "; ")
		}
	} else if _, ok := headers["feature-policy"]; ok {
		result.Status = "warning"
		result.Name = "Feature-Policy"
		result.Value = headers["feature-policy"]
		result.Recommendation = "Feature-Policy is deprecated. Migrate to Permissions-Policy."
	} else {
		result.Status = "missing"
		result.Recommendation = `Implement Permissions-Policy. Example: "geolocation=(), microphone=()" to disable sensitive features`
	}

	return result
}

func checkExpectCT(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Expect-CT",
		Severity:    "low",
		Description: "Used to enforce Certificate Transparency requirements (deprecated in favor of built-in browser mechanisms).",
	}

	if val, ok := headers["expect-ct"]; ok {
		result.Status = "present"
		result.Value = val
		result.Recommendation = "Expect-CT is deprecated. Modern browsers handle Certificate Transparency enforcement automatically."
	} else {
		result.Status = "missing"
		result.Recommendation = "Expect-CT is not needed for modern browsers as they enforce Certificate Transparency by default."
	}

	return result
}

func checkServer(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Server",
		Severity:    "info",
		Description: "Reveals information about the server software which could help attackers identify vulnerabilities.",
	}

	if val, ok := headers["server"]; ok {
		result.Status = "present"
		result.Value = val
		result.Recommendation = "Consider removing or obfuscating the Server header to avoid revealing server information."
	} else {
		result.Status = "present"
		result.Recommendation = "Good practice - Server header is not exposed."
	}

	return result
}

func checkCacheControl(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Cache-Control",
		Severity:    "medium",
		Description: "Controls caching behavior which can impact both performance and security.",
	}

	if val, ok := headers["cache-control"]; ok {
		result.Status = "present"
		result.Value = val
		result.Recommendation = "Ensure sensitive content has appropriate cache directives."

		// Check for no-store on sensitive pages
		if !strings.Contains(val, "no-store") {
			result.Status = "warning"
			result.Recommendation += " Consider 'no-store' for sensitive pages to prevent caching."
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Implement Cache-Control header appropriate for your content."
	}

	return result
}

func checkCrossOriginEmbedderPolicy(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Cross-Origin-Embedder-Policy",
		Severity:    "high",
		Description: "Prevents a document from loading any cross-origin resources that don't explicitly grant permission.",
	}

	validPolicies := map[string]bool{
		"unsafe-none":  true,
		"require-corp": true,
	}

	if val, ok := headers["cross-origin-embedder-policy"]; ok {
		val = strings.ToLower(val)
		if validPolicies[val] {
			result.Status = "present"
			result.Value = val

			if val == "require-corp" {
				result.Recommendation = "Strong security policy that requires CORS for embedded resources."
			} else {
				result.Status = "warning"
				result.Recommendation = "Consider 'require-corp' for better isolation."
			}
		} else {
			result.Status = "error"
			result.Value = val
			result.Recommendation = "Invalid policy. Use 'require-corp' or 'unsafe-none'."
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Consider adding Cross-Origin-Embedder-Policy: require-corp for better isolation."
	}

	return result
}

func checkCrossOriginOpenerPolicy(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Cross-Origin-Opener-Policy",
		Severity:    "high",
		Description: "Prevents other domains from opening your site in a way that can access your window object.",
	}

	validPolicies := map[string]bool{
		"unsafe-none":              true,
		"same-origin":              true,
		"same-origin-allow-popups": true,
	}

	if val, ok := headers["cross-origin-opener-policy"]; ok {
		val = strings.ToLower(val)
		if validPolicies[val] {
			result.Status = "present"
			result.Value = val

			if val == "same-origin" {
				result.Recommendation = "Strong security policy that isolates your window from cross-origin windows."
			} else {
				result.Status = "warning"
				result.Recommendation = "Consider 'same-origin' for better isolation."
			}
		} else {
			result.Status = "error"
			result.Value = val
			result.Recommendation = "Invalid policy. Use 'same-origin', 'same-origin-allow-popups', or 'unsafe-none'."
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Consider adding Cross-Origin-Opener-Policy: same-origin for better isolation."
	}

	return result
}

func checkCrossOriginResourcePolicy(headers map[string]string) HeaderCheckResult {
	result := HeaderCheckResult{
		Name:        "Cross-Origin-Resource-Policy",
		Severity:    "medium",
		Description: "Prevents other domains from loading your resources (e.g., images, scripts) cross-origin.",
	}

	validPolicies := map[string]bool{
		"same-site":    true,
		"same-origin":  true,
		"cross-origin": true,
	}

	if val, ok := headers["cross-origin-resource-policy"]; ok {
		val = strings.ToLower(val)
		if validPolicies[val] {
			result.Status = "present"
			result.Value = val

			if val == "same-origin" {
				result.Recommendation = "Strong security policy that restricts resource loading to same-origin only."
			} else if val == "same-site" {
				result.Recommendation = "Good security policy that restricts resource loading to same-site."
			}
		} else {
			result.Status = "error"
			result.Value = val
			result.Recommendation = "Invalid policy. Use 'same-origin', 'same-site', or 'cross-origin'."
		}
	} else {
		result.Status = "missing"
		result.Recommendation = "Consider adding Cross-Origin-Resource-Policy: same-origin for better resource isolation."
	}

	return result
}

func extractMaxAge(hsts string) int {
	parts := strings.Split(hsts, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			var maxAge int
			_, err := fmt.Sscanf(part, "max-age=%d", &maxAge)
			if err == nil {
				return maxAge
			}
		}
	}
	return 0
}
