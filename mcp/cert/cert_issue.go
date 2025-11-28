package cert

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xJacky/Nginx-UI/internal/cert"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/mark3labs/mcp-go/mcp"
)

const certificateIssueToolName = "nginx_cert_issue"

var certificateIssueTool = mcp.NewTool(
	certificateIssueToolName,
	mcp.WithDescription("Issue an SSL certificate using Let's Encrypt (HTTP-01 or DNS-01) and return the file paths"),
	mcp.WithArray("domains", mcp.Description("List of domains for the certificate (e.g. ['example.com'])")),
	mcp.WithString("challenge_method", mcp.Description("Challenge method: 'http01' (default) or 'dns01'")),
	mcp.WithNumber("dns_credential_id", mcp.Description("ID of DNS credential (required if using dns01)")),
)

func handleCertificateIssue(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	// 1. Parse Domains
	domainsInterface, ok := args["domains"].([]interface{})
	if !ok || len(domainsInterface) == 0 {
		return nil, fmt.Errorf("domains list is required and cannot be empty")
	}
	domains := make([]string, len(domainsInterface))
	for i, v := range domainsInterface {
		domains[i] = fmt.Sprint(v)
	}

	// 2. Parse Method
	method := "http01"
	if m, ok := args["challenge_method"].(string); ok && m != "" {
		method = m
	}

	// 3. Parse DNS Credential (optional)
	var dnsCredID uint64
	if id, ok := args["dns_credential_id"].(float64); ok {
		dnsCredID = uint64(id)
	}

	if method == "dns01" && dnsCredID == 0 {
		return nil, fmt.Errorf("dns_credential_id is required for dns01 challenge")
	}

	// 4. Prepare Internal Payload
	// We leave KeyType as default (usually EC256 or RSA)
	payload := &cert.ConfigPayload{
		ServerName:      domains,
		ChallengeMethod: method,
		DNSCredentialID: dnsCredID,
	}

	// 5. Ensure Database Record Exists
	// The internal logic requires a valid CertID to update the database status.
	certModel, err := model.FirstOrCreateCert(domains[0], payload.GetKeyType())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate record in DB: %w", err)
	}
	payload.CertID = certModel.ID

	// 6. Setup Headless Logger
	// The internal IssueCert expects a logger. We use one that doesn't panic without a WebSocket.
	logger := cert.NewLogger()
	logger.SetCertModel(&certModel)
	defer logger.Close()

	// 7. Execute Issuance
	// This blocks until Let's Encrypt verifies the challenge and issues the cert.
	err = cert.IssueCert(payload, logger)
	
	logOutput := logger.ToString()

	if err != nil {
		return nil, fmt.Errorf("Certificate issuance failed: %v\n\nLogs:\n%s", err, logOutput)
	}

	// 8. Return Paths
	// You can now use these paths in your config template.
	result := map[string]string{
		"status":           "success",
		"message":          "Certificate issued successfully",
		"certificate_path": payload.GetCertificatePath(),
		"private_key_path": payload.GetCertificateKeyPath(),
		"logs":             logOutput, // Useful for debugging
	}
	jsonResult, _ := json.Marshal(result)

	return mcp.NewToolResultText(string(jsonResult)), nil
}