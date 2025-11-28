package cert

import (
	"github.com/0xJacky/Nginx-UI/internal/mcp"
)

func Init() {
	mcp.AddTool(certificateIssueTool, handleCertificateIssue)
}