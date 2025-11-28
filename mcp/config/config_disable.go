package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xJacky/Nginx-UI/internal/config"
	"github.com/0xJacky/Nginx-UI/internal/helper"
	"github.com/0xJacky/Nginx-UI/internal/nginx"
	"github.com/mark3labs/mcp-go/mcp"
)

const nginxConfigDisableToolName = "nginx_config_disable"

var nginxConfigDisableTool = mcp.NewTool(
	nginxConfigDisableToolName,
	mcp.WithDescription("Disable an Nginx configuration (removes symlink from sites-enabled)"),
	mcp.WithString("name", mcp.Description("The name of the configuration file to disable")),
)

func handleNginxConfigDisable(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	name, ok := args["name"].(string)

	if !ok || name == "" {
		return nil, fmt.Errorf("argument 'name' is required")
	}

	// Resolve path to sites-enabled
	sitesEnabledDir := nginx.GetConfPath("sites-enabled")
	
	// Calculate the full path of the symlink to be removed
	// We use GetConfSymlinkPath to handle potential OS-specific naming (like usually identical on Linux)
	targetPath := nginx.GetConfSymlinkPath(filepath.Join(sitesEnabledDir, name))

	// Security check: ensure path is valid and within allowable directories
	if !helper.IsUnderDirectory(targetPath, sitesEnabledDir) {
		return nil, config.ErrPathIsNotUnderTheNginxConfDir
	}

	// Check if the symlink exists before trying to remove it
	if !helper.FileExists(targetPath) {
		return nil, fmt.Errorf("configuration is not enabled (symlink not found at %s)", targetPath)
	}

	// Remove the symlink
	if err := os.Remove(targetPath); err != nil {
		return nil, fmt.Errorf("failed to disable configuration (remove symlink): %w", err)
	}

	// Reload Nginx to apply changes
	res := nginx.Control(nginx.Reload)
	if res.IsError() {
		return nil, fmt.Errorf("nginx reload failed: %v", res.GetError())
	}

	// Construct Success Response
	result := map[string]string{
		"status":  "success",
		"message": "Site disabled and Nginx reloaded successfully",
		"path":    targetPath,
	}
	jsonResult, _ := json.Marshal(result)

	return mcp.NewToolResultText(string(jsonResult)), nil
}