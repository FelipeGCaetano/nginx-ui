package config

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/0xJacky/Nginx-UI/internal/config"
	"github.com/0xJacky/Nginx-UI/internal/helper"
	"github.com/0xJacky/Nginx-UI/internal/nginx"
	"github.com/0xJacky/Nginx-UI/query"
	"github.com/mark3labs/mcp-go/mcp"
)

const nginxConfigDeleteToolName = "nginx_config_delete"

var nginxConfigDeleteTool = mcp.NewTool(
	nginxConfigDeleteToolName,
	mcp.WithDescription("Delete an Nginx configuration file"),
	mcp.WithString("name", mcp.Description("The name of the configuration file to delete")),
	mcp.WithString("base_dir", mcp.Description("The base directory for the configuration")),
)

func handleNginxConfigDelete(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return nil, errors.New("name is required")
	}
	baseDir, ok := args["base_dir"].(string)
	if !ok || baseDir == "" {
		return nil, errors.New("base_dir is required")
	}

	// Resolve the full path based on the base directory
	dir := nginx.GetConfPath(baseDir)
	path := filepath.Join(dir, name)

	// Security check: ensure path is valid and within allowable directories
	if !helper.IsUnderDirectory(path, nginx.GetConfPath()) {
		return nil, config.ErrPathIsNotUnderTheNginxConfDir
	}

	// Check if file exists before attempting deletion
	if !helper.FileExists(path) {
		return nil, os.ErrNotExist
	}

	// Delete the file from disk
	err := os.Remove(path)
	if err != nil {
		return nil, err
	}

	// Reload Nginx to apply changes
	res := nginx.Control(nginx.Reload)
	if res.IsError() {
		return nil, res.GetError()
	}

	// Remove the record from the database
	q := query.Config
	_, err = q.Where(q.Filepath.Eq(path)).Delete()
	if err != nil {
		return nil, err
	}

	// Construct result
	result := map[string]interface{}{
		"name":      name,
		"file_path": path,
		"status":    "deleted",
	}

	jsonResult, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(jsonResult)), nil
}