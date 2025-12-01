package middleware

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/0xJacky/Nginx-UI/internal/user"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/settings"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/uozi-tech/cosy/logger"
)

var (
	verifyKey *rsa.PublicKey
	once      sync.Once
)

func loadKeySafe() {
	once.Do(func() {
		logger.Info("🔒 MCP: Inicializando sistema de segurança...")

		// 1. Tenta ENV
		keyPath := os.Getenv("MCP_PUBLIC_KEY_PATH")
		
		// 2. Fallback inteligente
		if keyPath == "" {
			cwd, _ := os.Getwd()
			// Tenta primeiro no local padrão do Linux
			if _, err := os.Stat("/home/nmultifibra/nginx-ui/certs/mcp_public_key.pem"); err == nil {
				keyPath = "/home/nmultifibra/nginx-ui/certs/mcp_public_key.pem"
			} else {
				// Se não, tenta relativo (Dev)
				keyPath = filepath.Join(cwd, "mcp_public_key.pem")
			}
		}

		logger.Infof("🔍 MCP: Lendo chave pública de: %s", keyPath)

		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			logger.Errorf("❌ MCP: Falha ao ler arquivo: %v. Autenticação via Token DESATIVADA.", err)
			return
		}

		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(keyData)
		if err != nil {
			logger.Errorf("❌ MCP: Chave inválida: %v", err)
			verifyKey = nil
		} else {
			logger.Info("✅ MCP: Autenticação Segura ATIVADA com sucesso!")
		}
	})
}

// getToken from header, cookie or query
func getToken(c *gin.Context) (token string) {
	if token = c.GetHeader("Authorization"); token != "" {
		return
	}

	if token = c.Query("token"); token != "" {
		if len(token) > 16 {
			// Long token (base64 encoded JWT)
			tokenBytes, _ := base64.StdEncoding.DecodeString(token)
			return string(tokenBytes)
		}
		// Short token (16 characters)
		return token
	}

	if token, _ = c.Cookie("token"); token != "" {
		return token
	}

	return ""
}

// getXNodeID from header or query
func getXNodeID(c *gin.Context) (xNodeID string) {
	if xNodeID = c.GetHeader("X-Node-ID"); xNodeID != "" {
		return xNodeID
	}

	return c.Query("x_node_id")
}

// getNodeSecret from header or query
func getNodeSecret(c *gin.Context) (secret string) {
	if secret = c.GetHeader("X-Node-Secret"); secret != "" {
		return secret
	}

	return c.Query("node_secret")
}

// AuthRequired is a middleware that checks if the user is authenticated
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		loadKeySafe()

		abortWithAuthFailure := func() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "Authorization failed",
			})
		}

		xNodeID := getXNodeID(c)
		if xNodeID != "" {
			c.Set("ProxyNodeID", xNodeID)
		}

		// Check node secret authentication
		// if nodeSecret := getNodeSecret(c); nodeSecret != "" && nodeSecret == settings.NodeSettings.Secret {
		// 	initUser := user.GetInitUser(c)
		// 	c.Set("Secret", nodeSecret)
		// 	c.Set("user", initUser)
		// 	c.Next()
		// 	return
		// }

		token := getToken(c)
		if token == "" {
			abortWithAuthFailure()
			return
		}

		if verifyKey != nil && len(token) > 16 {
			jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return verifyKey, nil
			})

			if err == nil && jwtToken.Valid {
				systemUser := &model.User{
					Name: "MCP System",
				}
				c.Set("user", systemUser)
				c.Next()
				return
			}
		}

		var (
			u  *model.User
			ok bool
		)

		if len(token) <= 16 {
			// Short token (16 characters)
			u, ok = user.GetTokenUserByShortToken(token)
			if !ok {
				abortWithAuthFailure()
				return
			}
		} else {
			// Long JWT token
			u, ok = user.GetTokenUser(token)
			if !ok {
				abortWithAuthFailure()
				return
			}
		}

		c.Set("user", u)
		c.Next()
	}
}

type ServerFileSystemType struct {
	http.FileSystem
}

func (f ServerFileSystemType) Exists(prefix string, _path string) bool {
	file, err := f.Open(path.Join(prefix, _path))
	if file != nil {
		defer func(file http.File) {
			err = file.Close()
			if err != nil {
				logger.Error("file not found", err)
			}
		}(file)
	}
	return err == nil
}

// CacheJs is a middleware that send header to client to cache js file
func CacheJs() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.Contains(c.Request.URL.String(), "js") {
			c.Header("Cache-Control", "max-age: 1296000")
			if c.Request.Header.Get("If-Modified-Since") == settings.LastModified {
				c.AbortWithStatus(http.StatusNotModified)
			}
			c.Header("Last-Modified", settings.LastModified)
		}
	}
}
