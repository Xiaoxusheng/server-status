package main

// ==================== 高风险操作审计日志 ====================

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

const auditLogFile = "/opt/server-status/audit.log"

// auditAction 记录高风险操作到审计日志（服务变更、防火墙修改等）
func auditAction(r *http.Request, action, detail string) {
	username := ""
	clientIP := ""
	if r != nil {
		if s, ok := getSessionFromRequest(r); ok {
			username = s.Username
		}
		clientIP = getClientIP(r)
	}
	entry := map[string]interface{}{
		"time":   time.Now().Format(time.RFC3339),
		"user":   username,
		"ip":     clientIP,
		"action": action,
		"detail": detail,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if err := os.MkdirAll(dirOf(auditLogFile), 0755); err != nil {
		log.Printf("创建审计日志目录失败: %v", err)
		return
	}
	f, err := os.OpenFile(auditLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("写入审计日志失败: %v", err)
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
	log.Printf("AUDIT [%s] %s: %s", username, action, detail)
}
