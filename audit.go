package main

// ==================== 高风险操作审计日志 ====================

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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

// auditQueryHandler GET /api/audit?user=xxx&limit=50
// 读取审计日志，支持按用户过滤，返回最近 N 条（倒序）
func auditQueryHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	data, err := os.ReadFile(auditLogFile)
	if err != nil {
		writeJSON(w, http.StatusOK, "获取审计记录成功", []map[string]interface{}{})
		return
	}
	out := make([]map[string]interface{}, 0, 64)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if user != "" {
			if u, _ := m["user"].(string); u != user {
				continue
			}
		}
		out = append(out, m)
	}
	// 文件按时间追加，最新在末尾 → 反转为倒序
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, http.StatusOK, "获取审计记录成功", out)
}
