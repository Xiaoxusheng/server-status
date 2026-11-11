package main

// health.go —— 对外探活端点 GET /healthz
//
// 给 Uptime Kuma / 云监控这类探针用：探针带不了登录会话，所以这个端点不挂鉴权，
// 但也正因如此，它只暴露"能不能用"的布尔值与版本号，不返回任何路径、配置、用户名。
// 只要有硬性检查失败就返回 503，监控直接按状态码判定即可，不用解析 JSON。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// healthzItem 单项检查结果
type healthzItem struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// healthReport /healthz 的响应体
type healthReport struct {
	Status    string                 `json:"status"` // ok / degraded
	Version   string                 `json:"version"`
	Commit    string                 `json:"commit"`
	BuildDate string                 `json:"build_date"`
	UptimeSec int64                  `json:"uptime_seconds"`
	Uptime    string                 `json:"uptime"`
	CheckedAt string                 `json:"checked_at"`
	Checks    map[string]healthzItem `json:"checks"`
}

// docker 探活要起子进程，比其它检查慢得多；缓存 30 秒，
// 避免探针高频打进来时被 docker CLI 拖住（探针通常 30~60s 一次，够用）。
var (
	healthDockerMu    sync.Mutex
	healthDockerAt    time.Time
	healthDockerCheck healthzItem
)

const healthDockerTTL = 30 * time.Second

// checkDockerHealth 探测 docker daemon 是否可达；没装 docker 视为"跳过"而不是故障
func checkDockerHealth() healthzItem {
	healthDockerMu.Lock()
	defer healthDockerMu.Unlock()

	if !healthDockerAt.IsZero() && time.Since(healthDockerAt) < healthDockerTTL {
		return healthDockerCheck
	}

	res := healthzItem{OK: true}
	if _, err := exec.LookPath("docker"); err != nil {
		res.Detail = "未安装 docker，跳过"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").Output()
		switch {
		case err != nil:
			res = healthzItem{OK: false, Detail: "docker daemon 不可达"}
		default:
			if v := strings.TrimSpace(string(out)); v != "" {
				res.Detail = "Engine v" + v
			}
		}
	}

	healthDockerAt = time.Now()
	healthDockerCheck = res
	return res
}

// processStart 仅在持久化启动时间缺失时兜底（正常路径用 serverStartTime）
var processStart = time.Now()

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	// 整体预算 2 秒：探针超时一般 3~5 秒，这里不能拖住它
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := make(map[string]healthzItem, 4)
	healthy := true

	// 1. SQLite：能查就说明连接和库文件都正常（写检查没意义，读失败已经说明问题）
	if err := opsStore.Ping(ctx); err != nil {
		checks["database"] = healthzItem{OK: false, Detail: "sqlite 不可用"}
		healthy = false
	} else {
		checks["database"] = healthzItem{OK: true}
	}

	// 2. 模板目录：首页模板读不到，等于整个面板白屏
	if _, err := os.Stat(filepath.Join(indexPath, "index.html")); err != nil {
		checks["templates"] = healthzItem{OK: false, Detail: "模板目录不可读"}
		healthy = false
	} else {
		checks["templates"] = healthzItem{OK: true}
	}

	// 3. 媒体目录：只报告，不判故障（有人可能压根没配媒体库）
	if entries, err := os.ReadDir(mediaDir); err != nil {
		checks["media"] = healthzItem{OK: false, Detail: "媒体目录不可读"}
	} else {
		checks["media"] = healthzItem{OK: true, Detail: fmt.Sprintf("%d 项", len(entries))}
	}

	// 4. Docker daemon
	if dc := checkDockerHealth(); !dc.OK {
		checks["docker"] = dc
		healthy = false
	} else {
		checks["docker"] = dc
	}

	start := serverStartTime
	if start.IsZero() {
		start = processStart
	}
	up := time.Since(start)

	rep := healthReport{
		Status:    "ok",
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		UptimeSec: int64(up / time.Second),
		Uptime:    formatUptimeCN(up),
		CheckedAt: time.Now().Format(time.RFC3339),
		Checks:    checks,
	}
	if !healthy {
		rep.Status = "degraded"
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(rep)
}
