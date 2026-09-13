package main

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// amapRegeoURL 高德反向地理编码端点（包级变量便于测试替换）
var amapRegeoURL = "https://restapi.amap.com/v3/geocode/regeo"

// privateRegeoHandler GET /api/private/geo/regeo?location=lng,lat
// 服务端代理高德 regeo：key 只保存在服务器配置里，不再经 session 接口下发浏览器。
// 前端传来的已是 GCJ-02 坐标（wgs2gcj 仍在浏览器侧完成），响应原样透传高德 JSON。
func privateRegeoHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		writeJSONError(w, http.StatusForbidden, "私人空间不可用")
		return
	}
	key := privateStore.config.Geo.AmapKey
	if key == "" {
		// 未配置 key：按前端既有约定返回 status=0，浏览器自动回退 nominatim
		writeRawJSON(w, http.StatusOK, `{"status":"0","info":"NO_KEY","infocode":"10044"}`)
		return
	}
	loc := strings.TrimSpace(r.URL.Query().Get("location"))
	if len(loc) > 32 {
		writeJSONError(w, http.StatusBadRequest, "location 参数过长")
		return
	}
	parts := strings.Split(loc, ",")
	if len(parts) != 2 {
		writeJSONError(w, http.StatusBadRequest, "location 参数格式应为 lng,lat")
		return
	}
	for _, p := range parts {
		if _, err := strconv.ParseFloat(strings.TrimSpace(p), 64); err != nil {
			writeJSONError(w, http.StatusBadRequest, "location 参数不是有效坐标")
			return
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(amapRegeoURL + "?key=" + url.QueryEscape(key) + "&location=" + url.QueryEscape(loc))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "地理编码服务请求失败")
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "地理编码服务响应读取失败")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// writeRawJSON 原样写出 JSON 字符串（代理透传用，不包 {code,message,data} 外壳）
func writeRawJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write([]byte(body))
}
