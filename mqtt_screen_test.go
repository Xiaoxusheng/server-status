package main

// MQTT 设备定位大屏的公开接口测试。
// 这个接口无需登录，任何未授权访客都能拿到响应，所以本测试的核心不是"数据对不对"，
// 而是"有没有多给"——设备内网 IP、WiFi 名、固件版本、运行时长等一律不得出现。

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 取自生产环境的真实上报样例，含全部敏感字段，用于验证裁剪是否彻底
const mqttTestPayload = `{"count":1415,"uptime_ms":43319819,"ip":"192.168.1.54","wifi":"hm",` +
	`"version":"1.5.2","rssi":-53,"reboot_count":90,"free_heap":167744,"temperature":22,` +
	`"humidity":39,"gps_fix":true,"gps_stale":false,"satellites":8,"sats_in_view":25,` +
	`"sats_gps":12,"lat":32.015804,"lon":118.789593,"altitude":20.9,"speed_kmh":0.0,` +
	`"course":83.1,"fix_mode":3,"hdop":3.1,"pdop":5.0,"vdop":0.0,` +
	`"gps_time":"234724.000","gps_date":"160926"}`

// newMqttUpstreamMock 模拟上游 mqtt-dashboard 的三个接口。
// lastSeen 由调用方指定，用于分别覆盖"在线"与"离线"两种判定。
func newMqttUpstreamMock(t *testing.T, payload string, lastSeen int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/messages", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]string{
			{"time": "07:37:24", "client": "esp32-d8d514", "topic": "esp32/data", "payload": payload},
			{"time": "07:47:25", "client": "esp32-d8d514", "topic": "esp32/data", "payload": payload},
		})
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"range": "1h",
			"rssi": []map[string]interface{}{
				{"t": lastSeen, "v": -53},
			},
			"uptime": []map[string]interface{}{
				{"t": lastSeen, "v": 43319819},
			},
		})
	})
	mux.HandleFunc("/api/track", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"points": []map[string]interface{}{
				{"t": lastSeen - 600, "lat": 32.015721, "lon": 118.789761},
				{"t": lastSeen, "lat": 32.015804, "lon": 118.789593},
			},
		})
	})
	return httptest.NewServer(mux)
}

// 正常路径：字段正确映射，且时间戳/轨迹可用
func TestFetchMqttScreenDataMapsWhitelistedFields(t *testing.T) {
	lastSeen := time.Now().Unix()
	ts := newMqttUpstreamMock(t, mqttTestPayload, lastSeen)
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}

	if data.Device != "esp32-d8d514" {
		t.Errorf("设备名应为 esp32-d8d514，实际 %q", data.Device)
	}
	if !data.Fix {
		t.Error("gps_fix=true 应映射为 Fix=true")
	}
	if data.Lat != 32.015804 || data.Lon != 118.789593 {
		t.Errorf("坐标映射错误: %v, %v", data.Lat, data.Lon)
	}
	if data.Temperature != 22 || data.Humidity != 39 {
		t.Errorf("温湿度映射错误: %v, %v", data.Temperature, data.Humidity)
	}
	if data.Rssi != -53 || data.Satellites != 8 || data.SatsInView != 25 {
		t.Errorf("信号/卫星数映射错误: rssi=%v sats=%v in_view=%v", data.Rssi, data.Satellites, data.SatsInView)
	}
	if data.LastSeen != lastSeen {
		t.Errorf("最后上报时间应取自 /api/health，实际 %d", data.LastSeen)
	}
	if len(data.Track) != 2 {
		t.Errorf("轨迹点应为 2 个，实际 %d", len(data.Track))
	}
	if !data.Online {
		t.Error("刚上报过的设备应判定为在线")
	}
}

// 超过离线阈值未上报的设备必须判为离线（大屏靠这个显示"设备离线"）
func TestFetchMqttScreenDataMarksOfflineWhenStale(t *testing.T) {
	lastSeen := time.Now().Add(-mqttScreenOfflineAfter() - time.Minute).Unix()
	ts := newMqttUpstreamMock(t, mqttTestPayload, lastSeen)
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.Online {
		t.Error("超过离线阈值的历史数据不应判定为在线")
	}
}

// 核心安全用例：序列化后的响应里不得出现任何设备内部信息或凭据
func TestFetchMqttScreenDataDropsSensitiveFields(t *testing.T) {
	ts := newMqttUpstreamMock(t, mqttTestPayload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	body := string(raw)

	// 每一条都对应 payload 里的真实敏感值或字段名
	for _, leaked := range []string{
		"192.168.1.54", // 设备内网 IP
		"hm",           // WiFi 名
		"1.5.2",        // 固件版本
		"43319819",     // 运行时长
		"167744",       // 空闲堆
		"234724",       // GPS 时间
		"160926",       // GPS 日期
		"uptime_ms", "reboot_count", "free_heap", "fix_mode",
		"pdop", "vdop", "gps_stale", "sats_gps", "count",
	} {
		if strings.Contains(body, leaked) {
			t.Errorf("公开响应泄露了 %q: %s", leaked, body)
		}
	}
}

// 未定位时不应把 (0,0) 当成有效坐标对外发布
func TestFetchMqttScreenDataNoFixClearsCoordinates(t *testing.T) {
	payload := `{"temperature":20,"humidity":40,"gps_fix":false,"lat":0,"lon":0,"satellites":0}`
	ts := newMqttUpstreamMock(t, payload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.Fix {
		t.Error("gps_fix=false 应映射为 Fix=false")
	}
	if data.Lat != 0 || data.Lon != 0 {
		t.Errorf("未定位时不应带出坐标，实际 %v, %v", data.Lat, data.Lon)
	}
	if data.Temperature != 20 || data.Humidity != 40 {
		t.Error("未定位不应影响环境数据映射")
	}
}

// 固件 1.5.3 起设备端会做静止平均滤波，并上报 stationary / acc_m / avg_n。
// 这三个字段要透出去，页面才能显示"静止 · 精度 ±1.6 m"。
const mqttTestPayloadV153 = `{"count":53,"uptime_ms":15640179,"ip":"192.168.1.54","wifi":"hm",` +
	`"version":"1.5.3","rssi":-53,"reboot_count":92,"free_heap":168028,"temperature":23,` +
	`"humidity":57,"gps_fix":true,"gps_stale":false,"stationary":true,"acc_m":1.6,"avg_n":62,` +
	`"satellites":7,"sats_in_view":14,"lat":32.016328,"lon":118.789964,"altitude":-2.0,` +
	`"speed_kmh":0.0,"course":203.0,"fix_mode":3,"hdop":1.3,"pdop":2.1,"vdop":0.0,` +
	`"gps_time":"082207.000","gps_date":"170926"}`

// 设备端滤波结果必须原样透出去（页面的"定位精度/定位状态"全靠它）
func TestFetchMqttScreenDataMapsStationaryFields(t *testing.T) {
	ts := newMqttUpstreamMock(t, mqttTestPayloadV153, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if !data.Stationary {
		t.Error("stationary=true 应映射为 Stationary=true")
	}
	if math.Abs(data.AccM-1.6) > 1e-9 {
		t.Errorf("acc_m 应映射为 1.6，实际 %v", data.AccM)
	}
	if data.AvgN != 62 {
		t.Errorf("avg_n 应映射为 62，实际 %d", data.AvgN)
	}
}

// 老固件（1.5.2 及以前）不报这几个字段，必须保持零值：
// 页面据此显示"—"，绝不能把"没上报"当成"移动中"
func TestFetchMqttScreenDataStationaryFieldsAbsentOnOldFirmware(t *testing.T) {
	ts := newMqttUpstreamMock(t, mqttTestPayload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.Stationary || data.AccM != 0 || data.AvgN != 0 {
		t.Errorf("老固件上报不应带出滤波字段: stationary=%v acc=%v n=%v",
			data.Stationary, data.AccM, data.AvgN)
	}
}

// 未定位时定位质量信息一并清零，避免出现"没有坐标却标着静止、精度 1.6 m"
func TestFetchMqttScreenDataNoFixClearsStationaryFields(t *testing.T) {
	payload := `{"temperature":20,"humidity":40,"gps_fix":false,"lat":0,"lon":0,` +
		`"stationary":true,"acc_m":1.6,"avg_n":62}`
	ts := newMqttUpstreamMock(t, payload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.Stationary || data.AccM != 0 || data.AvgN != 0 {
		t.Errorf("未定位时滤波字段应清零: stationary=%v acc=%v n=%v",
			data.Stationary, data.AccM, data.AvgN)
	}
}

// 上游整体不可达时必须报错，由 handler 转成通用提示（不能把上游地址透出去）
func TestFetchMqttScreenDataUpstreamDown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	if _, err := fetchMqttScreenData(); err == nil {
		t.Error("上游异常时应返回错误")
	}
}

// 上游 messages 全是无法解析的记录时应报错，而不是返回空壳数据
func TestFetchMqttScreenDataNoParsableMessage(t *testing.T) {
	ts := newMqttUpstreamMock(t, "not-a-json-payload", time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	if _, err := fetchMqttScreenData(); err == nil {
		t.Error("没有可解析的设备上报时应返回错误")
	}
}

// handler 层：上游不可达时返回 502 且正文不含上游地址
func TestPublicMqttScreenHandlerUpstreamDown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	rec := httptest.NewRecorder()
	publicMqttScreenHandler(rec, httptest.NewRequest(http.MethodGet, "/api/public/mqtt/screen", nil))

	if rec.Code != http.StatusBadGateway {
		t.Errorf("上游不可达应返回 502，实际 %d", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, ts.URL) || strings.Contains(body, "boom") {
		t.Errorf("错误响应不应透出上游细节: %s", body)
	}
}

// handler 层：正常路径返回统一外壳且带 no-store
func TestPublicMqttScreenHandlerOK(t *testing.T) {
	ts := newMqttUpstreamMock(t, mqttTestPayload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	// 清掉可能存在的缓存，保证本次真的走上游
	mqttScreenCacheMu.Lock()
	mqttScreenCacheData, mqttScreenCacheAt = nil, time.Time{}
	mqttScreenCacheMu.Unlock()

	rec := httptest.NewRecorder()
	publicMqttScreenHandler(rec, httptest.NewRequest(http.MethodGet, "/api/public/mqtt/screen", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("正常路径应 200，实际 %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("私有数据应禁止缓存，实际 Cache-Control=%q", cc)
	}
	var resp struct {
		Code int             `json:"code"`
		Data *mqttScreenData `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if resp.Code != 200 || resp.Data == nil {
		t.Fatalf("响应外壳异常: %s", rec.Body.String())
	}
	if resp.Data.Device != "esp32-d8d514" {
		t.Errorf("设备名映射错误: %q", resp.Data.Device)
	}
}

// 短缓存：TTL 内重复调用不应重复打上游
func TestBuildMqttScreenDataUsesCache(t *testing.T) {
	var hits int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/messages":
			hits++
			json.NewEncoder(w).Encode([]map[string]string{
				{"time": "07:47:25", "client": "esp32-d8d514", "topic": "esp32/data", "payload": mqttTestPayload},
			})
		case "/api/health":
			json.NewEncoder(w).Encode(map[string]interface{}{"range": "1h"})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"points": []interface{}{}})
		}
	}))
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	mqttScreenCacheMu.Lock()
	mqttScreenCacheData, mqttScreenCacheAt = nil, time.Time{}
	mqttScreenCacheMu.Unlock()

	for i := 0; i < 3; i++ {
		if _, err := buildMqttScreenData(); err != nil {
			t.Fatalf("第 %d 次取数失败: %v", i+1, err)
		}
	}
	if hits != 1 {
		t.Errorf("TTL 内应只打一次上游，实际 %d 次", hits)
	}
}

// ==================== 逆地理编码 ====================

// stubMqttScreenAmap 把高德端点指向本地 stub，既避免测试真的打外部接口，
// 也让地址字段可断言。同时清空地址缓存，避免测试之间互相污染。
func stubMqttScreenAmap(t *testing.T, address string) *int {
	t.Helper()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Query().Get("key") == "" {
			t.Error("调用高德时必须带 key")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "1",
			"regeocode": map[string]interface{}{"formatted_address": address},
		})
	}))
	old := amapRegeoURL
	amapRegeoURL = srv.URL
	t.Cleanup(func() {
		amapRegeoURL = old
		srv.Close()
	})
	resetMqttScreenGeoCache()
	return &hits
}

func resetMqttScreenGeoCache() {
	mqttScreenGeoMu.Lock()
	mqttScreenGeoCache = map[string]mqttScreenGeoEntry{}
	mqttScreenGeoMu.Unlock()
}

// 坐标转换必须与前端页面里的实现一致，否则地图标记和地址会指向不同地方
func TestMqttScreenWGS84ToGCJ02(t *testing.T) {
	lat, lon := 32.015804, 118.789593
	glat, glon := mqttScreenWGS84ToGCJ02(lat, lon)

	// 实测偏移：纬度约 -0.00206，经度约 +0.00519（约 500m）
	if math.Abs((glat-lat)-(-0.002055)) > 1e-5 {
		t.Errorf("纬度偏移异常: %v", glat-lat)
	}
	if math.Abs((glon-lon)-0.005191) > 1e-5 {
		t.Errorf("经度偏移异常: %v", glon-lon)
	}
	// 中国境外不做偏移
	if la, lo := mqttScreenWGS84ToGCJ02(35.0, 139.0); la != 35.0 || lo != 139.0 {
		t.Errorf("境外坐标不应偏移，实际 %v,%v", la, lo)
	}
}

// 解析成功并命中网格缓存：设备静止时不能反复消耗高德配额
func TestMqttScreenReverseGeocodeSuccessAndCache(t *testing.T) {
	hits := stubMqttScreenAmap(t, "江苏省南京市秦淮区示例路1号")
	t.Setenv("SERVER_STATUS_AMAP_KEY", "test-key")

	const want = "江苏省南京市秦淮区示例路1号"
	if got := mqttScreenReverseGeocode(32.015804, 118.789593); got != want {
		t.Fatalf("地址解析错误: %q", got)
	}
	// 同一网格（小数 3 位内）再取两次都应命中缓存
	mqttScreenReverseGeocode(32.015804, 118.789593)
	mqttScreenReverseGeocode(32.015799, 118.789601)
	if *hits != 1 {
		t.Errorf("同网格应命中缓存，实际请求高德 %d 次", *hits)
	}
	// 跨网格（约 1km 外）应重新请求
	mqttScreenReverseGeocode(32.025804, 118.789593)
	if *hits != 2 {
		t.Errorf("跨网格应重新请求，实际 %d 次", *hits)
	}
}

// 高德不可用时必须降级成空串，而不是让整个定位接口失败
func TestMqttScreenReverseGeocodeFailureDegrades(t *testing.T) {
	amap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer amap.Close()
	old := amapRegeoURL
	amapRegeoURL = amap.URL
	defer func() { amapRegeoURL = old }()
	resetMqttScreenGeoCache()
	t.Setenv("SERVER_STATUS_AMAP_KEY", "test-key")

	if got := mqttScreenReverseGeocode(30.0, 120.0); got != "" {
		t.Errorf("高德异常应返回空串，实际 %q", got)
	}
}

// 高德返回 status!=1（配额耗尽/无效 key）时同样降级
func TestMqttScreenReverseGeocodeBadStatus(t *testing.T) {
	amap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "0", "info": "DAILY_QUERY_OVER_LIMIT",
		})
	}))
	defer amap.Close()
	old := amapRegeoURL
	amapRegeoURL = amap.URL
	defer func() { amapRegeoURL = old }()
	resetMqttScreenGeoCache()
	t.Setenv("SERVER_STATUS_AMAP_KEY", "test-key")

	if got := mqttScreenReverseGeocode(30.0, 120.0); got != "" {
		t.Errorf("status!=1 应返回空串，实际 %q", got)
	}
}

// 没配 key 时不应发起任何外部请求
func TestMqttScreenReverseGeocodeWithoutKey(t *testing.T) {
	t.Setenv("SERVER_STATUS_AMAP_KEY", "")
	if mqttScreenAmapKey() != "" {
		t.Skip("测试环境已配置 privateStore 的高德 key，跳过")
	}
	amap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("没有 key 时不应请求高德")
	}))
	defer amap.Close()
	old := amapRegeoURL
	amapRegeoURL = amap.URL
	defer func() { amapRegeoURL = old }()
	resetMqttScreenGeoCache()

	if got := mqttScreenReverseGeocode(31.0, 121.0); got != "" {
		t.Errorf("无 key 应返回空串，实际 %q", got)
	}
}

// 环境变量优先于 privateStore 配置，便于部署时覆盖
func TestMqttScreenAmapKeyPrefersEnv(t *testing.T) {
	t.Setenv("SERVER_STATUS_AMAP_KEY", "env-key")
	if got := mqttScreenAmapKey(); got != "env-key" {
		t.Errorf("应优先取环境变量，实际 %q", got)
	}
}

// 端到端：地址要出现在公开接口的返回里，且拿不到时不影响其它字段
func TestFetchMqttScreenDataIncludesAddress(t *testing.T) {
	stubMqttScreenAmap(t, "江苏省南京市秦淮区夫子庙街道")
	t.Setenv("SERVER_STATUS_AMAP_KEY", "test-key")

	ts := newMqttUpstreamMock(t, mqttTestPayload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.Address != "江苏省南京市秦淮区夫子庙街道" {
		t.Errorf("地址未写入: %q", data.Address)
	}
	if data.Lat != 32.015804 || data.Temperature != 22 {
		t.Error("地址解析不应影响其它字段")
	}
}

// 地址解析失败时，定位数据必须照常返回（只是地址为空）
func TestFetchMqttScreenDataAddressFailureKeepsData(t *testing.T) {
	amap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer amap.Close()
	old := amapRegeoURL
	amapRegeoURL = amap.URL
	defer func() { amapRegeoURL = old }()
	resetMqttScreenGeoCache()
	t.Setenv("SERVER_STATUS_AMAP_KEY", "test-key")

	ts := newMqttUpstreamMock(t, mqttTestPayload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("地址失败不应让整个接口失败: %v", err)
	}
	if data.Address != "" {
		t.Errorf("地址应为空，实际 %q", data.Address)
	}
	if data.Lat != 32.015804 || data.Device != "esp32-d8d514" {
		t.Error("地址失败时定位主数据必须完好")
	}
}

// 上报间隔必须可配置：设备改发送频率时不该改代码
func TestMqttScreenReportIntervalConfigurable(t *testing.T) {
	t.Setenv(mqttScreenReportIntervalEnv, "")
	if got := mqttScreenReportInterval(); got != mqttScreenReportIntervalDefault {
		t.Errorf("未配置时应回退默认 %d，实际 %d", mqttScreenReportIntervalDefault, got)
	}

	t.Setenv(mqttScreenReportIntervalEnv, "1800")
	if got := mqttScreenReportInterval(); got != 1800 {
		t.Errorf("应读取环境变量 1800，实际 %d", got)
	}
	// 离线阈值随上报间隔联动（2 倍）
	if got := mqttScreenOfflineAfter(); got != 3600*time.Second {
		t.Errorf("离线阈值应联动为 3600s，实际 %v", got)
	}

	// 非法值一律回退默认，不能让页面出现"每 0 分钟上报一次"
	for _, bad := range []string{"abc", "-5", "0", "  "} {
		t.Setenv(mqttScreenReportIntervalEnv, bad)
		if got := mqttScreenReportInterval(); got != mqttScreenReportIntervalDefault {
			t.Errorf("%q 应回退默认，实际 %d", bad, got)
		}
	}
}

// 上报间隔要随接口下发，前端不该把它写死
func TestFetchMqttScreenDataSendsReportInterval(t *testing.T) {
	t.Setenv(mqttScreenReportIntervalEnv, "900")
	stubMqttScreenAmap(t, "")

	ts := newMqttUpstreamMock(t, mqttTestPayload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.ReportInterval != 900 {
		t.Errorf("应下发 report_interval=900，实际 %d", data.ReportInterval)
	}
}

// 实际上报间隔取相邻间隔的中位数：偶发丢包不该把结果带偏
func TestMqttScreenObservedInterval(t *testing.T) {
	mk := func(ts ...int64) []mqttScreenTrackPoint {
		pts := make([]mqttScreenTrackPoint, len(ts))
		for i, v := range ts {
			pts[i] = mqttScreenTrackPoint{T: v}
		}
		return pts
	}

	if got := mqttScreenObservedInterval(mk(100, 200)); got != 0 {
		t.Errorf("少于 3 个点应返回 0，实际 %d", got)
	}
	if got := mqttScreenObservedInterval(mk(0, 600, 1200, 1800)); got != 600 {
		t.Errorf("稳定 600s 应算出 600，实际 %d", got)
	}
	// 中间丢了一次包（间隔 1200），中位数仍应是 600 而不是被均值带偏
	if got := mqttScreenObservedInterval(mk(0, 600, 1800, 2400, 3000)); got != 600 {
		t.Errorf("丢包时中位数应为 600，实际 %d", got)
	}
	// 上游返回顺序不保证
	if got := mqttScreenObservedInterval(mk(1200, 0, 1800, 600)); got != 600 {
		t.Errorf("乱序输入应算出 600，实际 %d", got)
	}
	// 时间戳全相同 → 没有有效间隔
	if got := mqttScreenObservedInterval(mk(100, 100, 100)); got != 0 {
		t.Errorf("无有效间隔应返回 0，实际 %d", got)
	}

	// 自适应上报：前面 10 分钟一报、最近切到 4 秒一报。
	// 必须反映"当前"节奏，而不是两者的中间值（生产环境实测就是这种混合模式）。
	var mixed []mqttScreenTrackPoint
	for i := 0; i < 20; i++ {
		mixed = append(mixed, mqttScreenTrackPoint{T: int64(i) * 600})
	}
	last := int64(19) * 600
	for i := 1; i <= 10; i++ {
		mixed = append(mixed, mqttScreenTrackPoint{T: last + int64(i)*4})
	}
	if got := mqttScreenObservedInterval(mixed); got != 4 {
		t.Errorf("自适应上报应反映当前节奏 4s，实际 %d", got)
	}
}

// 接口要把"实际观测到的间隔"下发出去，前端优先显示它
func TestFetchMqttScreenDataSendsObservedInterval(t *testing.T) {
	t.Setenv(mqttScreenReportIntervalEnv, "900")
	stubMqttScreenAmap(t, "")

	// 上游轨迹点间隔固定 600s
	base := time.Now().Unix() - 3000
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/messages":
			json.NewEncoder(w).Encode([]map[string]string{
				{"time": "07:47:25", "client": "esp32-d8d514", "topic": "esp32/data", "payload": mqttTestPayload},
			})
		case "/api/health":
			json.NewEncoder(w).Encode(map[string]interface{}{"range": "1h", "rssi": []map[string]interface{}{{"t": base + 2400, "v": -53}}})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"points": []map[string]interface{}{
				{"t": base, "lat": 32.01, "lon": 118.78},
				{"t": base + 600, "lat": 32.02, "lon": 118.79},
				{"t": base + 1200, "lat": 32.03, "lon": 118.80},
				{"t": base + 1800, "lat": 32.04, "lon": 118.81},
				{"t": base + 2400, "lat": 32.05, "lon": 118.82},
			}})
		}
	}))
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.ObservedInterval != 600 {
		t.Errorf("应算出实际间隔 600，实际 %d", data.ObservedInterval)
	}
	// 配置值也要照常下发，供样本不足时兜底
	if data.ReportInterval != 900 {
		t.Errorf("配置间隔应仍为 900，实际 %d", data.ReportInterval)
	}
}

// 未定位时不应触发地址解析
func TestFetchMqttScreenDataNoFixSkipsGeocode(t *testing.T) {
	hits := stubMqttScreenAmap(t, "不应出现")
	t.Setenv("SERVER_STATUS_AMAP_KEY", "test-key")

	payload := `{"temperature":20,"humidity":40,"gps_fix":false,"lat":0,"lon":0}`
	ts := newMqttUpstreamMock(t, payload, time.Now().Unix())
	defer ts.Close()
	t.Setenv(mqttScreenUpstreamEnv, ts.URL)

	data, err := fetchMqttScreenData()
	if err != nil {
		t.Fatalf("取数失败: %v", err)
	}
	if data.Address != "" {
		t.Errorf("未定位不应有地址，实际 %q", data.Address)
	}
	if *hits != 0 {
		t.Errorf("未定位不应请求高德，实际 %d 次", *hits)
	}
}
