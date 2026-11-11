package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ==================== MQTT 设备定位大屏（公开只读） ====================
//
// 数据源是本机的 mqtt-dashboard 服务（默认 127.0.0.1:7777）。那个服务同时挂着
// 设备控制与配置类接口：/api/config 会明文回显高德 key 与 MQTT 凭据，/api/command
// 与 /api/ota 可直接向设备下发指令，且全部无认证。因此它绝不能直接对公网开放。
//
// 这里由 server-status 做一层**只读代理 + 字段白名单裁剪**：
//   - 只取定位与环境相关的必要字段，不透传 payload 原文；
//   - 设备内网 IP、WiFi 名、固件版本、运行时长、重启次数、空闲堆、原始 GPS 语句
//     等设备内部信息一律丢弃；
//   - 上游地址不出现在响应里，公网只需要访问本服务的这一个接口。
//
// 该接口**无需登录**（大屏要直接投屏展示），因此返回内容必须经得起公开审视。

const (
	// mqttScreenUpstreamEnv 覆盖上游地址的环境变量名
	mqttScreenUpstreamEnv = "SERVER_STATUS_MQTT_UPSTREAM"
	// mqttScreenUpstreamDefault 上游 mqtt-dashboard 默认地址（仅本机回环）
	mqttScreenUpstreamDefault = "http://127.0.0.1:7777"
	// mqttScreenHTTPTimeout 单次上游请求超时
	mqttScreenHTTPTimeout = 3 * time.Second
	// mqttScreenMaxBody 上游响应体读取上限，防止异常放大
	mqttScreenMaxBody = 1 << 20 // 1 MiB
	// mqttScreenCacheTTL 结果缓存时长。公开接口会被大屏高频轮询，
	// 用全局缓存把上游压力固定在"每 TTL 一次"，与访客数量无关。
	mqttScreenCacheTTL = 5 * time.Second
	// mqttScreenReportIntervalEnv 覆盖设备上报间隔的环境变量名（单位：秒）
	mqttScreenReportIntervalEnv = "SERVER_STATUS_MQTT_REPORT_INTERVAL"
	// mqttScreenReportIntervalDefault 设备上报间隔默认值（秒）。设备实际约 10 分钟一报。
	// 这是**默认值不是硬编码**：设备改频率后不用改代码，设环境变量即可。
	mqttScreenReportIntervalDefault = 600
	// mqttScreenOfflineFactor 离线判定倍数：
	// 超过「上报间隔 × 该倍数」没有新数据即视为离线。默认 2 倍（即 20 分钟）。
	mqttScreenOfflineFactor = 2
	// mqttScreenTrackLimit 轨迹最多返回的点数
	mqttScreenTrackLimit = 60
	// mqttScreenRange 向上游索取的时序窗口
	mqttScreenRange = "1h"

	// mqttScreenGeoTTL 逆地理编码成功结果的缓存时长
	mqttScreenGeoTTL = 30 * time.Minute
	// mqttScreenGeoFailTTL 逆地理编码失败结果的缓存时长（短一些，便于恢复）
	mqttScreenGeoFailTTL = time.Minute
	// mqttScreenGeoTimeout 逆地理编码请求超时
	mqttScreenGeoTimeout = 3 * time.Second
	// mqttScreenGeoGrid 坐标缓存网格精度（小数位）。3 位约 100m：
	// 设备基本静止，用网格做 key 能让公开接口的高频轮询几乎不消耗高德配额。
	mqttScreenGeoGrid = 3
	// mqttScreenGeoCacheMax 缓存条数上限，超过即整体重置（网格很小，正常不会触达）
	mqttScreenGeoCacheMax = 512

	// mqttScreenScatterWindow 计算"实测散布"最多取最近这么多个轨迹点。
	// 设备静止时约 5 分钟一报，20 个点覆盖约 1.5 小时，足够稳健又不会把
	// 很久以前的搬移混进来。
	mqttScreenScatterWindow = 20
	// mqttScreenScatterMax 散布超过该值时，说明轨迹里混入了搬移/飞点，
	// 不再当作"定位精度"展示（否则会画出一个几百米的圈，误导比不画更糟）。
	mqttScreenScatterMax = 150.0
)

// mqttScreenObservedWindow 推算实际间隔时只看最近这么多个轨迹点
const mqttScreenObservedWindow = 10

// mqttScreenObservedInterval 从轨迹点时间戳推算**近期**上报间隔（秒）。
//
// 只取最近 mqttScreenObservedWindow 个点，而不是全部：设备是自适应上报的
// （实测静止时约 10 分钟一报、移动时 3~4 秒一报），拿全量数据取中位数会得到
// 一个既不代表静止、也不代表移动的中间值，对判断"数据新不新鲜"毫无用处。
//
// 取相邻间隔的中位数抗抖动（偶发丢包会让个别间隔翻倍，均值会被带偏）；
// 样本不足时返回 0，由调用方回退到配置值。
func mqttScreenObservedInterval(points []mqttScreenTrackPoint) int {
	if len(points) < 3 {
		return 0
	}
	// 先按时间排序：上游返回顺序不保证，乱序会算出负间隔
	sorted := make([]mqttScreenTrackPoint, len(points))
	copy(sorted, points)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].T < sorted[j].T })

	recent := sorted
	if len(sorted) > mqttScreenObservedWindow {
		recent = sorted[len(sorted)-mqttScreenObservedWindow:]
	}

	diffs := make([]int64, 0, len(recent)-1)
	for i := 1; i < len(recent); i++ {
		if d := recent[i].T - recent[i-1].T; d > 0 {
			diffs = append(diffs, d)
		}
	}
	if len(diffs) == 0 {
		return 0
	}
	sort.Slice(diffs, func(i, j int) bool { return diffs[i] < diffs[j] })
	return int(diffs[len(diffs)/2])
}

// mqttScreenTrackScatter 计算最近轨迹点的实测散布（米）：
// 各点到中位中心距离的 75 分位。中位数和分位数都不受个别飞点影响，
// 衡量的是"设备静止时页面上的位置到底会飘多远"，包含多路径造成的系统性偏差。
//
// 返回 0 表示样本不足，或散布大到像是轨迹里混入了搬移/飞点——这时画一个
// 几百米的误差圈只会误导，不如不画。
func mqttScreenTrackScatter(points []mqttScreenTrackPoint, limit int) (float64, int) {
	if limit <= 0 || len(points) < 5 {
		return 0, 0
	}
	pts := make([]mqttScreenTrackPoint, len(points))
	copy(pts, points)
	sort.Slice(pts, func(i, j int) bool { return pts[i].T < pts[j].T })
	if len(pts) > limit {
		pts = pts[len(pts)-limit:]
	}

	n := len(pts)
	lats := make([]float64, n)
	lons := make([]float64, n)
	for i, p := range pts {
		lats[i] = p.Lat
		lons[i] = p.Lon
	}
	clat := mqttScreenMedian(lats)
	clon := mqttScreenMedian(lons)

	dists := make([]float64, n)
	for i, p := range pts {
		dists[i] = mqttScreenDistanceM(clat, clon, p.Lat, p.Lon)
	}
	sort.Float64s(dists)
	p75 := dists[(n-1)*3/4]
	if p75 > mqttScreenScatterMax {
		return 0, n
	}
	return p75, n
}

func mqttScreenMedian(values []float64) float64 {
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// mqttScreenDistanceM 两点距离（米）。只做几十~几百米量级的统计，
// 等距圆柱近似足够，且不依赖外部库。
func mqttScreenDistanceM(lat1, lon1, lat2, lon2 float64) float64 {
	const metersPerDegLat = 111132.0
	metersPerDegLon := 111320.0 * math.Cos((lat1+lat2)/2*math.Pi/180)
	dy := (lat2 - lat1) * metersPerDegLat
	dx := (lon2 - lon1) * metersPerDegLon
	return math.Hypot(dx, dy)
}

// mqttScreenReportInterval 返回设备上报间隔（秒）。
// 设备改发送频率时只需设 SERVER_STATUS_MQTT_REPORT_INTERVAL，不必改代码；
// 前端展示的"每 X 分钟上报一次"和离线判定都由它推导。
func mqttScreenReportInterval() int {
	if v := strings.TrimSpace(os.Getenv(mqttScreenReportIntervalEnv)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("⚠️ %s 取值非法（%q），回退默认 %d 秒", mqttScreenReportIntervalEnv, v, mqttScreenReportIntervalDefault)
	}
	return mqttScreenReportIntervalDefault
}

// mqttScreenOfflineAfter 离线判定阈值，随上报间隔联动
func mqttScreenOfflineAfter() time.Duration {
	return time.Duration(mqttScreenReportInterval()) * mqttScreenOfflineFactor * time.Second
}

// mqttScreenUpstream 返回上游基址（去掉尾部斜杠）
func mqttScreenUpstream() string {
	if v := strings.TrimSpace(os.Getenv(mqttScreenUpstreamEnv)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return mqttScreenUpstreamDefault
}

var mqttScreenHTTPClient = &http.Client{Timeout: mqttScreenHTTPTimeout}

// ---------- 上游响应结构（仅解析用得到的字段） ----------

type mqttScreenUpstreamMessage struct {
	Time    string `json:"time"`
	Client  string `json:"client"`
	Topic   string `json:"topic"`
	Payload string `json:"payload"`
}

// mqttScreenDevicePayload 设备上报 payload 中我们关心的字段。
// 统一用指针，以便区分"未上报该字段"与"上报为 0"。
type mqttScreenDevicePayload struct {
	Temperature *float64 `json:"temperature"`
	Humidity    *float64 `json:"humidity"`
	RSSI        *int     `json:"rssi"`
	GPSFix      *bool    `json:"gps_fix"`
	GPSStale    *bool    `json:"gps_stale"` // 设备端滤波结果是否已过期（样本一直被质量/飞点门限拒绝）
	Satellites  *int     `json:"satellites"`
	SatsInView  *int     `json:"sats_in_view"`
	Lat         *float64 `json:"lat"`
	Lon         *float64 `json:"lon"`
	Altitude    *float64 `json:"altitude"`
	SpeedKmh    *float64 `json:"speed_kmh"`
	Course      *float64 `json:"course"`
	Hdop        *float64 `json:"hdop"`

	// 以下三项自固件 1.5.3 起提供（设备端静止平均滤波的输出）。
	// 老固件不报这些字段，解析后为 nil —— 页面据此显示"—"而不是错误结论。
	Stationary *bool    `json:"stationary"` // 设备端是否判定为静止
	AccM       *float64 `json:"acc_m"`      // 设备端估计的定位精度（米）
	AvgN       *int     `json:"avg_n"`      // 参与平均的样本数
}

// mqttScreenSeriesPoint 上游 /api/health 的时序点（带 unix 秒时间戳）
type mqttScreenSeriesPoint struct {
	T int64   `json:"t"`
	V float64 `json:"v"`
}

type mqttScreenTrackResp struct {
	Points []mqttScreenTrackPoint `json:"points"`
}

// ---------- 对外响应结构（字段白名单，改这里等于改公开面） ----------

type mqttScreenTrackPoint struct {
	T   int64   `json:"t"`
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type mqttScreenData struct {
	Device      string                 `json:"device"`       // 设备标识
	Online      bool                   `json:"online"`       // 是否在线（按最后上报时间判定）
	LastSeen    int64                  `json:"last_seen"`    // 最后上报时间（unix 秒）
	Fix         bool                   `json:"fix"`          // GPS 是否已定位
	Stale       bool                   `json:"stale"`        // 设备端滤波结果过期：当前坐标是最后可信位置
	Lat         float64                `json:"lat"`          // 纬度（WGS-84）
	Lon         float64                `json:"lon"`          // 经度（WGS-84）
	Address     string                 `json:"address"`      // 逆地理编码出的可读地址（拿不到为空串）
	Altitude    float64                `json:"altitude"`     // 海拔 m
	SpeedKmh    float64                `json:"speed_kmh"`    // 速度 km/h
	Course      float64                `json:"course"`       // 航向 度
	Satellites  int                    `json:"satellites"`   // 参与定位的卫星数
	SatsInView  int                    `json:"sats_in_view"` // 视野内卫星数
	Hdop        float64                `json:"hdop"`         // 水平精度因子
	Temperature float64                `json:"temperature"`  // 温度 ℃
	Humidity    float64                `json:"humidity"`     // 湿度 %
	Rssi        int                    `json:"rssi"`         // WiFi 信号 dBm
	Track       []mqttScreenTrackPoint `json:"track"`        // 轨迹点
	UpdatedAt   int64                  `json:"updated_at"`   // 本响应生成时间（unix 秒）

	// Stationary 设备端判定为静止：此时上报的坐标是最近约两分钟样本的均值，
	// 精度远高于单个解（实测单点散布 ±40 m，均值标准误个位数米）。
	// 固件 1.5.3 起提供；老固件恒为 false，此时 AvgN 为 0 可作为区分依据。
	Stationary bool `json:"stationary"`
	// AccM 设备端给出的定位精度估计（米）：固件 1.5.4 起静止时是窗口内
	// 真实散布（1σ），移动时是前后半窗位移量；1.5.3 及以前是均值标准误，
	// 数值明显偏小（见页面说明）。0 表示设备端没有提供。
	AccM float64 `json:"acc_m"`
	// AvgN 参与平均的样本数；0 表示设备端未做平均（老固件或未定位）。
	AvgN int `json:"avg_n"`

	// ScatterM 实测散布（米）：最近若干轨迹点到其稳健中心距离的 75 分位。
	// 它回答的是"设备静止时页面上的位置会飘多远"，包含多路径造成的系统性偏差，
	// 比设备端 acc_m（均值标准误）更接近用户实际看到的误差。
	// 0 表示样本不足、设备在移动或轨迹里混入了搬移/飞点，此时不展示。
	ScatterM float64 `json:"scatter_m"`
	// ScatterN 参与 ScatterM 统计的轨迹点数。
	ScatterN int `json:"scatter_n"`

	// ReportInterval 配置的上报间隔（秒），来自 SERVER_STATUS_MQTT_REPORT_INTERVAL，
	// 作为 ObservedInterval 数据不足时的兜底。
	ReportInterval int `json:"report_interval"`

	// ObservedInterval 从实际轨迹点推算出的上报间隔（秒），0 表示样本不足。
	// 这是"设备实际上多久报一次"，比配置值更能反映真实状态（设备改频率、
	// 丢包、休眠都会让实际值偏离配置值）。
	ObservedInterval int `json:"observed_interval"`
}

// ---------- 缓存 ----------

var (
	mqttScreenCacheMu   sync.Mutex
	mqttScreenCacheAt   time.Time
	mqttScreenCacheData *mqttScreenData
)

// publicMqttScreenHandler GET /api/public/mqtt/screen
// 公开只读接口：返回设备定位与环境数据，供大屏直接投屏展示。
func publicMqttScreenHandler(w http.ResponseWriter, r *http.Request) {
	// 内容随设备上报变化，且属于私有数据，禁止任何中间层缓存
	w.Header().Set("Cache-Control", "no-store")

	data, err := buildMqttScreenData()
	if err != nil {
		// 上游不可达时只回一句通用提示，不把上游地址/错误细节透给公网
		log.Printf("MQTT 大屏数据获取失败: %v", err)
		writeJSONError(w, http.StatusBadGateway, "设备数据暂不可用")
		return
	}
	writeJSON(w, http.StatusOK, "ok", data)
}

// buildMqttScreenData 带短缓存的取数入口
func buildMqttScreenData() (*mqttScreenData, error) {
	mqttScreenCacheMu.Lock()
	if mqttScreenCacheData != nil && time.Since(mqttScreenCacheAt) < mqttScreenCacheTTL {
		cached := mqttScreenCacheData
		mqttScreenCacheMu.Unlock()
		return cached, nil
	}
	mqttScreenCacheMu.Unlock()

	data, err := fetchMqttScreenData()
	if err != nil {
		return nil, err
	}

	mqttScreenCacheMu.Lock()
	mqttScreenCacheData, mqttScreenCacheAt = data, time.Now()
	mqttScreenCacheMu.Unlock()
	return data, nil
}

// fetchMqttScreenData 并发拉取上游三个接口并组装成白名单结构
func fetchMqttScreenData() (*mqttScreenData, error) {
	var (
		wg                     sync.WaitGroup
		rawMessages, rawHealth []byte
		rawTrack               []byte
		errMessages, errHealth error
		errTrack               error
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		rawMessages, errMessages = mqttScreenFetch("/api/messages")
	}()
	go func() {
		defer wg.Done()
		rawHealth, errHealth = mqttScreenFetch("/api/health?range=" + mqttScreenRange)
	}()
	go func() {
		defer wg.Done()
		rawTrack, errTrack = mqttScreenFetch("/api/track?range=" + mqttScreenRange)
	}()
	wg.Wait()

	// 设备数据是主体，拿不到就算失败
	if errMessages != nil {
		return nil, fmt.Errorf("messages: %w", errMessages)
	}

	var messages []mqttScreenUpstreamMessage
	if err := json.Unmarshal(rawMessages, &messages); err != nil {
		return nil, fmt.Errorf("解析 messages: %w", err)
	}

	out := &mqttScreenData{UpdatedAt: time.Now().Unix()}

	// ---- 1. 最新一条上报（数组为正序，从后往前找第一条能解析的记录）----
	var (
		latest       mqttScreenDevicePayload
		latestClient string
		found        bool
	)
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		if msg.Topic != "esp32/data" {
			continue
		}
		var payload mqttScreenDevicePayload
		if err := json.Unmarshal([]byte(msg.Payload), &payload); err != nil {
			continue
		}
		latest, latestClient, found = payload, msg.Client, true
		break
	}
	if !found {
		return nil, fmt.Errorf("上游没有可解析的设备上报")
	}
	out.Device = latestClient

	// 逐字段白名单拷贝：上游 payload 里的 ip/wifi/version/uptime_ms/reboot_count/
	// free_heap/gps_time 等一概不带出来。
	if latest.GPSFix != nil {
		out.Fix = *latest.GPSFix
	}
	if latest.GPSStale != nil {
		out.Stale = *latest.GPSStale
	}
	if latest.Lat != nil {
		out.Lat = *latest.Lat
	}
	if latest.Lon != nil {
		out.Lon = *latest.Lon
	}
	if latest.Altitude != nil {
		out.Altitude = *latest.Altitude
	}
	if latest.SpeedKmh != nil {
		out.SpeedKmh = *latest.SpeedKmh
	}
	if latest.Course != nil {
		out.Course = *latest.Course
	}
	if latest.Satellites != nil {
		out.Satellites = *latest.Satellites
	}
	if latest.SatsInView != nil {
		out.SatsInView = *latest.SatsInView
	}
	if latest.Hdop != nil {
		out.Hdop = *latest.Hdop
	}
	if latest.Temperature != nil {
		out.Temperature = *latest.Temperature
	}
	if latest.Humidity != nil {
		out.Humidity = *latest.Humidity
	}
	if latest.RSSI != nil {
		out.Rssi = *latest.RSSI
	}
	if latest.Stationary != nil {
		out.Stationary = *latest.Stationary
	}
	if latest.AccM != nil {
		out.AccM = *latest.AccM
	}
	if latest.AvgN != nil {
		out.AvgN = *latest.AvgN
	}

	// 未定位时不带出无意义的坐标，定位质量信息同样清零
	// （否则页面会显示"静止 · 精度 1.6 m"却没有坐标）
	if !out.Fix {
		out.Lat, out.Lon = 0, 0
		out.Stale = false
		out.Stationary = false
		out.AccM = 0
		out.AvgN = 0
		out.ScatterM, out.ScatterN = 0, 0
	}

	// ---- 2. 最后上报时间：/api/health 的时序点带 unix 时间戳 ----
	if errHealth == nil {
		out.LastSeen = mqttScreenLatestTimestamp(rawHealth)
	}

	// ---- 3. 轨迹 ----
	if errTrack == nil {
		var track mqttScreenTrackResp
		if err := json.Unmarshal(rawTrack, &track); err == nil {
			points := make([]mqttScreenTrackPoint, 0, len(track.Points))
			for _, p := range track.Points {
				// 丢弃未定位时上报的 (0,0) 占位点
				if p.Lat == 0 && p.Lon == 0 {
					continue
				}
				points = append(points, p)
			}
			if len(points) > mqttScreenTrackLimit {
				points = points[len(points)-mqttScreenTrackLimit:]
			}
			out.Track = points
			// health 不可用时用轨迹末点兜底
			if out.LastSeen == 0 && len(points) > 0 {
				out.LastSeen = points[len(points)-1].T
			}
		}
	}
	if out.Track == nil {
		out.Track = []mqttScreenTrackPoint{}
	}
	// 实际观测到的上报间隔；样本不足时为 0，由前端回退到配置值
	out.ObservedInterval = mqttScreenObservedInterval(out.Track)

	// ---- 3b. 实测散布：设备静止时页面上的位置到底会飘多远 ----
	// 设备端判定静止时，即便上报节奏因刚重启/丢星还没回到 5 分钟，轨迹点仍然
	// 围绕同一位置，散布是有意义的；只有明确在移动时才跳过。stale 时也不统计——
	// 那说明样本一直被拒，当前坐标是最后可信位置，不能拿旧轨迹的散布冒充当前精度。
	if out.Fix && !out.Stale &&
		(out.Stationary || out.ObservedInterval == 0 || out.ObservedInterval >= 120) {
		out.ScatterM, out.ScatterN = mqttScreenTrackScatter(out.Track, mqttScreenScatterWindow)
	}

	// ---- 4. 可读地址：逆地理编码，失败留空，绝不影响定位主数据 ----
	if out.Fix && (out.Lat != 0 || out.Lon != 0) {
		out.Address = mqttScreenReverseGeocode(out.Lat, out.Lon)
	}

	// ---- 5. 在线判定（阈值随上报间隔联动）----
	out.ReportInterval = mqttScreenReportInterval()
	if out.LastSeen > 0 {
		out.Online = time.Since(time.Unix(out.LastSeen, 0)) < mqttScreenOfflineAfter()
	}

	return out, nil
}

// mqttScreenLatestTimestamp 从 /api/health 响应里取最大的时间戳。
// 上游按 metric 返回多组时序数组（rssi/uptime/...），这里不假设具体字段名，
// 凡是形如 [{"t":..,"v":..}] 的数组都参与取最大值，这样上游新增指标也不会漏判在线。
func mqttScreenLatestTimestamp(raw []byte) int64 {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return 0
	}
	var latest int64
	for key, value := range fields {
		if key == "range" {
			continue
		}
		var points []mqttScreenSeriesPoint
		if err := json.Unmarshal(value, &points); err != nil {
			continue
		}
		for _, p := range points {
			if p.T > latest {
				latest = p.T
			}
		}
	}
	return latest
}

// mqttScreenFetch 向上游发起一次 GET，返回响应体
func mqttScreenFetch(path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mqttScreenHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mqttScreenUpstream()+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := mqttScreenHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("上游 %s 返回 %d", path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, mqttScreenMaxBody))
}

// ==================== 逆地理编码（服务端专用） ====================

// mqttScreenAmapKey 取高德 Web 服务 key。
// 这个 key 是服务端机密：只在本进程内用于调用高德 REST 接口，
// 绝不通过任何接口下发浏览器（公开页要用地图也走无需 key 的瓦片服务）。
func mqttScreenAmapKey() string {
	if v := strings.TrimSpace(os.Getenv("SERVER_STATUS_AMAP_KEY")); v != "" {
		return v
	}
	if privateStore != nil {
		return strings.TrimSpace(privateStore.config.Geo.AmapKey)
	}
	return ""
}

type mqttScreenGeoEntry struct {
	address string
	at      time.Time
}

var (
	mqttScreenGeoMu    sync.Mutex
	mqttScreenGeoCache = map[string]mqttScreenGeoEntry{}
)

// mqttScreenReverseGeocode 把坐标解析成可读地址。
// 任何一步失败都返回空串——地址只是锦上添花，绝不能因为它影响定位主数据。
func mqttScreenReverseGeocode(lat, lon float64) string {
	key := mqttScreenAmapKey()
	if key == "" {
		return ""
	}

	// 按网格做缓存 key：设备基本静止，同一个网格内反复请求只打一次高德
	grid := fmt.Sprintf("%.*f,%.*f", mqttScreenGeoGrid, lat, mqttScreenGeoGrid, lon)

	mqttScreenGeoMu.Lock()
	if e, ok := mqttScreenGeoCache[grid]; ok {
		ttl := mqttScreenGeoTTL
		if e.address == "" {
			ttl = mqttScreenGeoFailTTL
		}
		if time.Since(e.at) < ttl {
			mqttScreenGeoMu.Unlock()
			return e.address
		}
	}
	mqttScreenGeoMu.Unlock()

	// 设备上报的是 WGS-84，高德要求 GCJ-02，不转换会偏出数百米
	glat, glon := mqttScreenWGS84ToGCJ02(lat, lon)
	addr := mqttScreenFetchRegeo(key, glon, glat)

	mqttScreenGeoMu.Lock()
	if len(mqttScreenGeoCache) >= mqttScreenGeoCacheMax {
		mqttScreenGeoCache = map[string]mqttScreenGeoEntry{}
	}
	mqttScreenGeoCache[grid] = mqttScreenGeoEntry{address: addr, at: time.Now()}
	mqttScreenGeoMu.Unlock()

	return addr
}

// mqttScreenFetchRegeo 调一次高德逆地理编码，失败返回空串
func mqttScreenFetchRegeo(key string, glon, glat float64) string {
	ctx, cancel := context.WithTimeout(context.Background(), mqttScreenGeoTimeout)
	defer cancel()

	location := fmt.Sprintf("%.6f,%.6f", glon, glat)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		amapRegeoURL+"?key="+url.QueryEscape(key)+"&location="+url.QueryEscape(location), nil)
	if err != nil {
		return ""
	}
	resp, err := mqttScreenHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return ""
	}

	var parsed struct {
		Status    string `json:"status"`
		Regeocode struct {
			FormattedAddress string `json:"formatted_address"`
		} `json:"regeocode"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Status != "1" {
		return ""
	}
	return strings.TrimSpace(parsed.Regeocode.FormattedAddress)
}

// mqttScreenWGS84ToGCJ02 WGS-84 → GCJ-02（火星坐标），与前端页面里的实现保持一致。
func mqttScreenWGS84ToGCJ02(lat, lon float64) (float64, float64) {
	const (
		pi = math.Pi
		a  = 6378245.0
		ee = 0.00669342162296594323
	)
	// 中国境外不做偏移
	if lon < 72.004 || lon > 137.8347 || lat < 0.8293 || lat > 55.8271 {
		return lat, lon
	}
	dLat := mqttScreenTransformLat(lon-105.0, lat-35.0)
	dLon := mqttScreenTransformLon(lon-105.0, lat-35.0)
	radLat := lat / 180.0 * pi
	magic := math.Sin(radLat)
	magic = 1 - ee*magic*magic
	sqrtMagic := math.Sqrt(magic)
	dLat = (dLat * 180.0) / ((a * (1 - ee)) / (magic * sqrtMagic) * pi)
	dLon = (dLon * 180.0) / (a / sqrtMagic * math.Cos(radLat) * pi)
	return lat + dLat, lon + dLon
}

func mqttScreenTransformLat(x, y float64) float64 {
	pi := math.Pi
	ret := -100.0 + 2.0*x + 3.0*y + 0.2*y*y + 0.1*x*y + 0.2*math.Sqrt(math.Abs(x))
	ret += (20.0*math.Sin(6.0*x*pi) + 20.0*math.Sin(2.0*x*pi)) * 2.0 / 3.0
	ret += (20.0*math.Sin(y*pi) + 40.0*math.Sin(y/3.0*pi)) * 2.0 / 3.0
	ret += (160.0*math.Sin(y/12.0*pi) + 320*math.Sin(y*pi/30.0)) * 2.0 / 3.0
	return ret
}

func mqttScreenTransformLon(x, y float64) float64 {
	pi := math.Pi
	ret := 300.0 + x + 2.0*y + 0.1*x*x + 0.1*x*y + 0.1*math.Sqrt(math.Abs(x))
	ret += (20.0*math.Sin(6.0*x*pi) + 20.0*math.Sin(2.0*x*pi)) * 2.0 / 3.0
	ret += (20.0*math.Sin(x*pi) + 40.0*math.Sin(x/3.0*pi)) * 2.0 / 3.0
	ret += (150.0*math.Sin(x/12.0*pi) + 300.0*math.Sin(x/30.0*pi)) * 2.0 / 3.0
	return ret
}
