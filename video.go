package main

//
//import (
//	"encoding/json"
//	"fmt"
//	"log"
//	"net/http"
//	"os"
//	"os/exec"
//	"path/filepath"
//	"strings"
//	"time"
//)
//
//// 配置
//const (
//	Port          = ":8081"
//	StaticDir     = "./static"
//	TempDir       = "./temp"
//	MaxUploadSize = 500 * 1024 * 1024 // 500MB
//)
//
//// 请求和响应结构体
//type VideoRequest struct {
//	URL   string  `json:"url"`
//	Start float64 `json:"start"`
//	End   float64 `json:"end"`
//}
//
//type CheckResponse struct {
//	Exists bool   `json:"exists"`
//	Error  string `json:"error,omitempty"`
//}
//
//type CutResponse struct {
//	Success     bool   `json:"success"`
//	DownloadURL string `json:"download_url,omitempty"`
//	Error       string `json:"error,omitempty"`
//}
//
//func main() {
//	// 创建必要的目录
//	createDirectories()
//
//	// 设置静态文件服务
//	fs := http.FileServer(http.Dir(StaticDir))
//	http.Handle("/static/", http.StripPrefix("/static/", fs))
//
//	// 提供前端页面
//	http.HandleFunc("/", serveIndex)
//
//	// API路由
//	http.HandleFunc("/api/check-video", checkVideoHandler)
//	http.HandleFunc("/api/cut-video", cutVideoHandler)
//	http.HandleFunc("/api/download/", downloadHandler)
//
//	// 启动服务器
//	fmt.Printf("服务器启动在 http://localhost%s\n", Port)
//	fmt.Printf("静态文件目录: %s\n", StaticDir)
//	fmt.Printf("临时文件目录: %s\n", TempDir)
//
//	if err := http.ListenAndServe(Port, nil); err != nil {
//		log.Fatal("服务器启动失败: ", err)
//	}
//}
//
//// 创建必要的目录
//func createDirectories() {
//	dirs := []string{StaticDir, TempDir}
//	for _, dir := range dirs {
//		if err := os.MkdirAll(dir, 0755); err != nil {
//			log.Fatalf("创建目录 %s 失败: %v", dir, err)
//		}
//	}
//}
//
//// 提供前端页面
//func serveIndex(w http.ResponseWriter, r *http.Request) {
//	if r.URL.Path == "/" {
//		// 这里可以返回前端HTML，或者直接使用文件服务
//		http.ServeFile(w, r, "./video.html")
//	} else {
//		http.NotFound(w, r)
//	}
//}
//
//// 检查视频文件是否存在
//func checkVideoHandler(w http.ResponseWriter, r *http.Request) {
//	w.Header().Set("Content-Type", "application/json")
//	w.Header().Set("Access-Control-Allow-Origin", "*")
//
//	if r.Method != "POST" {
//		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
//		return
//	}
//
//	var req VideoRequest
//	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//		sendJSONResponse(w, CheckResponse{Exists: false, Error: "无效的请求数据"}, http.StatusBadRequest)
//		return
//	}
//
//	// 从URL中提取路径
//	urlPath := req.URL
//	if strings.Contains(urlPath, "/static/") {
//		// 提取/static/之后的部分
//		parts := strings.SplitN(urlPath, "/static/", 2)
//		if len(parts) > 1 {
//			videoPath := filepath.Join(StaticDir, parts[1])
//
//			// 检查文件是否存在
//			if _, err := os.Stat(videoPath); err == nil {
//				sendJSONResponse(w, CheckResponse{Exists: true}, http.StatusOK)
//				return
//			}
//		}
//	}
//
//	sendJSONResponse(w, CheckResponse{Exists: false, Error: "视频文件不存在"}, http.StatusOK)
//}
//
//// 裁剪视频处理
//func cutVideoHandler(w http.ResponseWriter, r *http.Request) {
//	w.Header().Set("Content-Type", "application/json")
//	w.Header().Set("Access-Control-Allow-Origin", "*")
//
//	if r.Method != "POST" {
//		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
//		return
//	}
//
//	var req VideoRequest
//	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//		sendJSONResponse(w, CutResponse{Success: false, Error: "无效的请求数据"}, http.StatusBadRequest)
//		return
//	}
//
//	// 验证参数
//	if req.Start < 0 || req.End <= req.Start {
//		sendJSONResponse(w, CutResponse{Success: false, Error: "无效的时间范围"}, http.StatusBadRequest)
//		return
//	}
//
//	// 从URL中提取文件名
//	var videoPath string
//	if strings.Contains(req.URL, "/static/") {
//		parts := strings.SplitN(req.URL, "/static/", 2)
//		if len(parts) > 1 {
//			videoPath = filepath.Join(StaticDir, parts[1])
//		}
//	}
//
//	if videoPath == "" {
//		sendJSONResponse(w, CutResponse{Success: false, Error: "无效的视频URL"}, http.StatusBadRequest)
//		return
//	}
//
//	// 检查文件是否存在
//	if _, err := os.Stat(videoPath); os.IsNotExist(err) {
//		sendJSONResponse(w, CutResponse{Success: false, Error: "视频文件不存在"}, http.StatusNotFound)
//		return
//	}
//
//	// 生成输出文件名
//	timestamp := time.Now().Format("20060102_150405")
//	outputFilename := fmt.Sprintf("cropped_%s_%s", filepath.Base(videoPath), timestamp)
//	outputPath := filepath.Join(TempDir, outputFilename)
//
//	// 使用FFmpeg裁剪视频
//	duration := req.End - req.Start
//	cmd := exec.Command("ffmpeg",
//		"-i", videoPath,
//		"-ss", fmt.Sprintf("%.2f", req.Start),
//		"-t", fmt.Sprintf("%.2f", duration),
//		"-c", "copy",
//		"-avoid_negative_ts", "make_zero",
//		outputPath,
//	)
//
//	// 执行FFmpeg命令
//	if err := cmd.Run(); err != nil {
//		log.Printf("FFmpeg裁剪失败: %v", err)
//		sendJSONResponse(w, CutResponse{Success: false, Error: "视频裁剪失败"}, http.StatusInternalServerError)
//		return
//	}
//
//	// 检查输出文件
//	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
//		sendJSONResponse(w, CutResponse{Success: false, Error: "输出文件创建失败"}, http.StatusInternalServerError)
//		return
//	}
//
//	// 返回下载URL
//	downloadURL := fmt.Sprintf("/api/download/%s", outputFilename)
//	sendJSONResponse(w, CutResponse{
//		Success:     true,
//		DownloadURL: downloadURL,
//	}, http.StatusOK)
//}
//
//// 处理视频下载
//func downloadHandler(w http.ResponseWriter, r *http.Request) {
//	// 提取文件名
//	filename := strings.TrimPrefix(r.URL.Path, "/api/download/")
//	if filename == "" {
//		http.Error(w, "文件名不能为空", http.StatusBadRequest)
//		return
//	}
//
//	filePath := filepath.Join(TempDir, filename)
//
//	// 检查文件是否存在
//	if _, err := os.Stat(filePath); os.IsNotExist(err) {
//		http.NotFound(w, r)
//		return
//	}
//
//	// 设置响应头
//	w.Header().Set("Content-Type", "video/mp4")
//	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
//
//	// 提供文件下载
//	http.ServeFile(w, r, filePath)
//
//	// 可选：下载后删除临时文件
//	// defer os.Remove(filePath)
//}
//
//// 发送JSON响应
//func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
//	w.Header().Set("Content-Type", "application/json")
//	w.WriteHeader(statusCode)
//	json.NewEncoder(w).Encode(data)
//}
