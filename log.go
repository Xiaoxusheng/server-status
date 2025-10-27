package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 日志级别
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
)

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// 日志系统结构体
type Logger struct {
	mu         sync.Mutex
	file       *os.File
	consoleOut io.Writer
	level      LogLevel
}

// 日志条目结构
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	IP        string    `json:"ip,omitempty"`
	Path      string    `json:"path,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// 初始化日志系统
func NewLogger(level LogLevel) (*Logger, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 创建日志文件，按日期命名
	logFile := filepath.Join(logDir, fmt.Sprintf("server_%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("打开日志文件失败: %v", err)
	}

	return &Logger{
		file:       file,
		consoleOut: os.Stdout,
		level:      level,
	}, nil
}

// 记录日志
func (l *Logger) Log(level LogLevel, message string, r *http.Request, err error) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level.String(),
		Message:   message,
	}

	if r != nil {
		entry.IP = getClientIP(r)
		entry.Path = r.URL.Path
		entry.UserAgent = r.UserAgent()
	}

	if err != nil {
		entry.Error = err.Error()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// 格式化日志输出
	logLine := fmt.Sprintf("[%s] %s: %s", entry.Timestamp.Format("2006-01-02 15:04:05"), entry.Level, entry.Message)
	if entry.IP != "" {
		logLine += fmt.Sprintf(" IP: %s", entry.IP)
	}
	if entry.Path != "" {
		logLine += fmt.Sprintf(" Path: %s", entry.Path)
	}
	if entry.Error != "" {
		logLine += fmt.Sprintf(" Error: %s", entry.Error)
	}
	logLine += "\n"

	// 输出到控制台和文件
	l.consoleOut.Write([]byte(logLine))
	l.file.Write([]byte(logLine))

	// 检查是否需要切换到新的日志文件（新的一天）
	currentLogFile := filepath.Join(logDir, fmt.Sprintf("server_%s.log", time.Now().Format("2006-01-02")))
	if l.file.Name() != currentLogFile {
		l.file.Close()
		newFile, err := os.OpenFile(currentLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			// 如果无法创建新文件，继续使用旧文件
			l.file, _ = os.OpenFile(l.file.Name(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		} else {
			l.file = newFile
		}
	}
}

// 关闭日志文件
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// 简化日志方法
func (l *Logger) Debug(message string, r *http.Request) {
	l.Log(DEBUG, message, r, nil)
}

func (l *Logger) Info(message string, r *http.Request) {
	l.Log(INFO, message, r, nil)
}

func (l *Logger) Warning(message string, r *http.Request) {
	l.Log(WARNING, message, r, nil)
}

func (l *Logger) Error(message string, r *http.Request, err error) {
	l.Log(ERROR, message, r, err)
}

// 全局日志实例
var logger *Logger

// 初始化日志系统
func initLogger() {
	var err error
	logger, err = NewLogger(INFO) // 默认INFO级别
	if err != nil {
		log.Fatalf("初始化日志系统失败: %v", err)
	}
}
