package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// 定义常量
const (
	pingInterval      = 30 * time.Second
	pongWait          = 40 * time.Second
	writeWait         = 10 * time.Second
	maxMessageSize    = 512
	userCleanupPeriod = 5 * time.Minute
	userInactiveLimit = 30 * time.Minute
)

// 定义用户结构
type User struct {
	ID        string    `json:"id"`
	Latitude  float64   `json:"lat"`
	Longitude float64   `json:"lng"`
	Accuracy  float64   `json:"accuracy"`
	LastSeen  time.Time `json:"last_seen"`
}

// 定义WebSocket消息结构
type Message struct {
	Type     string          `json:"type"` // register, location_update, users_list, user_left
	UserID   string          `json:"userId"`
	Lat      float64         `json:"lat,omitempty"`
	Lng      float64         `json:"lng,omitempty"`
	Accuracy float64         `json:"accuracy,omitempty"`
	Users    map[string]User `json:"users,omitempty"`
}

// 客户端连接信息
type Client struct {
	conn   *websocket.Conn
	userID string
	send   chan []byte
}

// 全局变量
var (
	upgraders = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// 生产环境中应限制允许的域名
			// return r.Header.Get("Origin") == "https://yourdomain.com"
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	// 存储所有连接的客户端
	clients = make(map[*Client]bool)

	// 存储用户信息
	users = make(map[string]User)

	// 广播通道
	broadcast = make(chan Message, 100)

	// 互斥锁保护并发访问
	mu sync.RWMutex

	// 注册/注销通道
	register   = make(chan *Client)
	unregister = make(chan *Client)
)

// 健康检查端点
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("服务器运行正常"))
}

// 启动WebSocket服务器
func startWebSocketServer() {
	ticker := time.NewTicker(userCleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case client := <-register:
			mu.Lock()
			clients[client] = true

			// 检查是否已有相同用户ID的连接，如果有则关闭旧连接
			for c := range clients {
				if c != client && c.userID == client.userID {
					log.Printf("用户 %s 已有连接，关闭旧连接", client.userID)
					closeClient(c)
				}
			}

			// 初始化或更新用户信息
			users[client.userID] = User{
				ID:       client.userID,
				LastSeen: time.Now(),
			}
			log.Printf("用户 %s 已连接，当前连接数: %d", client.userID, len(clients))
			mu.Unlock()

			// 发送当前所有用户信息给新连接的用户
			sendAllUsers(client)

		case client := <-unregister:
			mu.Lock()
			if _, ok := clients[client]; ok {
				delete(clients, client)
				close(client.send)
				log.Printf("用户 %s 已断开连接，当前连接数: %d", client.userID, len(clients))

				// 如果用户没有其他连接，则从用户列表中移除
				userHasOtherConnections := false
				for c := range clients {
					if c.userID == client.userID {
						userHasOtherConnections = true
						break
					}
				}

				if !userHasOtherConnections {
					delete(users, client.userID)
					// 广播用户离开通知
					broadcast <- Message{
						Type:   "user_left",
						UserID: client.userID,
					}
				}
			}
			mu.Unlock()

		case message := <-broadcast:
			mu.RLock()
			for client := range clients {
				// 不发送给消息来源的客户端（如果是位置更新）
				if message.Type == "location_update" && client.userID == message.UserID {
					continue
				}

				select {
				case client.send <- serializeMessage(message):
				default:
					closeClient(client)
				}
			}
			mu.RUnlock()

		case <-ticker.C:
			cleanupInactiveUsers()
		}
	}
}

// 处理WebSocket连接
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgraders.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket升级失败:", err)
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, 256),
	}

	// 启动读写goroutines
	go client.writePump()
	go client.readPump()
}

// 读取消息
func (c *Client) readPump() {
	defer func() {
		unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("读取错误: %v", err)
			}
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Println("解析消息失败:", err)
			continue
		}

		switch msg.Type {
		case "register":
			c.userID = msg.UserID
			register <- c

		case "location_update":
			mu.Lock()
			if user, exists := users[msg.UserID]; exists {
				user.Latitude = msg.Lat
				user.Longitude = msg.Lng
				user.Accuracy = msg.Accuracy
				user.LastSeen = time.Now()
				users[msg.UserID] = user
			}
			mu.Unlock()

			// 广播位置更新
			broadcast <- msg
		}
	}
}

// 写入消息
func (c *Client) writePump() {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// 通道关闭
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// 将队列中的消息一起发送
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// 向客户端发送所有用户信息
func sendAllUsers(client *Client) {
	mu.RLock()
	message := Message{
		Type:  "users_list",
		Users: users,
	}
	mu.RUnlock()

	client.send <- serializeMessage(message)
}

// 序列化消息
func serializeMessage(msg Message) []byte {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Println("序列化消息失败:", err)
		return nil
	}
	return data
}

// 清理不活跃用户
func cleanupInactiveUsers() {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	for id, user := range users {
		if now.Sub(user.LastSeen) > userInactiveLimit {
			// 检查用户是否还有活跃连接
			hasActiveConnection := false
			for client := range clients {
				if client.userID == id {
					hasActiveConnection = true
					break
				}
			}

			if !hasActiveConnection {
				delete(users, id)
				log.Printf("清理不活跃用户: %s", id)

				// 广播用户离开通知
				broadcast <- Message{
					Type:   "user_left",
					UserID: id,
				}
			}
		}
	}
}

// 关闭客户端连接
func closeClient(client *Client) {
	close(client.send)
	delete(clients, client)
	client.conn.Close()
}
