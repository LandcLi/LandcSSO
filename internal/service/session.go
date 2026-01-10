package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/LandcLi/LandcSSO/pkg/config"
	"github.com/LandcLi/LandcSSO/pkg/logger"

	"github.com/go-redis/redis/v8"
)

// SessionService 会话服务
type SessionService struct {
	redisClient redis.UniversalClient
}

// NewSessionService 创建会话服务实例
func NewSessionService() *SessionService {
	return &SessionService{
		redisClient: config.RedisClient,
	}
}

// Session 会话结构
type Session struct {
	ID        string                 `json:"id"`
	UserID    uint                   `json:"user_id"`
	Username  string                 `json:"username"`
	ExpiresAt time.Time              `json:"expires_at"`
	Data      map[string]interface{} `json:"data"`
}

// CreateSession 创建会话
func (s *SessionService) CreateSession(userID uint, username string, data map[string]interface{}) (string, error) {
	ctx := context.Background()
	// 生成会话ID
	sessionID := fmt.Sprintf("session:%d:%d", userID, time.Now().UnixNano())

	// 创建会话
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24小时过期
		Data:      data,
	}

	// 序列化会话
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		logger.Errorf(ctx, "序列化会话失败: %v", err)
		return "", err
	}

	// 存储会话到Redis
	err = s.redisClient.Set(ctx, sessionID, sessionJSON, 24*time.Hour).Err()
	if err != nil {
		logger.Errorf(ctx, "存储会话到Redis失败: %v", err)
		return "", err
	}

	return sessionID, nil
}

// GetSession 获取会话
func (s *SessionService) GetSession(sessionID string) (*Session, error) {
	ctx := context.Background()
	// 从Redis获取会话
	sessionJSON, err := s.redisClient.Get(ctx, sessionID).Result()
	if err != nil {
		logger.Errorf(ctx, "从Redis获取会话失败: %v", err)
		return nil, err
	}

	// 反序列化会话
	var session Session
	err = json.Unmarshal([]byte(sessionJSON), &session)
	if err != nil {
		logger.Errorf(ctx, "反序列化会话失败: %v", err)
		return nil, err
	}

	// 检查会话是否过期
	if time.Now().After(session.ExpiresAt) {
		// 删除过期会话
		s.DeleteSession(sessionID)
		return nil, errors.New("会话已过期")
	}

	return &session, nil
}

// UpdateSession 更新会话
func (s *SessionService) UpdateSession(sessionID string, data map[string]interface{}) error {
	ctx := context.Background()
	// 获取会话
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	// 更新会话数据
	session.Data = data
	session.ExpiresAt = time.Now().Add(24 * time.Hour) // 重置过期时间

	// 序列化会话
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		logger.Errorf(ctx, "序列化会话失败: %v", err)
		return err
	}

	// 存储会话到Redis
	err = s.redisClient.Set(ctx, sessionID, sessionJSON, 24*time.Hour).Err()
	if err != nil {
		logger.Errorf(ctx, "存储会话到Redis失败: %v", err)
		return err
	}

	return nil
}

// DeleteSession 删除会话
func (s *SessionService) DeleteSession(sessionID string) error {
	ctx := context.Background()
	// 从Redis删除会话
	err := s.redisClient.Del(ctx, sessionID).Err()
	if err != nil {
		logger.Errorf(ctx, "从Redis删除会话失败: %v", err)
		return err
	}

	return nil
}

// DeleteUserSessions 删除用户的所有会话
func (s *SessionService) DeleteUserSessions(userID uint) error {
	ctx := context.Background()
	// 查找用户的所有会话
	keys, err := s.redisClient.Keys(ctx, fmt.Sprintf("session:%d:*", userID)).Result()
	if err != nil {
		logger.Errorf(ctx, "查找用户会话失败: %v", err)
		return err
	}

	// 删除所有会话
	if len(keys) > 0 {
		err = s.redisClient.Del(ctx, keys...).Err()
		if err != nil {
			logger.Errorf(ctx, "删除用户会话失败: %v", err)
			return err
		}
	}

	return nil
}

// ExtendSession 延长会话过期时间
func (s *SessionService) ExtendSession(sessionID string) error {
	ctx := context.Background()
	// 获取会话
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	// 更新过期时间
	session.ExpiresAt = time.Now().Add(24 * time.Hour)

	// 序列化会话
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		logger.Errorf(ctx, "序列化会话失败: %v", err)
		return err
	}

	// 存储会话到Redis
	err = s.redisClient.Set(ctx, sessionID, sessionJSON, 24*time.Hour).Err()
	if err != nil {
		logger.Errorf(ctx, "存储会话到Redis失败: %v", err)
		return err
	}

	return nil
}
