package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/logger"
	"github.com/go-redis/redis/v8"
)

type sessionServiceImpl struct {
	redisClient redis.UniversalClient
	// In-memory fallback when Redis is not available
	memStore   map[string][]byte
	memMu      sync.RWMutex
	useMemory  bool
}

func NewSessionServiceImpl() *sessionServiceImpl {
	client := config.GetRedis()
	useMemory := client == nil
	return &sessionServiceImpl{
		redisClient: client,
		memStore:    make(map[string][]byte),
		useMemory:   useMemory,
	}
}

func init() {
	if service.GetSessionService() == nil {
		service.RegisterSessionServiceImpl(NewSessionServiceImpl())
	}
}

func (s *sessionServiceImpl) CreateSession(userID uint, username string, data map[string]interface{}) (string, error) {
	ctx := context.Background()
	sessionID := fmt.Sprintf("session:%d:%d", userID, time.Now().UnixNano())

	session := &service.Session{
		ID:        sessionID,
		UserID:    userID,
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Data:      data,
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		logger.Errorf(ctx, "序列化会话失败: %v", err)
		return "", err
	}

	if s.useMemory {
		s.memMu.Lock()
		s.memStore[sessionID] = sessionJSON
		s.memMu.Unlock()
	} else {
		err = s.redisClient.Set(ctx, sessionID, sessionJSON, 24*time.Hour).Err()
		if err != nil {
			logger.Errorf(ctx, "存储会话到Redis失败: %v", err)
			return "", err
		}
	}

	return sessionID, nil
}

func (s *sessionServiceImpl) GetSession(sessionID string) (*service.Session, error) {
	ctx := context.Background()

	var sessionJSON []byte
	var err error

	if s.useMemory {
		s.memMu.RLock()
		data, ok := s.memStore[sessionID]
		s.memMu.RUnlock()
		if !ok {
			return nil, errors.New("会话不存在")
		}
		sessionJSON = data
	} else {
		result, e := s.redisClient.Get(ctx, sessionID).Result()
		if e != nil {
			logger.Errorf(ctx, "从Redis获取会话失败: %v", e)
			return nil, e
		}
		sessionJSON = []byte(result)
	}

	var session service.Session
	err = json.Unmarshal(sessionJSON, &session)
	if err != nil {
		logger.Errorf(ctx, "反序列化会话失败: %v", err)
		return nil, err
	}

	if time.Now().After(time.Unix(session.ExpiresAt, 0)) {
		s.DeleteSession(sessionID)
		return nil, errors.New("会话已过期")
	}

	return &session, nil
}

func (s *sessionServiceImpl) UpdateSession(sessionID string, data map[string]interface{}) error {
	ctx := context.Background()
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	session.Data = data
	session.ExpiresAt = time.Now().Add(24 * time.Hour).Unix()

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		logger.Errorf(ctx, "序列化会话失败: %v", err)
		return err
	}

	if s.useMemory {
		s.memMu.Lock()
		s.memStore[sessionID] = sessionJSON
		s.memMu.Unlock()
	} else {
		err = s.redisClient.Set(ctx, sessionID, sessionJSON, 24*time.Hour).Err()
		if err != nil {
			logger.Errorf(ctx, "存储会话到Redis失败: %v", err)
			return err
		}
	}

	return nil
}

func (s *sessionServiceImpl) DeleteSession(sessionID string) error {
	ctx := context.Background()

	if s.useMemory {
		s.memMu.Lock()
		delete(s.memStore, sessionID)
		s.memMu.Unlock()
	} else {
		err := s.redisClient.Del(ctx, sessionID).Err()
		if err != nil {
			logger.Errorf(ctx, "从Redis删除会话失败: %v", err)
			return err
		}
	}

	return nil
}

func (s *sessionServiceImpl) DeleteUserSessions(userID uint) error {
	ctx := context.Background()

	if s.useMemory {
		prefix := fmt.Sprintf("session:%d:", userID)
		s.memMu.Lock()
		for key := range s.memStore {
			if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
				delete(s.memStore, key)
			}
		}
		s.memMu.Unlock()
	} else {
		keys, err := s.redisClient.Keys(ctx, fmt.Sprintf("session:%d:*", userID)).Result()
		if err != nil {
			logger.Errorf(ctx, "查找用户会话失败: %v", err)
			return err
		}

		if len(keys) > 0 {
			err = s.redisClient.Del(ctx, keys...).Err()
			if err != nil {
				logger.Errorf(ctx, "删除用户会话失败: %v", err)
				return err
			}
		}
	}

	return nil
}

func (s *sessionServiceImpl) ExtendSession(sessionID string) error {
	ctx := context.Background()
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	session.ExpiresAt = time.Now().Add(24 * time.Hour).Unix()

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		logger.Errorf(ctx, "序列化会话失败: %v", err)
		return err
	}

	if s.useMemory {
		s.memMu.Lock()
		s.memStore[sessionID] = sessionJSON
		s.memMu.Unlock()
	} else {
		err = s.redisClient.Set(ctx, sessionID, sessionJSON, 24*time.Hour).Err()
		if err != nil {
			logger.Errorf(ctx, "存储会话到Redis失败: %v", err)
			return err
		}
	}

	return nil
}
