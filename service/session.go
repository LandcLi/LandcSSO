package service

type Session struct {
	ID        string
	UserID    uint
	Username  string
	ExpiresAt int64
	Data      map[string]interface{}
}

type sessionService interface {
	CreateSession(userID uint, username string, data map[string]interface{}) (string, error)
	GetSession(sessionID string) (*Session, error)
	UpdateSession(sessionID string, data map[string]interface{}) error
	DeleteSession(sessionID string) error
	DeleteUserSessions(userID uint) error
	ExtendSession(sessionID string) error
}

var sessionServiceImpl sessionService

func RegisterSessionServiceImpl(impl sessionService) {
	sessionServiceImpl = impl
}

func GetSessionService() sessionService {
	return sessionServiceImpl
}
