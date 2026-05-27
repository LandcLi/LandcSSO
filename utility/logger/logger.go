package logger

import (
	"context"

	"github.com/LandcLi/landc-go/log/facade"
)

var logger facade.Logger

func InitLogger(config *facade.LogConfig) {
	if GetLogger() != nil {
		return
	}
	// 根据LogConfig创建日志实例
	logger = facade.GetLoggerWithLogConfig(config)
	logger.Info("使用LogConfig的日志")
}
func InitLoggerWithLogger(l facade.Logger) {
	logger = l
}
func GetLogger() facade.Logger {
	return logger
}
func Debug(ctx context.Context, msg string) {
	logger.WithContext(ctx).Debug(msg)
}
func Info(ctx context.Context, msg string) {
	logger.WithContext(ctx).Info(msg)
}
func Warn(ctx context.Context, msg string) {
	logger.WithContext(ctx).Warn(msg)
}
func Error(ctx context.Context, msg string) {
	logger.WithContext(ctx).Error(msg)
}
func Fatal(ctx context.Context, msg string) {
	logger.WithContext(ctx).Fatal(msg)
}
func Debugf(ctx context.Context, format string, v ...interface{}) {
	logger.WithContext(ctx).Debugf(format, v...)
}
func Infof(ctx context.Context, format string, v ...interface{}) {
	logger.WithContext(ctx).Infof(format, v...)
}
func Warnf(ctx context.Context, format string, v ...interface{}) {
	logger.WithContext(ctx).Warnf(format, v...)
}
func Errorf(ctx context.Context, format string, v ...interface{}) {
	logger.WithContext(ctx).Errorf(format, v...)
}
func Fatalf(ctx context.Context, format string, v ...interface{}) {
	logger.WithContext(ctx).Fatalf(format, v...)
}
