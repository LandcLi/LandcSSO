package logger

import (
	"context"
	"time"

	"github.com/LandcLi/LandcLogFace"
	"github.com/LandcLi/LandcSSO/pkg/config"
)

var logger LandcLogFace.Logger

func InitLogger(config *config.Config) {
	// 创建并配置LogConfig
	localConfig := LandcLogFace.NewLogConfig()
	logLevel := LandcLogFace.DebugLevel
	switch (*config).Log.Level {
	case "info":
		logLevel = LandcLogFace.InfoLevel
	case "warn":
		logLevel = LandcLogFace.WarnLevel
	case "error":
		logLevel = LandcLogFace.ErrorLevel
	}
	localConfig.WithProvider((*config).Log.Provider).
		WithName("sso-server").
		WithLevel(logLevel).
		WithFormat((*config).Log.Format).
		WithOutputPath((*config).Log.OutputPath).
		WithMaxLogSize(50).                // 单个日志文件最大50MB
		WithMaxLogAge(7 * 24 * time.Hour). // 日志文件保留7天
		WithMaxLogFiles(5).                // 最多保留5个日志文件
		WithCompressLogs(true).            // 压缩旧日志
		WithMaxMessageSize(10)             // 单条日志最大10KB

	// 根据LogConfig创建日志实例
	logger = LandcLogFace.GetLoggerWithLogConfig(localConfig)
	logger.Info("使用LogConfig的日志")
}
func GetLogger() LandcLogFace.Logger {
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
