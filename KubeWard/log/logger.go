// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package log

import (
	"encoding/json"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// zapLogger is the global sugared logger instance.
var zapLogger *zap.SugaredLogger

// init initializes the zap logger at package load time.
func init() {
	initLogger()
}

// customTimeEncoder formats the log timestamp in human-readable format.
func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05.000000"))
}

// initLogger sets up the zap logger with console encoding and debug level.
func initLogger() {
	defaultConfig := []byte(`{
		"level": "debug",
		"encoding": "console",
		"outputPaths": ["stdout"],
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"nameKey": "logger",
			"timeKey": "time",
			"callerKey": "logger",
			"stacktraceKey": "stacktrace",
			"callstackKey": "callstack",
			"errorKey": "error",
			"levelEncoder": "capitalColor",
			"durationEncoder": "second",
			"sampling": {
				"initial": "3",
				"thereafter": "10"
			}
		}
	}`)

	config := zap.Config{}
	if err := json.Unmarshal(defaultConfig, &config); err != nil {
		panic(err)
	}

	config.EncoderConfig.EncodeTime = customTimeEncoder
	config.Level.SetLevel(zap.DebugLevel)

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	zapLogger = logger.Sugar()
}

// Print logs an informational message.
func Print(message string) {
	zapLogger.Info(message)
}

// Printf logs an informational message with formatting.
func Printf(message string, args ...interface{}) {
	zapLogger.Infof(message, args...)
}

// Debug logs a debug-level message.
func Debug(message string) {
	zapLogger.Debug(message)
}

// Debugf logs a debug-level message with formatting.
func Debugf(message string, args ...interface{}) {
	zapLogger.Debugf(message, args...)
}

// Err logs an error message.
func Err(message string) {
	zapLogger.Error(message)
}

// Errf logs an error message with formatting.
func Errf(message string, args ...interface{}) {
	zapLogger.Errorf(message, args...)
}

// Warn logs a warning message.
func Warn(message string) {
	zapLogger.Warn(message)
}

// Warnf logs a warning message with formatting.
func Warnf(message string, args ...interface{}) {
	zapLogger.Warnf(message, args...)
}
