package logger

import (
	"fmt"
	"log"
	"os"
)

// Logger defines the logging interface
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Fatal(msg string, args ...interface{})
	With(key string, value interface{}) Logger
	WithError(err error) Logger
}

// logger implements the Logger interface
type logger struct {
	level string
}

// New creates a new logger instance
func New(level string) Logger {
	return &logger{level: level}
}

// Debug logs a debug message
func (l *logger) Debug(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	log.Printf("[DEBUG] %s", msg)
}

// Info logs an info message
func (l *logger) Info(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	log.Printf("[INFO] %s", msg)
}

// Warn logs a warning message
func (l *logger) Warn(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	log.Printf("[WARN] %s", msg)
}

// Error logs an error message
func (l *logger) Error(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	log.Printf("[ERROR] %s", msg)
}

// Fatal logs a fatal message and exits
func (l *logger) Fatal(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	log.Printf("[FATAL] %s", msg)
	os.Exit(1)
}

// With adds a key-value pair to the logger context
func (l *logger) With(key string, value interface{}) Logger {
	return l // Simple implementation for now
}

// WithError adds an error to the logger context
func (l *logger) WithError(err error) Logger {
	return l // Simple implementation for now
}

// Global logger instance
var globalLogger Logger

// init initializes the global logger
func init() {
	globalLogger = New("info")
}

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(l Logger) {
	globalLogger = l
}

// Debug logs a debug message using the global logger
func Debug(msg string, args ...interface{}) {
	globalLogger.Debug(msg, args...)
}

// Info logs an info message using the global logger
func Info(msg string, args ...interface{}) {
	globalLogger.Info(msg, args...)
}

// Warn logs a warning message using the global logger
func Warn(msg string, args ...interface{}) {
	globalLogger.Warn(msg, args...)
}

// Error logs an error message using the global logger
func Error(msg string, args ...interface{}) {
	globalLogger.Error(msg, args...)
}

// Fatal logs a fatal message using the global logger and exits
func Fatal(msg string, args ...interface{}) {
	globalLogger.Fatal(msg, args...)
}

// With adds a key-value pair to the global logger context
func With(key string, value interface{}) Logger {
	return globalLogger.With(key, value)
}

// WithError adds an error to the global logger context
func WithError(err error) Logger {
	return globalLogger.WithError(err)
}
