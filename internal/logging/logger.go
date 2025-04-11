package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type LogLevel int

const (
	SILENT LogLevel = iota
	ERROR
	WARNING
	NOTICE
	INFO
	DEBUG
)

var (
	currentLevel = ERROR
	output       io.Writer = os.Stderr
)

func SetLevel(level LogLevel) {
	currentLevel = level
}

func SetOutput(w io.Writer) {
	output = w
}

func parseLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "SILENT":
		return SILENT, nil
	case "ERROR":
		return ERROR, nil
	case "WARNING":
		return WARNING, nil
	case "NOTICE":
		return NOTICE, nil
	case "INFO":
		return INFO, nil
	case "DEBUG":
		return DEBUG, nil
	default:
		return ERROR, fmt.Errorf("invalid log level: %s", level)
	}
}

func SetLevelFromString(level string) error {
	l, err := parseLevel(level)
	if err != nil {
		return err
	}
	SetLevel(l)
	return nil
}

func log(level LogLevel, prefix string, format string, args ...interface{}) {
	if level > currentLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(output, "[%s] %s\n", prefix, msg)
}

func Debug(format string, args ...interface{}) {
	log(DEBUG, "DEBUG", format, args...)
}

func Info(format string, args ...interface{}) {
	log(INFO, "INFO", format, args...)
}

func Notice(format string, args ...interface{}) {
	log(NOTICE, "NOTICE", format, args...)
}

func Warning(format string, args ...interface{}) {
	log(WARNING, "WARNING", format, args...)
}

func Error(format string, args ...interface{}) {
	log(ERROR, "ERROR", format, args...)
} 