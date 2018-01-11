package dlog

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Severity int32

type globals struct {
	sync.Mutex
	logLevel Severity
	appName  string
}

var (
	_globals = globals{
		logLevel: SeverityLast,
		appName:  "-",
	}
)

const (
	SeverityDebug Severity = iota
	SeverityInfo
	SeverityNotice
	SeverityWarning
	SeverityError
	SeverityCritical
	SeverityFatal
	SeverityLast
)

var SeverityName = []string{
	SeverityDebug:    "DEBUG",
	SeverityInfo:     "INFO",
	SeverityNotice:   "NOTICE",
	SeverityWarning:  "WARNING",
	SeverityError:    "ERROR",
	SeverityCritical: "CRITICAL",
	SeverityFatal:    "FATAL",
}

func Debugf(format string, args ...interface{}) {
	logf(SeverityDebug, format, args...)
}

func Infof(format string, args ...interface{}) {
	logf(SeverityInfo, format, args...)
}

func Noticef(format string, args ...interface{}) {
	logf(SeverityNotice, format, args...)
}

func Warnf(format string, args ...interface{}) {
	logf(SeverityWarning, format, args...)
}

func Errorf(format string, args ...interface{}) {
	logf(SeverityError, format, args...)
}

func Criticalf(format string, args ...interface{}) {
	logf(SeverityCritical, format, args...)
}

func Fatalf(format string, args ...interface{}) {
	logf(SeverityFatal, format, args...)
}

func Debug(message interface{}) {
	log(SeverityDebug, message)
}

func Info(message interface{}) {
	log(SeverityInfo, message)
}

func Notice(message interface{}) {
	log(SeverityNotice, message)
}

func Warn(message interface{}) {
	log(SeverityWarning, message)
}

func Error(message interface{}) {
	log(SeverityError, message)
}

func Critical(message interface{}) {
	log(SeverityCritical, message)
}

func Fatal(message interface{}) {
	log(SeverityFatal, message)
}

func (s *Severity) get() Severity {
	return Severity(atomic.LoadInt32((*int32)(s)))
}

func (s *Severity) set(val Severity) {
	atomic.StoreInt32((*int32)(s), int32(val))
}

func (s *Severity) String() string {
	return strconv.FormatInt(int64(*s), 10)
}

func (s *Severity) Get() interface{} {
	return s.get()
}

func (s *Severity) Set(strVal string) error {
	val, _ := strconv.Atoi(strVal)
	s.set(Severity(val))
	return nil
}

func Init(appName string, logLevel Severity) {
	_globals.logLevel.set(logLevel)
	flag.Var(&_globals.logLevel, "loglevel", fmt.Sprintf("Log level (%d-%d)", SeverityDebug, SeverityFatal))
}

func logf(severity Severity, format string, args ...interface{}) {
	if severity < _globals.logLevel.get() {
		return
	}
	now := time.Now()
	year, month, day := now.Date()
	hour, minute, second := now.Clock()
	message := fmt.Sprintf(format, args...)
	message = strings.TrimSpace(strings.TrimSuffix(message, "\n"))
	if len(message) <= 0 {
		return
	}
	line := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d] [%s] [%s] %s\n", year, int(month), day, hour, minute, second, _globals.appName, SeverityName[severity], message)
	_globals.Lock()
	os.Stderr.WriteString(line)
	_globals.Unlock()
	if severity >= SeverityFatal {
		os.Exit(255)
	}
}

func log(severity Severity, args interface{}) {
	logf(severity, "%v", args)
}
