// +build !windows

package dlog

import (
	"github.com/hashicorp/go-syslog"
)

var severityToSyslogPriority = []gsyslog.Priority{
	SeverityDebug:    gsyslog.LOG_DEBUG,
	SeverityInfo:     gsyslog.LOG_INFO,
	SeverityNotice:   gsyslog.LOG_NOTICE,
	SeverityWarning:  gsyslog.LOG_WARNING,
	SeverityError:    gsyslog.LOG_ERR,
	SeverityCritical: gsyslog.LOG_CRIT,
	SeverityFatal:    gsyslog.LOG_ALERT,
}

type systemLogger struct {
	inner *gsyslog.Syslogger
}

func newSystemLogger(appName string, facility string) (*systemLogger, error) {
	eventLogger, err := gsyslog.NewLogger(gsyslog.LOG_INFO, facility, appName)
	if err != nil {
		return nil, err
	}
	return &systemLogger{inner: &eventLogger}, nil
}

func (systemLogger *systemLogger) writeString(severity Severity, message string) {
	(*systemLogger.inner).WriteLevel(severityToSyslogPriority[severity], []byte(message))
}
