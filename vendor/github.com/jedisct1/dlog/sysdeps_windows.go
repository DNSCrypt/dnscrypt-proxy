package dlog

import "golang.org/x/sys/windows/svc/eventlog"

type systemLogger struct {
	inner *eventlog.Log
}

func newSystemLogger(appName string, facility string) (*systemLogger, error) {
	eventLogger, err := eventlog.Open(appName)
	if err != nil {
		return nil, err
	}
	return &systemLogger{inner: eventLogger}, nil
}

func (systemLogger *systemLogger) writeString(severity Severity, message string) {
	switch severity {
	case SeverityError:
	case SeverityCritical:
	case SeverityFatal:
		systemLogger.inner.Error(uint32(severity), message)
	case SeverityWarning:
		systemLogger.inner.Warning(uint32(severity), message)
	default:
		systemLogger.inner.Info(uint32(severity), message)
	}
}
