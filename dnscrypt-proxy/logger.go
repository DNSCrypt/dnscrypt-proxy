package main

import (
	"io"
	"os"

	"github.com/jedisct1/dlog"
	"gopkg.in/natefinch/lumberjack.v2"
)

func Logger(logMaxSize int, logMaxAge int, logMaxBackups int, fileName string) io.Writer {
	if fileName == "/dev/stdout" {
		return os.Stdout
	}
	if st, _ := os.Stat(fileName); st != nil && !st.Mode().IsRegular() {
		if st.Mode().IsDir() {
			dlog.Fatalf("[%v] is a directory", fileName)
		}
		fp, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			dlog.Fatalf("Unable to access [%v]: [%v]", fileName, err)
		}
		return fp
	}
	logger := &lumberjack.Logger{LocalTime: true, MaxSize: logMaxSize, MaxAge: logMaxAge, MaxBackups: logMaxBackups, Filename: fileName, Compress: true}

	return logger
}
