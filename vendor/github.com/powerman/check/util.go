package check

import (
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

func callerTestFileLines() (file string, line int, funcLine int) {
	pc, file, line, ok := runtime.Caller(0)
	myfile := file
	for stack := 1; ok && samePackage(myfile, file); stack++ {
		pc, file, line, ok = runtime.Caller(stack)
	}
	if f := runtime.FuncForPC(pc); f != nil {
		_, funcLine = f.FileLine(f.Entry())
	}
	return file, line, funcLine
}

func samePackage(basefile, file string) bool {
	return filepath.Dir(basefile) == filepath.Dir(file) && !strings.HasSuffix(file, "_test.go")
}

func callerFuncName(stack int) string {
	pc, _, _, _ := runtime.Caller(stack + 1)
	return strings.TrimPrefix(funcNameAt(pc), "(*C).")
}

func funcName(f any) string {
	return funcNameAt(reflect.ValueOf(f).Pointer())
}

func funcNameAt(pc uintptr) string {
	name := "<unknown>"
	if f := runtime.FuncForPC(pc); f != nil {
		name = f.Name()
		if i := strings.LastIndex(name, "/"); i != -1 {
			name = name[i+1:]
		}
		if i := strings.Index(name, "."); i != -1 {
			name = name[i+1:]
		}
	}
	return name
}

func format(msg ...any) string {
	if len(msg) > 1 {
		return fmt.Sprintf(msg[0].(string), msg[1:]...)
	}
	return fmt.Sprint(msg...)
}

// digits return amount of decimal digits in number.
func digits(number int) int {
	if number == 0 {
		return 1
	}
	return int(math.Floor(math.Log10(float64(number)) + 1))
}
