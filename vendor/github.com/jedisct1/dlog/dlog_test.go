package dlog

func Example() {
	Init("example", SeverityNotice, "")
	// Call flag.Parse() around that time
	Info("Application is starting")
	Debugf("Counter value: %d", 0)
	Fatal("Kaboom")
}
