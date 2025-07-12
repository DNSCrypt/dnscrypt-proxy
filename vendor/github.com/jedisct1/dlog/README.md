[![](https://godoc.org/github.com/jedisct1/dlog?status.svg)](https://godoc.org/github.com/jedisct1/dlog)

# dlog

Go's standard logger is fairly limited. As result, kazilion alternatives loggers have been written.

All of these are wonderful. They can make your logs look colorful and pretty, buffer things in complicated ways, format data for ElasticSearch, and more.

Cool, but all I wanted is something super dumb, that just exposes `log.Info()`, `log.Error()` and a couple other standard levels.

I don't need a super flexible kitchen sink. Just something super basic and trivial to use. I just want it to handle different log levels, and be able to write simple logs to `stderr`, to a local file, to `syslog` and to the Windows event log.

So, here's one more logging library for Go. The dumbest of them all. Enjoy.
