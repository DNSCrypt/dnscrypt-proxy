godaemon
========

Daemonize Go applications with `exec()` instead of `fork()`. Read our [blog post](https://vividcortex.com/blog/2013/08/27/godaemon-a-library-to-daemonize-go-apps/) on the subject.

You can't daemonize the usual way in Go. Daemonizing is a Unix concept that requires
some [specific things](http://goo.gl/vTUsVy) you can't do
easily in Go. But you can still accomplish the same goals 
if you don't mind that your program will start copies of itself
several times, as opposed to using `fork()` the way many programmers are accustomed to doing.

It is somewhat controversial whether it's even a good idea to make programs daemonize themselves,
or how to do it correctly (and whether it's even possible to do correctly in Go).
Read [here](https://code.google.com/p/go/issues/detail?id=227),
[here](http://www.ryanday.net/2012/09/04/the-problem-with-a-golang-daemon/),
and [here](http://stackoverflow.com/questions/14537045/how-i-should-run-my-golang-process-in-background)
for more on this topic. However, at [VividCortex](https://vividcortex.com/) we do need to run one of our processes as a
daemon with the usual attributes of a daemon, and we chose the approach implemented in this package.

Because of the factors mentioned in the first link just given, you should take great care when
using this package's approach. It works for us, because we don't do anything like starting up
goroutines in our `init()` functions, or other things that are perfectly legal in Go in general.

## Getting Started

View the [package documentation](http://godoc.org/github.com/VividCortex/godaemon)
for details about how it works. Briefly, to make your program into a daemon,
do the following as soon as possible in your `main()` function:

```go
import (
	"github.com/VividCortex/godaemon"
)

func main() {
	godaemon.MakeDaemon(&godaemon.DaemonAttr{})
}
```

Use the `CaptureOutput` attribute if you need to capture your program's
standard output and standard error streams. In that case, the function returns
two valid readers (`io.Reader`) that you can read from the program itself.
That's particularly useful for functions that write error or diagnosis messages
right to the error output, which are normally lost in a daemon.

Use the `Files` attribute if you need to inherit open files into the daemon.
This is primarily intended for avoiding race conditions when holding locks on
those files (flocks). Releasing and re-acquiring locks between successive fork
calls opens up the chance for another program to steal the lock. However, by
declaring your file descriptors in the `Files` attribute, `MakeDaemon()` will
guarantee that locks are not released throughout the whole process. Your daemon
will inherit the file still holding the same locks, with no other process having
intervened in between. See the
[package documentation](http://godoc.org/github.com/VividCortex/godaemon) for
more details and sample code. (Note that you shouldn't use this feature to
inherit TTY descriptors; otherwise what you get is technically not a daemon.)


## Contribute

Contributions are welcome. Please open pull requests or issue reports!


## License

This repository is Copyright (c) 2013 VividCortex, Inc. All rights reserved.
It is licensed under the MIT license. Please see the LICENSE file for applicable
license terms.

## Authors

The primary author is [Gustavo Kristic](https://github.com/gkristic), with some
documentation and other minor contributions by others at VividCortex.

## History

An earlier version of this concept with a slightly different interface was
developed internally at VividCortex.

## Cats

A Go Daemon is a good thing, and so we present an angelic cat picture:

![Angelic Cat](http://f.cl.ly/items/2b0y0n3W2W1H0S1K3g0g/angelic-cat.jpg)
