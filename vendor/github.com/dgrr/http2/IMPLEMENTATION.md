# Implementation

A document that explains in detail how the client and the server works.

## Client implementation

The client holds (0, N) connections to a single host.
A connection is created in the following cases:
- There are no previous existing connections.
- All the connections are busy (aka not able to open more streams).

Connections are stored in a list because it's the easiest way to keep elements.

When a connection is created 2 goroutines are spawned. One for reading
and dispatching events, and another for writing (either frames and requests).

The [read loop](https://github.com/dgrr/http2/blob/8cb32376c36f056fca0ec30854f3522005a777ac/conn.go#L357)
will read all the frames and handling only the ones carrying a StreamID.
Lower layers will handle everything related to Settings, WindowUpdate, Ping
and/or disconnection.

The [write loop](https://github.com/dgrr/http2/blob/8cb32376c36f056fca0ec30854f3522005a777ac/conn.go#L290)
will write the requests and frames. I like to separate both terms because the request
comes from fasthttp, and the `frames` is a term related to http2.

Why having 2 coroutines? As HTTP/2 is a replacement of HTTP/1.1, the equivalent
to opening a connection per request in HTTP/1 is the figure of the `frame` in HTTP/2.
As writing to the same connection might happen concurrently and thus, can invoke
errors, 2 coroutines are required, one for writing and another for reading
synchronously.

### How sending a request works?

When we send a request we write to a channel to the writeLoop coroutine with
all the data required, in this case we make use of the [Ctx](https://github.com/dgrr/http2/blob/8cb32376c36f056fca0ec30854f3522005a777ac/client.go#L26-L33)
structure.

That being sent, it gets received by the writeLoop coroutine, and then
it proceeds to [serialize and write](https://github.com/dgrr/http2/blob/8cb32376c36f056fca0ec30854f3522005a777ac/conn.go#L385)
into the connection the required frames, and after that [registers](https://github.com/dgrr/http2/blob/8cb32376c36f056fca0ec30854f3522005a777ac/conn.go#L321)
the StreamID into a shared map. This map is shared among the 'write' and 'read' loops.

In the meantime, the client [waits on a channel](https://github.com/dgrr/http2/blob/8cb32376c36f056fca0ec30854f3522005a777ac/client.go#L102)
for any error.

When we receive the response from the server, the readLoop will check if the StreamID
is on the shared map, and if so, it will [handle the response](https://github.com/dgrr/http2/blob/8cb32376c36f056fca0ec30854f3522005a777ac/conn.go#L559).
After the server finished sending the request, the readLoop will end the request
sending the result to the client. That result might be an error or just a `nil`
over the channel provided by the client.

After the request/response finished, the client will continue thus exiting the
`Do` function.