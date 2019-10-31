package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/dchest/safefile"

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/jedisct1/go-minisign"
)

type SourceFormat int

const (
	SourceFormatV2 = iota
)

const (
	DefaultPrefetchDelay    time.Duration = 24 * time.Hour
	MinimumPrefetchInterval time.Duration = 10 * time.Minute
)

type Source struct {
	urls        []string
	prefetch    []*URLToPrefetch
	format      SourceFormat
	in          []byte
	minisignKey *minisign.PublicKey
}

func (source *Source) checkSignature(bin, sig []byte) (err error) {
	var signature minisign.Signature
	if signature, err = minisign.DecodeSignature(string(sig)); err == nil {
		_, err = source.minisignKey.Verify(bin, signature)
	}
	return
}

// timeNow can be replaced by tests to provide a static value
var timeNow = time.Now

func fetchFromCache(cacheFile string, refreshDelay time.Duration) (bin, sig []byte, delayTillNextUpdate time.Duration, err error) {
	delayTillNextUpdate = time.Duration(0)
	if refreshDelay < DefaultPrefetchDelay {
		refreshDelay = DefaultPrefetchDelay
	}
	var fi os.FileInfo
	if fi, err = os.Stat(cacheFile); err != nil {
		return
	}
	if bin, err = ioutil.ReadFile(cacheFile); err != nil {
		return
	}
	if sig, err = ioutil.ReadFile(cacheFile + ".minisig"); err != nil {
		return
	}
	if elapsed := timeNow().Sub(fi.ModTime()); elapsed < refreshDelay {
		dlog.Debugf("Cache file [%s] is still fresh", cacheFile)
		delayTillNextUpdate = DefaultPrefetchDelay - elapsed
	} else {
		dlog.Debugf("Cache file [%s] needs to be refreshed", cacheFile)
	}
	return
}

func fetchFromURL(xTransport *XTransport, u *url.URL) (bin []byte, err error) {
	var resp *http.Response
	if resp, _, err = xTransport.Get(u, "", DefaultTimeout); err == nil {
		bin, err = ioutil.ReadAll(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		resp.Body.Close()
	}
	return
}

func fetchWithCache(xTransport *XTransport, urlStr string, cacheFile string, refreshDelay time.Duration) (bin, sig []byte, delayTillNextUpdate time.Duration, err error) {
	if bin, sig, delayTillNextUpdate, err = fetchFromCache(cacheFile, refreshDelay); err != nil {
		if len(urlStr) == 0 {
			dlog.Errorf("Cache file [%s] not present and no URL given to retrieve it", cacheFile)
			return
		}
		dlog.Debugf("Cache file [%s] not present", cacheFile)
	}
	if err == nil && delayTillNextUpdate > 0 {
		dlog.Debugf("Delay till next update: %v", delayTillNextUpdate)
		return
	}

	dlog.Infof("Loading source information from URL [%s]", urlStr)

	var srcURL, sigURL *url.URL
	if srcURL, err = url.Parse(urlStr); err != nil {
		return
	}
	if sigURL, err = url.Parse(urlStr + ".minisig"); err != nil {
		return
	}
	if bin, err = fetchFromURL(xTransport, srcURL); err != nil {
		return
	}
	if sig, err = fetchFromURL(xTransport, sigURL); err != nil {
		return
	}
	if err = AtomicFileWrite(cacheFile, bin); err != nil {
		if absPath, err2 := filepath.Abs(cacheFile); err2 == nil {
			dlog.Warnf("%s: %s", absPath, err)
		}
	}
	if err = AtomicFileWrite(cacheFile+".minisig", sig); err != nil {
		if absPath, err2 := filepath.Abs(cacheFile + ".minisig"); err2 == nil {
			dlog.Warnf("%s: %s", absPath, err)
		}
	}
	delayTillNextUpdate = DefaultPrefetchDelay
	return
}

func AtomicFileWrite(file string, data []byte) error {
	return safefile.WriteFile(file, data, 0644)
}

type URLToPrefetch struct {
	url       string
	cacheFile string
	when      time.Time
}

func NewSource(xTransport *XTransport, urls []string, minisignKeyStr string, cacheFile string, formatStr string, refreshDelay time.Duration) (source *Source, err error) {
	source = &Source{urls: urls}
	if formatStr == "v2" {
		source.format = SourceFormatV2
	} else {
		return source, fmt.Errorf("Unsupported source format: [%s]", formatStr)
	}
	if minisignKey, err := minisign.NewPublicKey(minisignKeyStr); err == nil {
		source.minisignKey = &minisignKey
	} else {
		return source, err
	}
	now := timeNow()
	source.prefetch = []*URLToPrefetch{}

	var bin, sig []byte
	var delayTillNextUpdate time.Duration
	var preloadURL string
	if len(urls) <= 0 {
		bin, sig, delayTillNextUpdate, err = fetchWithCache(xTransport, "", cacheFile, refreshDelay)
	} else {
		preloadURL = urls[0]
		for _, url := range urls {
			bin, sig, delayTillNextUpdate, err = fetchWithCache(xTransport, url, cacheFile, refreshDelay)
			if err == nil {
				preloadURL = url
				break
			}
			dlog.Infof("Loading from [%s] failed", url)
		}
	}
	if len(preloadURL) > 0 {
		url := preloadURL
		source.prefetch = append(source.prefetch, &URLToPrefetch{url: url, cacheFile: cacheFile, when: now.Add(delayTillNextUpdate)})
	}
	if err != nil {
		return
	}

	if err = source.checkSignature(bin, sig); err != nil {
		return
	}
	dlog.Noticef("Source [%s] loaded", cacheFile)
	source.in = bin
	return
}

func PrefetchSources(xTransport *XTransport, sources []*Source) time.Duration {
	now := timeNow()
	interval := MinimumPrefetchInterval
	for _, source := range sources {
		for _, urlToPrefetch := range source.prefetch {
			if now.After(urlToPrefetch.when) {
				dlog.Debugf("Prefetching [%s]", urlToPrefetch.url)
				if err := PrefetchSourceURL(xTransport, urlToPrefetch); err != nil {
					dlog.Debugf("Prefetching [%s] failed: %s", urlToPrefetch.url, err)
				} else {
					dlog.Debugf("Prefetching [%s] succeeded. Next refresh scheduled for %v", urlToPrefetch.url, urlToPrefetch.when)
					delay := urlToPrefetch.when.Sub(now)
					if delay >= MinimumPrefetchInterval && (interval == MinimumPrefetchInterval || interval > delay) {
						interval = delay
					}
				}
			}
		}
	}
	return interval
}

func (source *Source) Parse(prefix string) ([]RegisteredServer, error) {
	if source.format == SourceFormatV2 {
		return source.parseV2(prefix)
	}
	dlog.Fatal("Unexpected source format")
	return []RegisteredServer{}, nil
}

func (source *Source) parseV2(prefix string) ([]RegisteredServer, error) {
	var registeredServers []RegisteredServer
	var stampErrs []string
	appendStampErr := func(format string, a ...interface{}) {
		stampErr := fmt.Sprintf(format, a...)
		stampErrs = append(stampErrs, stampErr)
		dlog.Warn(stampErr)
	}
	in := string(source.in)
	parts := strings.Split(in, "## ")
	if len(parts) < 2 {
		return registeredServers, fmt.Errorf("Invalid format for source at [%v]", source.urls)
	}
	parts = parts[1:]
PartsLoop:
	for _, part := range parts {
		part = strings.TrimFunc(part, unicode.IsSpace)
		subparts := strings.Split(part, "\n")
		if len(subparts) < 2 {
			return registeredServers, fmt.Errorf("Invalid format for source at [%v]", source.urls)
		}
		name := strings.TrimFunc(subparts[0], unicode.IsSpace)
		if len(name) == 0 {
			return registeredServers, fmt.Errorf("Invalid format for source at [%v]", source.urls)
		}
		subparts = subparts[1:]
		name = prefix + name
		var stampStr, description string
		for _, subpart := range subparts {
			subpart = strings.TrimFunc(subpart, unicode.IsSpace)
			if strings.HasPrefix(subpart, "sdns:") {
				if len(stampStr) > 0 {
					appendStampErr("Multiple stamps for server [%s]", name)
					continue PartsLoop
				}
				stampStr = subpart
				continue
			} else if len(subpart) == 0 || strings.HasPrefix(subpart, "//") {
				continue
			}
			if len(description) > 0 {
				description += "\n"
			}
			description += subpart
		}
		if len(stampStr) < 6 {
			appendStampErr("Missing stamp for server [%s]", name)
			continue
		}
		stamp, err := stamps.NewServerStampFromString(stampStr)
		if err != nil {
			appendStampErr("Invalid or unsupported stamp [%v]: %s", stampStr, err.Error())
			continue
		}
		registeredServer := RegisteredServer{
			name: name, stamp: stamp, description: description,
		}
		dlog.Debugf("Registered [%s] with stamp [%s]", name, stamp.String())
		registeredServers = append(registeredServers, registeredServer)
	}
	if len(stampErrs) > 0 {
		return registeredServers, fmt.Errorf("%s", strings.Join(stampErrs, ", "))
	}
	return registeredServers, nil
}

func PrefetchSourceURL(xTransport *XTransport, urlToPrefetch *URLToPrefetch) error {
	_, _, delayTillNextUpdate, err := fetchWithCache(xTransport, urlToPrefetch.url, urlToPrefetch.cacheFile, DefaultPrefetchDelay)
	urlToPrefetch.when = timeNow().Add(delayTillNextUpdate)
	return err
}
