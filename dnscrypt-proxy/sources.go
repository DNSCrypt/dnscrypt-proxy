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
	urls                    []string
	prefetch                []*URLToPrefetch
	format                  SourceFormat
	in                      []byte
	minisignKey             *minisign.PublicKey
	cacheFile               string
	cacheTTL, prefetchDelay time.Duration
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

func (source *Source) fetchFromCache() (bin, sig []byte, delayTillNextUpdate time.Duration, err error) {
	delayTillNextUpdate = 0
	var fi os.FileInfo
	if fi, err = os.Stat(source.cacheFile); err != nil {
		return
	}
	if bin, err = ioutil.ReadFile(source.cacheFile); err != nil {
		return
	}
	if sig, err = ioutil.ReadFile(source.cacheFile + ".minisig"); err != nil {
		return
	}
	if elapsed := timeNow().Sub(fi.ModTime()); elapsed < source.cacheTTL {
		dlog.Debugf("Cache file [%s] is still fresh", source.cacheFile)
		delayTillNextUpdate = source.prefetchDelay - elapsed
	} else {
		dlog.Debugf("Cache file [%s] needs to be refreshed", source.cacheFile)
	}
	return
}

func (source *Source) writeToCache(bin, sig []byte) (err error) {
	f := source.cacheFile
	defer func() {
		if err != nil {
			if absPath, err2 := filepath.Abs(f); err2 == nil {
				f = absPath
			}
			dlog.Warnf("%s: %s", f, err)
		}
	}()
	if err = safefile.WriteFile(f, bin, 0644); err != nil {
		return
	}
	if err = safefile.WriteFile(f+".minisig", sig, 0644); err != nil {
		return
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

func (source *Source) fetchWithCache(xTransport *XTransport, urlStr string) (bin, sig []byte, delayTillNextUpdate time.Duration, err error) {
	if bin, sig, delayTillNextUpdate, err = source.fetchFromCache(); err != nil {
		if len(urlStr) == 0 {
			dlog.Errorf("Cache file [%s] not present and no URL given to retrieve it", source.cacheFile)
			return
		}
		dlog.Debugf("Cache file [%s] not present", source.cacheFile)
	}
	if err == nil && delayTillNextUpdate > 0 {
		dlog.Debugf("Delay till next update: %v", delayTillNextUpdate)
		return
	}

	dlog.Infof("Loading source information from URL [%s]", urlStr)

	var srcURL *url.URL
	if srcURL, err = url.Parse(urlStr); err != nil {
		return
	}
	sigURL := &url.URL{}
	*sigURL = *srcURL // deep copy to avoid parsing twice
	sigURL.Path += ".minisig"
	if bin, err = fetchFromURL(xTransport, srcURL); err != nil {
		return
	}
	if sig, err = fetchFromURL(xTransport, sigURL); err != nil {
		return
	}
	source.writeToCache(bin, sig) // ignore error: not fatal
	delayTillNextUpdate = source.prefetchDelay
	return
}

type URLToPrefetch struct {
	url  string
	when time.Time
}

func NewSource(xTransport *XTransport, urls []string, minisignKeyStr string, cacheFile string, formatStr string, refreshDelay time.Duration) (source *Source, err error) {
	if refreshDelay < DefaultPrefetchDelay {
		refreshDelay = DefaultPrefetchDelay
	}
	source = &Source{urls: urls, cacheFile: cacheFile, cacheTTL: refreshDelay, prefetchDelay: DefaultPrefetchDelay}
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
		bin, sig, delayTillNextUpdate, err = source.fetchWithCache(xTransport, "")
	} else {
		preloadURL = urls[0]
		for _, url := range urls {
			bin, sig, delayTillNextUpdate, err = source.fetchWithCache(xTransport, url)
			if err == nil {
				preloadURL = url
				break
			}
			dlog.Infof("Loading from [%s] failed", url)
		}
	}
	if len(preloadURL) > 0 {
		url := preloadURL
		source.prefetch = append(source.prefetch, &URLToPrefetch{url: url, when: now.Add(delayTillNextUpdate)})
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
				_, _, delay, err := source.fetchWithCache(xTransport, urlToPrefetch.url)
				if err != nil {
					dlog.Debugf("Prefetching [%s] failed: %v", urlToPrefetch.url, err)
					continue
				}
				dlog.Debugf("Prefetching [%s] succeeded. Next refresh scheduled for %v", urlToPrefetch.url, urlToPrefetch.when)
				urlToPrefetch.when = now.Add(delay)
				if delay >= MinimumPrefetchInterval && (interval == MinimumPrefetchInterval || interval > delay) {
					interval = delay
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
