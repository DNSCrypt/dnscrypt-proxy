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
	name                    string
	urls                    []string
	format                  SourceFormat
	in                      []byte
	minisignKey             *minisign.PublicKey
	cacheFile               string
	cacheTTL, prefetchDelay time.Duration
	refresh                 time.Time
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

func (source *Source) fetchFromCache() (delay time.Duration, err error) {
	var bin, sig []byte
	if bin, err = ioutil.ReadFile(source.cacheFile); err != nil {
		return
	}
	if sig, err = ioutil.ReadFile(source.cacheFile + ".minisig"); err != nil {
		return
	}
	if err = source.checkSignature(bin, sig); err != nil {
		return
	}
	source.in = bin
	var fi os.FileInfo
	if fi, err = os.Stat(source.cacheFile); err != nil {
		return
	}
	if elapsed := timeNow().Sub(fi.ModTime()); elapsed < source.cacheTTL {
		delay = source.prefetchDelay - elapsed
		dlog.Debugf("Source [%s] cache file [%s] is still fresh, next update: %v", source.name, source.cacheFile, delay)
	} else {
		dlog.Debugf("Source [%s] cache file [%s] needs to be refreshed", source.name, source.cacheFile)
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

func (source *Source) fetchWithCache(xTransport *XTransport, urlStr string) (delay time.Duration, err error) {
	if delay, err = source.fetchFromCache(); err != nil {
		if len(urlStr) == 0 {
			dlog.Errorf("Source [%s] cache file [%s] not present and no URL given", source.name, source.cacheFile)
			return
		}
		dlog.Debugf("Source [%s] cache file [%s] not present", source.name, source.cacheFile)
	}
	if delay > 0 {
		return
	}
	delay = MinimumPrefetchInterval
	dlog.Infof("Source [%s] loading from URL [%s]", source.name, urlStr)

	var srcURL *url.URL
	if srcURL, err = url.Parse(urlStr); err != nil {
		return
	}
	sigURL := &url.URL{}
	*sigURL = *srcURL // deep copy to avoid parsing twice
	sigURL.Path += ".minisig"
	var bin, sig []byte
	if bin, err = fetchFromURL(xTransport, srcURL); err != nil {
		return
	}
	if sig, err = fetchFromURL(xTransport, sigURL); err != nil {
		return
	}
	if err = source.checkSignature(bin, sig); err != nil {
		return
	}
	source.in = bin
	source.writeToCache(bin, sig) // ignore error: not fatal
	delay = source.prefetchDelay
	return
}

// NewSource loads a new source using the given cacheFile and urls, ensuring it has a valid signature
func NewSource(name string, xTransport *XTransport, urls []string, minisignKeyStr string, cacheFile string, formatStr string, refreshDelay time.Duration) (source *Source, err error) {
	if refreshDelay < DefaultPrefetchDelay {
		refreshDelay = DefaultPrefetchDelay
	}
	source = &Source{name: name, urls: urls, cacheFile: cacheFile, cacheTTL: refreshDelay, prefetchDelay: DefaultPrefetchDelay}
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

	var delay time.Duration
	if len(urls) <= 0 {
		delay, err = source.fetchWithCache(xTransport, "")
	} else {
		for _, url := range urls {
			delay, err = source.fetchWithCache(xTransport, url)
			if err == nil {
				break
			}
			dlog.Infof("Source [%s] failed to load from [%s]", name, url)
		}
		source.refresh = now.Add(delay)
	}
	if err != nil {
		return
	}
	dlog.Noticef("Source [%s] loaded", name)
	return
}

// PrefetchSources downloads latest versions of given sources, ensuring they have a valid signature before caching
func PrefetchSources(xTransport *XTransport, sources []*Source) time.Duration {
	now := timeNow()
	interval := MinimumPrefetchInterval
	for _, source := range sources {
		if source.refresh.IsZero() || source.refresh.After(now) {
			continue
		}
		dlog.Debugf("Prefetching [%s]", source.name)
		for _, u := range source.urls {
			if delay, err := source.fetchWithCache(xTransport, u); err != nil {
				dlog.Debugf("Prefetching [%s] from [%s] failed: %v", source.name, u, err)
			} else {
				dlog.Debugf("Prefetching [%s] succeeded, next update: %v", source.name, delay)
				source.refresh = now.Add(delay)
				if delay >= MinimumPrefetchInterval && (interval == MinimumPrefetchInterval || interval > delay) {
					interval = delay
				}
				break
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
