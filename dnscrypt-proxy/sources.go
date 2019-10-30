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
	MinSourcesUpdateDelay = time.Duration(24) * time.Hour
)

type Source struct {
	urls        []string
	format      SourceFormat
	in          string
	minisignKey *minisign.PublicKey
}

func (source *Source) checkSignature(bin, sig string) (err error) {
	var signature minisign.Signature
	if signature, err = minisign.DecodeSignature(sig); err == nil {
		_, err = source.minisignKey.Verify([]byte(bin), signature)
	}
	return
}

// timeNow can be replaced by tests to provide a static value
var timeNow = time.Now

func fetchFromCache(cacheFile string, refreshDelay time.Duration) (in string, expired bool, delayTillNextUpdate time.Duration, err error) {
	expired = false
	delayTillNextUpdate = time.Duration(0)
	if refreshDelay < MinSourcesUpdateDelay {
		refreshDelay = MinSourcesUpdateDelay
	}
	fi, err := os.Stat(cacheFile)
	if err != nil {
		dlog.Debugf("Cache file [%s] not present", cacheFile)
		return
	}
	var bin []byte
	bin, err = ioutil.ReadFile(cacheFile)
	if err != nil {
		return
	}
	in = string(bin)
	elapsed := timeNow().Sub(fi.ModTime())
	if elapsed < refreshDelay {
		dlog.Debugf("Cache file [%s] is still fresh", cacheFile)
		delayTillNextUpdate = MinSourcesUpdateDelay - elapsed
	} else {
		dlog.Debugf("Cache file [%s] needs to be refreshed", cacheFile)
		expired = true
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

func fetchWithCache(xTransport *XTransport, urlStr string, cacheFile string, refreshDelay time.Duration) (in string, delayTillNextUpdate time.Duration, err error) {
	expired := false
	in, expired, delayTillNextUpdate, err = fetchFromCache(cacheFile, refreshDelay)
	if err == nil && !expired {
		dlog.Debugf("Delay till next update: %v", delayTillNextUpdate)
		return
	}
	if len(urlStr) == 0 {
		if !expired {
			err = fmt.Errorf("Cache file [%s] not present and no URL given to retrieve it", cacheFile)
		}
		return
	}

	dlog.Infof("Loading source information from URL [%s]", urlStr)

	var u *url.URL
	if u, err = url.Parse(urlStr); err != nil {
		return
	}
	var bin []byte
	if bin, err = fetchFromURL(xTransport, u); err != nil {
		return
	}
	if err = AtomicFileWrite(cacheFile, bin); err != nil {
		if absPath, err2 := filepath.Abs(cacheFile); err2 == nil {
			dlog.Warnf("%s: %s", absPath, err)
		}
	}
	in = string(bin)
	delayTillNextUpdate = MinSourcesUpdateDelay
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

func NewSource(xTransport *XTransport, urls []string, minisignKeyStr string, cacheFile string, formatStr string, refreshDelay time.Duration) (Source, []URLToPrefetch, error) {
	source := Source{urls: urls}
	if formatStr == "v2" {
		source.format = SourceFormatV2
	} else {
		return source, []URLToPrefetch{}, fmt.Errorf("Unsupported source format: [%s]", formatStr)
	}
	urlsToPrefetch := []URLToPrefetch{}
	if minisignKey, err := minisign.NewPublicKey(minisignKeyStr); err == nil {
		source.minisignKey = &minisignKey
	} else {
		return source, urlsToPrefetch, err
	}
	now := timeNow()
	sigCacheFile := cacheFile + ".minisig"

	var sigStr, in string
	var delayTillNextUpdate, sigDelayTillNextUpdate time.Duration
	var err, sigErr error
	var preloadURL string
	if len(urls) <= 0 {
		in, delayTillNextUpdate, err = fetchWithCache(xTransport, "", cacheFile, refreshDelay)
		sigStr, sigDelayTillNextUpdate, sigErr = fetchWithCache(xTransport, "", sigCacheFile, refreshDelay)
	} else {
		preloadURL = urls[0]
		for _, url := range urls {
			sigURL := url + ".minisig"
			in, delayTillNextUpdate, err = fetchWithCache(xTransport, url, cacheFile, refreshDelay)
			sigStr, sigDelayTillNextUpdate, sigErr = fetchWithCache(xTransport, sigURL, sigCacheFile, refreshDelay)
			if err == nil && sigErr == nil {
				preloadURL = url
				break
			}
			dlog.Infof("Loading from [%s] failed", url)
		}
	}
	if len(preloadURL) > 0 {
		url := preloadURL
		sigURL := url + ".minisig"
		urlsToPrefetch = append(urlsToPrefetch, URLToPrefetch{url: url, cacheFile: cacheFile, when: now.Add(delayTillNextUpdate)})
		urlsToPrefetch = append(urlsToPrefetch, URLToPrefetch{url: sigURL, cacheFile: sigCacheFile, when: now.Add(sigDelayTillNextUpdate)})
	}
	if sigErr != nil && err == nil {
		err = sigErr
	}
	if err != nil {
		return source, urlsToPrefetch, err
	}

	if err = source.checkSignature(in, sigStr); err != nil {
		return source, urlsToPrefetch, err
	}
	dlog.Noticef("Source [%s] loaded", cacheFile)
	source.in = in
	return source, urlsToPrefetch, nil
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
	_, delayTillNextUpdate, err := fetchWithCache(xTransport, urlToPrefetch.url, urlToPrefetch.cacheFile, MinSourcesUpdateDelay)
	urlToPrefetch.when = timeNow().Add(delayTillNextUpdate)
	return err
}
