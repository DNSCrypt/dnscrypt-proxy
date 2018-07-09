package main

import (
	"errors"
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
	SourcesUpdateDelay = time.Duration(24) * time.Hour
)

type Source struct {
	urls   []string
	format SourceFormat
	in     string
}

func fetchFromCache(cacheFile string) (in string, expired bool, delayTillNextUpdate time.Duration, err error) {
	expired = false
	fi, err := os.Stat(cacheFile)
	if err != nil {
		dlog.Debugf("Cache file [%s] not present", cacheFile)
		delayTillNextUpdate = time.Duration(0)
		return
	}
	elapsed := time.Since(fi.ModTime())
	if elapsed < SourcesUpdateDelay {
		dlog.Debugf("Cache file [%s] is still fresh", cacheFile)
		delayTillNextUpdate = SourcesUpdateDelay - elapsed
	} else {
		dlog.Debugf("Cache file [%s] needs to be refreshed", cacheFile)
		delayTillNextUpdate = time.Duration(0)
	}
	var bin []byte
	bin, err = ioutil.ReadFile(cacheFile)
	if err != nil {
		delayTillNextUpdate = time.Duration(0)
		return
	}
	in = string(bin)
	if delayTillNextUpdate <= time.Duration(0) {
		expired = true
	}
	return
}

func fetchWithCache(xTransport *XTransport, urlStr string, cacheFile string) (in string, cached bool, delayTillNextUpdate time.Duration, err error) {
	cached = false
	expired := false
	in, expired, delayTillNextUpdate, err = fetchFromCache(cacheFile)
	if err == nil && !expired {
		dlog.Debugf("Delay till next update: %v", delayTillNextUpdate)
		cached = true
		return
	}
	if expired {
		cached = true
	}
	if len(urlStr) == 0 {
		if !expired {
			err = fmt.Errorf("Cache file [%s] not present and no URL given to retrieve it", cacheFile)
		}
		return
	}

	var resp *http.Response
	dlog.Infof("Loading source information from URL [%s]", urlStr)

	url, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	resp, _, err = xTransport.Get(url, "", 30*time.Second)
	if err == nil && resp != nil && (resp.StatusCode < 200 || resp.StatusCode > 299) {
		err = fmt.Errorf("Webserver returned code %d", resp.StatusCode)
		return
	} else if err != nil {
		return
	} else if resp == nil {
		err = errors.New("Webserver returned an error")
		return
	}
	var bin []byte
	bin, err = ioutil.ReadAll(io.LimitReader(resp.Body, MaxHTTPBodyLength))
	resp.Body.Close()
	if err != nil {
		return
	}
	err = nil
	cached = false
	in = string(bin)
	delayTillNextUpdate = SourcesUpdateDelay
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
	_ = refreshDelay
	source := Source{urls: urls}
	if formatStr == "v2" {
		source.format = SourceFormatV2
	} else {
		return source, []URLToPrefetch{}, fmt.Errorf("Unsupported source format: [%s]", formatStr)
	}
	minisignKey, err := minisign.NewPublicKey(minisignKeyStr)
	if err != nil {
		return source, []URLToPrefetch{}, err
	}
	now := time.Now()
	urlsToPrefetch := []URLToPrefetch{}
	sigCacheFile := cacheFile + ".minisig"

	var sigStr, in string
	var cached, sigCached bool
	var delayTillNextUpdate, sigDelayTillNextUpdate time.Duration
	var sigErr error
	var preloadURL string
	if len(urls) <= 0 {
		in, cached, delayTillNextUpdate, err = fetchWithCache(xTransport, "", cacheFile)
		sigStr, sigCached, sigDelayTillNextUpdate, sigErr = fetchWithCache(xTransport, "", sigCacheFile)
	} else {
		preloadURL = urls[0]
		for _, url := range urls {
			sigURL := url + ".minisig"
			in, cached, delayTillNextUpdate, err = fetchWithCache(xTransport, url, cacheFile)
			sigStr, sigCached, sigDelayTillNextUpdate, sigErr = fetchWithCache(xTransport, sigURL, sigCacheFile)
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

	signature, err := minisign.DecodeSignature(sigStr)
	if err != nil {
		os.Remove(cacheFile)
		os.Remove(sigCacheFile)
		return source, urlsToPrefetch, err
	}
	res, err := minisignKey.Verify([]byte(in), signature)
	if err != nil || !res {
		os.Remove(cacheFile)
		os.Remove(sigCacheFile)
		return source, urlsToPrefetch, err
	}
	if !cached {
		if err = AtomicFileWrite(cacheFile, []byte(in)); err != nil {
			if absPath, err2 := filepath.Abs(cacheFile); err2 == nil {
				dlog.Warnf("%s: %s", absPath, err)
			}
		}
	}
	if !sigCached {
		if err = AtomicFileWrite(sigCacheFile, []byte(sigStr)); err != nil {
			if absPath, err2 := filepath.Abs(sigCacheFile); err2 == nil {
				dlog.Warnf("%s: %s", absPath, err)
			}
		}
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
	in := string(source.in)
	parts := strings.Split(in, "## ")
	if len(parts) < 2 {
		return registeredServers, fmt.Errorf("Invalid format for source at [%v]", source.urls)
	}
	parts = parts[1:]
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
			if strings.HasPrefix(subpart, "sdns://") {
				if len(stampStr) > 0 {
					return registeredServers, fmt.Errorf("Multiple stamps for server [%s] in source from [%v]", name, source.urls)
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
		if len(stampStr) < 8 {
			return registeredServers, fmt.Errorf("Missing stamp for server [%s] in source from [%v]", name, source.urls)
		}
		stamp, err := stamps.NewServerStampFromString(stampStr)
		if err != nil {
			dlog.Errorf("Invalid or unsupported stamp: [%v]", stampStr)
			return registeredServers, err
		}
		registeredServer := RegisteredServer{
			name: name, stamp: stamp, description: description,
		}
		dlog.Debugf("Registered [%s] with stamp [%s]", name, stamp.String())
		registeredServers = append(registeredServers, registeredServer)
	}
	return registeredServers, nil
}

func PrefetchSourceURL(xTransport *XTransport, urlToPrefetch *URLToPrefetch) error {
	in, cached, delayTillNextUpdate, err := fetchWithCache(xTransport, urlToPrefetch.url, urlToPrefetch.cacheFile)
	if err == nil && !cached {
		AtomicFileWrite(urlToPrefetch.cacheFile, []byte(in))
	}
	urlToPrefetch.when = time.Now().Add(delayTillNextUpdate)
	return err
}
