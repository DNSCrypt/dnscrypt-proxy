package main

import (
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dchest/safefile"

	"github.com/jedisct1/dlog"
	"github.com/jedisct1/go-minisign"
)

type SourceFormat int

const (
	SourceFormatV1 = iota
)

const (
	SourcesUpdateDelayAfterFailure = time.Duration(1) * time.Minute
)

type Source struct {
	url    string
	format SourceFormat
	in     string
}

func fetchFromCache(cacheFile string) ([]byte, error) {
	dlog.Infof("Loading source information from cache file [%s]", cacheFile)
	return ioutil.ReadFile(cacheFile)
}

func fetchWithCache(url string, cacheFile string, refreshDelay time.Duration) (in string, cached bool, delayTillNextUpdate time.Duration, err error) {
	var bin []byte
	cached, usableCache, hotCache := false, false, false
	delayTillNextUpdate = refreshDelay
	fi, err := os.Stat(cacheFile)
	var elapsed time.Duration
	if err == nil {
		usableCache = true
		dlog.Debugf("Cache file present for [%s]", url)
		elapsed = time.Since(fi.ModTime())
		if elapsed < refreshDelay && elapsed >= 0 {
			hotCache = true
		}
	}
	if hotCache {
		bin, err = fetchFromCache(cacheFile)
		if err == nil {
			dlog.Debugf("Cache is still fresh for [%s]", url)
			cached = true
			delayTillNextUpdate = refreshDelay - elapsed
		}
	}
	if !cached {
		var resp *http.Response
		dlog.Infof("Loading source information from URL [%s]", url)
		resp, err = http.Get(url)
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = fmt.Errorf("Webserver returned code %d", resp.StatusCode)
		}
		if err != nil {
			delayTillNextUpdate = SourcesUpdateDelayAfterFailure
			if usableCache {
				dlog.Debugf("Falling back to cached version of [%s]", url)
				bin, err = fetchFromCache(cacheFile)
			}
			if err != nil {
				return
			}
		} else {
			bin, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				delayTillNextUpdate = SourcesUpdateDelayAfterFailure
				if usableCache {
					bin, err = fetchFromCache(cacheFile)
				}
				if err != nil {
					return
				}
			}
		}
	}
	err = nil
	in = string(bin)
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

func NewSource(url string, minisignKeyStr string, cacheFile string, formatStr string, refreshDelay time.Duration) (Source, []URLToPrefetch, error) {
	source := Source{url: url}
	if formatStr != "v1" {
		return source, []URLToPrefetch{}, fmt.Errorf("Unsupported source format: [%s]", formatStr)
	}
	source.format = SourceFormatV1
	minisignKey, err := minisign.NewPublicKey(minisignKeyStr)
	if err != nil {
		return source, []URLToPrefetch{}, err
	}
	sigURL := url + ".minisig"
	when := time.Now().Add(SourcesUpdateDelayAfterFailure)
	urlsToPrefetch := []URLToPrefetch{
		URLToPrefetch{url: url, cacheFile: cacheFile, when: when},
		URLToPrefetch{url: sigURL, cacheFile: cacheFile, when: when},
	}
	in, cached, delayTillNextUpdate, err := fetchWithCache(url, cacheFile, refreshDelay)
	if err != nil {
		return source, urlsToPrefetch, err
	}
	sigCacheFile := cacheFile + ".minisig"
	sigStr, sigCached, sigDelayTillNextUpdate, err := fetchWithCache(sigURL, sigCacheFile, refreshDelay)
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
			return source, urlsToPrefetch, err
		}
	}
	if !sigCached {
		if err = AtomicFileWrite(sigCacheFile, []byte(sigStr)); err != nil {
			return source, urlsToPrefetch, err
		}
	}
	dlog.Noticef("Source [%s] loaded", url)
	source.in = in
	if sigDelayTillNextUpdate < delayTillNextUpdate {
		delayTillNextUpdate = sigDelayTillNextUpdate
	}
	if delayTillNextUpdate < SourcesUpdateDelayAfterFailure {
		delayTillNextUpdate = SourcesUpdateDelayAfterFailure
	}
	when = time.Now().Add(delayTillNextUpdate)
	urlsToPrefetch = []URLToPrefetch{}
	return source, urlsToPrefetch, nil
}

func (source *Source) Parse() ([]RegisteredServer, error) {
	var registeredServers []RegisteredServer

	csvReader := csv.NewReader(strings.NewReader(source.in))
	records, err := csvReader.ReadAll()
	if err != nil {
		return registeredServers, nil
	}
	for lineNo, record := range records {
		if len(record) == 0 {
			continue
		}
		if len(record) < 14 {
			return registeredServers, fmt.Errorf("Parse error at line %d", 1+lineNo)
		}
		if lineNo == 0 {
			continue
		}
		name := record[0]
		serverAddrStr := record[10]
		providerName := record[11]
		serverPkStr := record[12]
		props := ServerInformalProperties(0)
		if strings.EqualFold(record[7], "yes") {
			props |= ServerInformalPropertyDNSSEC
		}
		if strings.EqualFold(record[8], "yes") {
			props |= ServerInformalPropertyNoLog
		}
		stamp, err := NewServerStampFromLegacy(serverAddrStr, serverPkStr, providerName, props)
		if err != nil {
			return registeredServers, err
		}
		registeredServer := RegisteredServer{
			name: name, stamp: stamp,
		}
		registeredServers = append(registeredServers, registeredServer)
	}
	return registeredServers, nil
}

func PrefetchSourceURLs(urlsToPrefetch []URLToPrefetch) {
	if len(urlsToPrefetch) <= 0 {
		return
	}
	dlog.Infof("Prefetching %d source URLs", len(urlsToPrefetch))
	for _, urlToPrefetch := range urlsToPrefetch {
		if _, _, _, err := fetchWithCache(urlToPrefetch.url, urlToPrefetch.cacheFile, time.Duration(0)); err != nil {
			dlog.Debugf("[%s]: %s", urlToPrefetch.url, err)
		}
	}
}
