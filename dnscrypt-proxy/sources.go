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

type Source struct {
	url    string
	format SourceFormat
	in     string
}

func fetchFromCache(cacheFile string) ([]byte, error) {
	dlog.Infof("Loading source information from cache file [%s]", cacheFile)
	return ioutil.ReadFile(cacheFile)
}

func fetchWithCache(url string, cacheFile string, refreshDelay time.Duration) (in string, cached bool, err error) {
	var bin []byte
	cached, usableCache := false, false
	fi, err := os.Stat(cacheFile)
	if err == nil {
		elapsed := time.Since(fi.ModTime())
		if elapsed < refreshDelay && elapsed >= 0 {
			usableCache = true
		}
	}
	if usableCache {
		bin, err = fetchFromCache(cacheFile)
		if err == nil {
			cached = true
		}
	}
	if !cached {
		var resp *http.Response
		dlog.Infof("Loading source information from URL [%s]", url)
		resp, err = http.Get(url)
		if err != nil {
			if usableCache {
				bin, err = fetchFromCache(cacheFile)
			}
			if err != nil {
				return
			}
		} else {
			bin, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				if usableCache {
					bin, err = fetchFromCache(cacheFile)
				}
				if err != nil {
					return
				}
			}
		}
	}
	in = string(bin)
	return
}

func AtomicFileWrite(file string, data []byte) error {
	return safefile.WriteFile(file, data, 0644)
}

func NewSource(url string, minisignKeyStr string, cacheFile string, formatStr string, refreshDelay time.Duration) (Source, error) {
	source := Source{url: url}
	if formatStr != "v1" {
		return source, fmt.Errorf("Unsupported source format: [%s]", formatStr)
	}
	source.format = SourceFormatV1
	minisignKey, err := minisign.NewPublicKey(minisignKeyStr)
	if err != nil {
		return source, err
	}
	in, cached, err := fetchWithCache(url, cacheFile, refreshDelay)
	if err != nil {
		return source, err
	}
	sigCacheFile := cacheFile + ".minisig"
	sigURL := url + ".minisig"
	sigStr, sigCached, err := fetchWithCache(sigURL, sigCacheFile, refreshDelay)
	if err != nil {
		return source, err
	}
	signature, err := minisign.DecodeSignature(sigStr)
	if err != nil {
		return source, err
	}
	res, err := minisignKey.Verify([]byte(in), signature)
	if err != nil || res != true {
		return source, err
	}
	if cached == false {
		if err = AtomicFileWrite(cacheFile, []byte(in)); err != nil {
			return source, err
		}
	}
	if sigCached == false {
		if err = AtomicFileWrite(sigCacheFile, []byte(sigStr)); err != nil {
			return source, err
		}
	}
	dlog.Noticef("Source [%s] loaded", url)
	source.in = in
	return source, nil
}

func (source *Source) Parse() ([]RegisteredServer, error) {
	var registeredServers []RegisteredServer

	csvReader := csv.NewReader(strings.NewReader(source.in))
	records, err := csvReader.ReadAll()
	if err != nil {
		return registeredServers, nil
	}
	for line, record := range records {
		if len(record) == 0 {
			continue
		}
		if len(record) < 14 {
			return registeredServers, fmt.Errorf("Parse error at line %d", line)
		}
		if line == 0 {
			continue
		}
		name := record[0]
		serverAddrStr := record[10]
		providerName := record[11]
		serverPkStr := record[12]
		stamp, err := NewServerStampFromLegacy(serverAddrStr, serverPkStr, providerName)
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
