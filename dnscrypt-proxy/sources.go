package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dchest/safefile"
	"github.com/jedisct1/dlog"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/jedisct1/go-minisign"
)

type SourceFormat int

const (
	SourceFormatV2 SourceFormat = iota
)

const (
	DefaultPrefetchDelay    = 24 * time.Hour
	MinimumPrefetchInterval = 10 * time.Minute
	MaxCacheTTL             = 168 * time.Hour // 7 days
)

// Source represents a DNS server list source with caching and signature verification.
type Source struct {
	sync.RWMutex
	name                    string
	urls                    []*url.URL
	format                  SourceFormat
	bin                     []byte
	minisignKey             *minisign.PublicKey
	cacheFile               string
	cacheTTL, prefetchDelay time.Duration
	refresh                 time.Time
	prefix                  string
}

// timeNow is a function variable that provides the current time.
// It can be replaced by tests to provide deterministic time values.
var (
	timeNowMu sync.RWMutex
	timeNow   = time.Now
)

// getCurrentTime safely retrieves the current time using the timeNow function.
func getCurrentTime() time.Time {
	timeNowMu.RLock()
	defer timeNowMu.RUnlock()
	return timeNow()
}

func (source *Source) checkSignature(bin, sig []byte) error {
	signature, err := minisign.DecodeSignature(string(sig))
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	if _, err := source.minisignKey.Verify(bin, signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func (source *Source) fetchFromCache() (time.Duration, error) {
	now := getCurrentTime()

	bin, err := os.ReadFile(source.cacheFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read cache file: %w", err)
	}

	sig, err := os.ReadFile(source.cacheFile + ".minisig")
	if err != nil {
		return 0, fmt.Errorf("failed to read signature file: %w", err)
	}

	if err := source.checkSignature(bin, sig); err != nil {
		return 0, err
	}

	source.Lock()
	source.bin = bin
	source.Unlock()

	fi, err := os.Stat(source.cacheFile)
	if err != nil {
		return 0, fmt.Errorf("failed to stat cache file: %w", err)
	}

	elapsed := now.Sub(fi.ModTime())
	if elapsed < source.cacheTTL {
		ttl := source.prefetchDelay - elapsed
		dlog.Debugf("Source [%s] cache file [%s] is still fresh, next update: %v", source.name, source.cacheFile, ttl)
		return ttl, nil
	}

	dlog.Debugf("Source [%s] cache file [%s] needs to be refreshed", source.name, source.cacheFile)
	return 0, nil
}

func writeSource(path string, bin, sig []byte) error {
	fSrc, err := safefile.Create(path, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create source file: %w", err)
	}
	defer fSrc.Close()

	fSig, err := safefile.Create(path+".minisig", 0o644)
	if err != nil {
		return fmt.Errorf("failed to create signature file: %w", err)
	}
	defer fSig.Close()

	if _, err := fSrc.Write(bin); err != nil {
		return fmt.Errorf("failed to write source data: %w", err)
	}

	if _, err := fSig.Write(sig); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	if err := fSrc.Commit(); err != nil {
		return fmt.Errorf("failed to commit source file: %w", err)
	}

	if err := fSig.Commit(); err != nil {
		return fmt.Errorf("failed to commit signature file: %w", err)
	}

	return nil
}

func (source *Source) updateCache(bin, sig []byte) {
	now := getCurrentTime()
	file := source.cacheFile
	absPath := file
	if resolved, err := filepath.Abs(file); err == nil {
		absPath = resolved
	}

	source.Lock()
	needsWrite := !bytes.Equal(source.bin, bin)
	source.Unlock()

	if needsWrite {
		if err := writeSource(file, bin, sig); err != nil {
			dlog.Warnf("Couldn't write cache file [%s]: %s", absPath, err)
		}
	}

	if err := os.Chtimes(file, now, now); err != nil {
		dlog.Warnf("Couldn't update cache file timestamps [%s]: %s", absPath, err)
	}

	source.Lock()
	source.bin = bin
	source.Unlock()
}

func (source *Source) parseURLs(urls []string) {
	for _, urlStr := range urls {
		srcURL, err := url.Parse(urlStr)
		if err != nil {
			dlog.Warnf("Source [%s] failed to parse URL [%s]: %v", source.name, urlStr, err)
			continue
		}
		source.urls = append(source.urls, srcURL)
	}
}

func fetchFromURL(xTransport *XTransport, u *url.URL) ([]byte, error) {
	bin, _, _, _, err := xTransport.GetWithCompression(u, "", DefaultTimeout)
	return bin, err
}

func (source *Source) fetchWithCache(xTransport *XTransport) (time.Duration, error) {
	now := getCurrentTime()

	ttl, err := source.fetchFromCache()
	if err != nil {
		if len(source.urls) == 0 {
			return 0, fmt.Errorf("source [%s] cache file [%s] not present and no valid URL: %w", source.name, source.cacheFile, err)
		}
		dlog.Debugf("Source [%s] cache file [%s] not present", source.name, source.cacheFile)
	}

	if len(source.urls) == 0 {
		return 0, err
	}

	if ttl > 0 {
		source.refresh = now.Add(ttl)
		return 0, nil
	}

	// Cache is stale or missing, fetch from URLs.
	ttl = MinimumPrefetchInterval
	source.refresh = now.Add(ttl)

	var bin, sig []byte
	var lastErr error

	for _, srcURL := range source.urls {
		dlog.Infof("Source [%s] loading from URL [%s]", source.name, srcURL)

		sigURL := new(url.URL)
		*sigURL = *srcURL
		sigURL.Path += ".minisig"

		bin, lastErr = fetchFromURL(xTransport, srcURL)
		if lastErr != nil {
			dlog.Debugf("Source [%s] failed to download from URL [%s]: %v", source.name, srcURL, lastErr)
			continue
		}

		sig, lastErr = fetchFromURL(xTransport, sigURL)
		if lastErr != nil {
			dlog.Debugf("Source [%s] failed to download signature from URL [%s]: %v", source.name, sigURL, lastErr)
			continue
		}

		lastErr = source.checkSignature(bin, sig)
		if lastErr != nil {
			dlog.Debugf("Source [%s] failed signature check using URL [%s]: %v", source.name, srcURL, lastErr)
			continue
		}

		// Valid signature found.
		break
	}

	if lastErr != nil {
		return 0, lastErr
	}

	source.updateCache(bin, sig)
	ttl = source.prefetchDelay
	source.refresh = now.Add(ttl)
	return ttl, nil
}

// NewSource creates and loads a new source using the given cacheFile and URLs,
// ensuring it has a valid minisign signature.
func NewSource(
	name string,
	xTransport *XTransport,
	urls []string,
	minisignKeyStr string,
	cacheFile string,
	formatStr string,
	refreshDelay time.Duration,
	cacheTTL time.Duration,
	prefix string,
) (*Source, error) {
	if refreshDelay < DefaultPrefetchDelay {
		refreshDelay = DefaultPrefetchDelay
	}
	if cacheTTL < refreshDelay {
		cacheTTL = refreshDelay
	}
	if cacheTTL > MaxCacheTTL {
		cacheTTL = MaxCacheTTL
	}

	source := &Source{
		name:          name,
		urls:          make([]*url.URL, 0, len(urls)),
		cacheFile:     cacheFile,
		cacheTTL:      cacheTTL,
		prefetchDelay: refreshDelay,
		prefix:        prefix,
	}

	if formatStr == "v2" {
		source.format = SourceFormatV2
	} else {
		return nil, fmt.Errorf("unsupported source format: [%s]", formatStr)
	}

	minisignKey, err := minisign.NewPublicKey(minisignKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid minisign key: %w", err)
	}
	source.minisignKey = &minisignKey

	source.parseURLs(urls)

	if _, err := source.fetchWithCache(xTransport); err != nil {
		return source, err
	}

	dlog.Noticef("Source [%s] loaded", name)
	return source, nil
}

// PrefetchSources downloads the latest versions of given sources,
// ensuring they have valid signatures before caching.
func PrefetchSources(xTransport *XTransport, sources []*Source) time.Duration {
	now := getCurrentTime()
	interval := MinimumPrefetchInterval

	for _, source := range sources {
		if source.refresh.IsZero() || source.refresh.After(now) {
			continue
		}

		dlog.Debugf("Prefetching [%s]", source.name)
		delay, err := source.fetchWithCache(xTransport)
		if err != nil {
			dlog.Infof("Prefetching [%s] failed: %v, will retry in %v", source.name, err, interval)
			continue
		}

		dlog.Debugf("Prefetching [%s] succeeded, next update in %v", source.name, delay)
		if delay >= MinimumPrefetchInterval && (interval == MinimumPrefetchInterval || interval > delay) {
			interval = delay
		}
	}

	return interval
}

// Parse parses the source data and returns a list of registered servers.
func (source *Source) Parse() ([]RegisteredServer, error) {
	if source.format == SourceFormatV2 {
		return source.parseV2()
	}
	return nil, errors.New("unexpected source format")
}

func (source *Source) parseV2() ([]RegisteredServer, error) {
	var stampErrs []string

	appendStampErr := func(format string, a ...any) {
		stampErr := fmt.Sprintf(format, a...)
		stampErrs = append(stampErrs, stampErr)
		dlog.Warn(stampErr)
	}

	source.RLock()
	binCopy := make([]byte, len(source.bin))
	copy(binCopy, source.bin)
	source.RUnlock()

	in := string(binCopy)
	parts := strings.Split(in, "## ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid format for source at [%v]", source.urls)
	}

	parts = parts[1:] // Skip preamble.

	registeredServers := make([]RegisteredServer, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		subparts := strings.Split(part, "\n")
		if len(subparts) < 2 {
			return nil, fmt.Errorf("invalid format for source at [%v]", source.urls)
		}

		name := strings.TrimSpace(subparts[0])
		if name == "" {
			return nil, fmt.Errorf("invalid format for source at [%v]", source.urls)
		}
		name = source.prefix + name
		subparts = subparts[1:]

		var description string
		stampStrs := make([]string, 0, 2)

		for _, subpart := range subparts {
			subpart = strings.TrimSpace(subpart)
			if strings.HasPrefix(subpart, "sdns:") && len(subpart) >= 6 {
				stampStrs = append(stampStrs, subpart)
			} else if len(subpart) == 0 || strings.HasPrefix(subpart, "//") {
				continue
			} else {
				if len(description) > 0 {
					description += "\n"
				}
				description += subpart
			}
		}

		if len(stampStrs) == 0 {
			appendStampErr("Missing stamp for server [%s]", name)
			continue
		}

		if len(stampStrs) > 1 {
			rand.Shuffle(len(stampStrs), func(i, j int) {
				stampStrs[i], stampStrs[j] = stampStrs[j], stampStrs[i]
			})
		}

		var stamp dnsstamps.ServerStamp
		var stampStr string
		var lastErr error

		for _, stampStr = range stampStrs {
			stamp, lastErr = dnsstamps.NewServerStampFromString(stampStr)
			if lastErr == nil {
				break
			}
			appendStampErr("Invalid or unsupported stamp [%v]: %s", stampStr, lastErr.Error())
		}

		if lastErr != nil {
			continue
		}

		registeredServer := RegisteredServer{
			name:        name,
			stamp:       stamp,
			description: description,
		}
		dlog.Debugf("Registered [%s] with stamp [%s]", name, stamp.String())
		registeredServers = append(registeredServers, registeredServer)
	}

	if len(stampErrs) > 0 {
		return registeredServers, fmt.Errorf("%s", strings.Join(stampErrs, ", "))
	}

	return registeredServers, nil
}
