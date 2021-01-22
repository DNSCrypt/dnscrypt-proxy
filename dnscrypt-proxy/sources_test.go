package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hectane/go-acl"
	"github.com/powerman/check"

	"github.com/jedisct1/go-minisign"
)

type SourceFixture struct {
	suffix  string
	content []byte
	length  string // HTTP Content-Length header
	perms   os.FileMode
	mtime   time.Time
}
type SourceTestState uint8

const (
	TestStateCorrect    SourceTestState = iota // valid files
	TestStateExpired                           // modification time of files set in distant past (cache only)
	TestStatePartial                           // incomplete files
	TestStatePartialSig                        // incomplete .minisig
	TestStateMissing                           // non-existent files
	TestStateMissingSig                        // non-existent .minisig
	TestStateReadErr                           // I/O error on reading files (download only)
	TestStateReadSigErr                        // I/O error on reading .minisig (download only)
	TestStateOpenErr                           // I/O error on opening files
	TestStateOpenSigErr                        // I/O error on opening .minisig
	TestStatePathErr                           // unparseable path to files (download only)
)

type SourceTestData struct {
	n                         int // subtest counter
	xTransport                *XTransport
	key                       *minisign.PublicKey
	keyStr, tempDir           string
	sources                   []string
	fixtures                  map[SourceTestState]map[string]SourceFixture
	timeNow, timeOld, timeUpd time.Time
	server                    *httptest.Server
	reqActual, reqExpect      map[string]uint
	cacheTests                map[string]SourceTestState
	downloadTests             map[string][]SourceTestState
}

type SourceTestExpect struct {
	success        bool
	err, cachePath string
	cache          []SourceFixture
	mtime          time.Time
	urls           []string
	Source         *Source
	delay          time.Duration
	prefix         string
}

func readFixture(t *testing.T, name string) []byte {
	bin, err := ioutil.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Unable to read test fixture %s: %v", name, err)
	}
	return bin
}

func writeSourceCache(t *testing.T, e *SourceTestExpect) {
	for _, f := range e.cache {
		if f.content == nil {
			continue
		}
		path := e.cachePath + f.suffix
		perms := f.perms
		if perms == 0 {
			perms = 0644
		}
		if err := ioutil.WriteFile(path, f.content, perms); err != nil {
			t.Fatalf("Unable to write cache file %s: %v", path, err)
		}
		if err := acl.Chmod(path, perms); err != nil {
			t.Fatalf("Unable to set permissions on cache file %s: %v", path, err)
		}
		if f.suffix != "" {
			continue
		}
		mtime := f.mtime
		if f.mtime.IsZero() {
			mtime = e.mtime
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatalf("Unable to touch cache file %s to %v: %v", path, f.mtime, err)
		}
	}
}

func checkSourceCache(c *check.C, e *SourceTestExpect) {
	for _, f := range e.cache {
		path := e.cachePath + f.suffix
		_ = acl.Chmod(path, 0644) // don't worry if this fails, reading it will catch the same problem
		got, err := ioutil.ReadFile(path)
		c.DeepEqual(got, f.content, "Unexpected content for cache file '%s', err %v", path, err)
		if f.suffix != "" {
			continue
		}
		if fi, err := os.Stat(path); err == nil { // again, if this failed it was already caught above
			mtime := f.mtime
			if f.mtime.IsZero() {
				mtime = e.mtime
			}
			c.EQ(fi.ModTime(), mtime, "Unexpected timestamp for cache file '%s'", path)
		}
	}
}

func loadSnakeoil(t *testing.T, d *SourceTestData) {
	key, err := minisign.NewPublicKeyFromFile(filepath.Join("testdata", "snakeoil.pub"))
	if err != nil {
		t.Fatalf("Unable to load snakeoil key: %v", err)
	}
	d.keyStr = string(bytes.SplitN(readFixture(t, "snakeoil.pub"), []byte("\n"), 2)[1])
	d.key = &key
}

func loadTestSourceNames(t *testing.T, d *SourceTestData) {
	files, err := ioutil.ReadDir(filepath.Join("testdata", "sources"))
	if err != nil {
		t.Fatalf("Unable to load list of test sources: %v", err)
	}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".minisig") {
			d.sources = append(d.sources, strings.TrimSuffix(file.Name(), ".minisig"))
		}
	}
}

func generateFixtureState(t *testing.T, d *SourceTestData, suffix, file string, state SourceTestState) {
	if _, ok := d.fixtures[state]; !ok {
		d.fixtures[state] = map[string]SourceFixture{}
	}
	if suffix != ".minisig" {
		switch state {
		case TestStatePartialSig, TestStateMissingSig, TestStateReadSigErr, TestStateOpenSigErr:
			d.fixtures[state][file] = d.fixtures[TestStateCorrect][file]
			return
		}
	}
	f := SourceFixture{suffix: suffix}
	switch state {
	case TestStateExpired:
		f.content, f.mtime = d.fixtures[TestStateCorrect][file].content, d.timeOld
	case TestStatePartial, TestStatePartialSig:
		f.content = d.fixtures[TestStateCorrect][file].content[:1]
	case TestStateReadErr, TestStateReadSigErr:
		f.content, f.length = []byte{}, "1"
	case TestStateOpenErr, TestStateOpenSigErr:
		f.content, f.perms = d.fixtures[TestStateCorrect][file].content[:1], 0200
	}
	d.fixtures[state][file] = f
}

func loadFixtures(t *testing.T, d *SourceTestData) {
	d.fixtures = map[SourceTestState]map[string]SourceFixture{TestStateCorrect: {}}
	for _, source := range d.sources {
		for _, suffix := range [...]string{"", ".minisig"} {
			file := source + suffix
			d.fixtures[TestStateCorrect][file] = SourceFixture{
				suffix:  suffix,
				content: readFixture(t, filepath.Join("sources", file)),
			}
			for _, state := range [...]SourceTestState{
				TestStateExpired,
				TestStatePartial,
				TestStateReadErr,
				TestStateOpenErr,
				TestStatePartialSig,
				TestStateMissingSig,
				TestStateReadSigErr,
				TestStateOpenSigErr,
			} {
				generateFixtureState(t, d, suffix, file, state)
			}
		}
	}
}

func makeTempDir(t *testing.T, d *SourceTestData) {
	name, err := ioutil.TempDir("", "sources_test.go."+t.Name())
	if err != nil {
		t.Fatalf("Unable to create temporary directory: %v", err)
	}
	d.tempDir = name
}

func makeTestServer(t *testing.T, d *SourceTestData) {
	d.reqActual, d.reqExpect = map[string]uint{}, map[string]uint{}
	d.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data []byte = nil
		d.reqActual[r.URL.Path]++
		pathParts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		state, _ := strconv.ParseUint(pathParts[0], 10, 8)
		if fixture, ok := d.fixtures[SourceTestState(state)][pathParts[1]]; ok {
			if len(fixture.length) > 0 {
				w.Header().Set("Content-Length", fixture.length) // client will return unexpected EOF
			}
			data = fixture.content
		}
		if data != nil {
			if _, err := w.Write(data); err != nil {
				t.Logf("Error writing HTTP response for request [%s]: %v", r.URL.Path, err)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func checkTestServer(c *check.C, d *SourceTestData) {
	c.DeepEqual(d.reqActual, d.reqExpect, "Unexpected HTTP request log")
	d.reqActual, d.reqExpect = map[string]uint{}, map[string]uint{}
}

func setupSourceTest(t *testing.T) (func(), *SourceTestData) {
	d := &SourceTestData{n: -1, xTransport: NewXTransport()}
	d.cacheTests = map[string]SourceTestState{ // determines cache files written to disk before each call
		"correct":      TestStateCorrect,
		"expired":      TestStateExpired,
		"partial":      TestStatePartial,
		"partial-sig":  TestStatePartialSig,
		"missing":      TestStateMissing,
		"missing-sig":  TestStateMissingSig,
		"open-err":     TestStateOpenErr,
		"open-sig-err": TestStateOpenSigErr,
	}
	d.downloadTests = map[string][]SourceTestState{ // determines the list of URLs passed in each call and how they will respond
		"correct":              {TestStateCorrect},
		"partial":              {TestStatePartial},
		"partial-sig":          {TestStatePartialSig},
		"missing":              {TestStateMissing},
		"missing-sig":          {TestStateMissingSig},
		"read-err":             {TestStateReadErr},
		"read-sig-err":         {TestStateReadSigErr},
		"open-err":             {TestStateOpenErr},
		"open-sig-err":         {TestStateOpenSigErr},
		"path-err":             {TestStatePathErr},
		"partial,correct":      {TestStatePartial, TestStateCorrect},
		"partial-sig,correct":  {TestStatePartialSig, TestStateCorrect},
		"missing,correct":      {TestStateMissing, TestStateCorrect},
		"missing-sig,correct":  {TestStateMissingSig, TestStateCorrect},
		"read-err,correct":     {TestStateReadErr, TestStateCorrect},
		"read-sig-err,correct": {TestStateReadSigErr, TestStateCorrect},
		"open-err,correct":     {TestStateOpenErr, TestStateCorrect},
		"open-sig-err,correct": {TestStateOpenSigErr, TestStateCorrect},
		"path-err,correct":     {TestStatePathErr, TestStateCorrect},
		"no-urls":              {},
	}
	d.xTransport.rebuildTransport()
	d.timeNow = time.Now().AddDate(0, 0, 0).Truncate(time.Second)
	d.timeOld = d.timeNow.Add(DefaultPrefetchDelay * -4)
	d.timeUpd = d.timeNow.Add(DefaultPrefetchDelay)
	timeNow = func() time.Time { return d.timeNow } // originally defined in sources.go, replaced during testing to ensure consistent results
	makeTempDir(t, d)
	makeTestServer(t, d)
	loadSnakeoil(t, d)
	loadTestSourceNames(t, d)
	loadFixtures(t, d)
	return func() {
		os.RemoveAll(d.tempDir)
		d.server.Close()
	}, d
}

func prepSourceTestCache(t *testing.T, d *SourceTestData, e *SourceTestExpect, source string, state SourceTestState) {
	e.cache = []SourceFixture{d.fixtures[state][source], d.fixtures[state][source+".minisig"]}
	switch state {
	case TestStateCorrect:
		e.Source.in, e.success = e.cache[0].content, true
	case TestStateExpired:
		e.Source.in = e.cache[0].content
	case TestStatePartial, TestStatePartialSig:
		e.err = "signature"
	case TestStateMissing, TestStateMissingSig, TestStateOpenErr, TestStateOpenSigErr:
		e.err = "open"
	}
	writeSourceCache(t, e)
}

func prepSourceTestDownload(t *testing.T, d *SourceTestData, e *SourceTestExpect, source string, downloadTest []SourceTestState) {
	if len(downloadTest) == 0 {
		return
	}
	for _, state := range downloadTest {
		path := "/" + strconv.FormatUint(uint64(state), 10) + "/" + source
		serverURL := d.server.URL
		switch state {
		case TestStateMissing, TestStateMissingSig:
			e.err = "404 Not Found"
		case TestStatePartial, TestStatePartialSig:
			e.err = "signature"
		case TestStateReadErr, TestStateReadSigErr:
			e.err = "unexpected EOF"
		case TestStateOpenErr, TestStateOpenSigErr:
			if u, err := url.Parse(serverURL + path); err == nil {
				host, port := ExtractHostAndPort(u.Host, -1)
				u.Host = fmt.Sprintf("%s:%d", host, port|0x10000) // high numeric port is parsed but then fails to connect
				serverURL = u.String()
			}
			e.err = "invalid port"
		case TestStatePathErr:
			path = "..." + path // non-numeric port fails URL parsing
		}
		if u, err := url.Parse(serverURL + path); err == nil {
			e.Source.urls = append(e.Source.urls, u)
		}
		e.urls = append(e.urls, serverURL+path)
		if e.success {
			continue
		}
		switch state {
		case TestStateCorrect:
			e.cache = []SourceFixture{d.fixtures[state][source], d.fixtures[state][source+".minisig"]}
			e.Source.in, e.success = e.cache[0].content, true
			fallthrough
		case TestStateMissingSig, TestStatePartial, TestStatePartialSig, TestStateReadSigErr:
			d.reqExpect[path+".minisig"]++
			fallthrough
		case TestStateMissing, TestStateReadErr:
			d.reqExpect[path]++
		}
	}
	if e.success {
		e.err = ""
		e.delay = DefaultPrefetchDelay
	} else {
		e.delay = MinimumPrefetchInterval
	}
	if len(e.Source.urls) > 0 {
		e.Source.refresh = d.timeNow.Add(e.delay)
	} else {
		e.success = false
	}
}

func setupSourceTestCase(t *testing.T, d *SourceTestData, i int,
	cacheTest *SourceTestState, downloadTest []SourceTestState) (id string, e *SourceTestExpect) {
	id = strconv.Itoa(d.n) + "-" + strconv.Itoa(i)
	e = &SourceTestExpect{
		cachePath: filepath.Join(d.tempDir, id),
		mtime:     d.timeNow,
	}
	e.Source = &Source{name: id, urls: []*url.URL{}, format: SourceFormatV2, minisignKey: d.key,
		cacheFile: e.cachePath, cacheTTL: DefaultPrefetchDelay * 3, prefetchDelay: DefaultPrefetchDelay}
	if cacheTest != nil {
		prepSourceTestCache(t, d, e, d.sources[i], *cacheTest)
		i = (i + 1) % len(d.sources) // make the cached and downloaded fixtures different
	}
	prepSourceTestDownload(t, d, e, d.sources[i], downloadTest)
	return
}

func TestNewSource(t *testing.T) {
	teardown, d := setupSourceTest(t)
	defer teardown()
	checkResult := func(t *testing.T, e *SourceTestExpect, got *Source, err error) {
		c := check.T(t)
		if len(e.err) > 0 {
			c.Match(err, e.err, "Unexpected error")
		} else {
			c.Nil(err, "Unexpected error")
		}
		c.DeepEqual(got, e.Source, "Unexpected return")
		checkTestServer(c, d)
		checkSourceCache(c, e)
	}
	d.n++
	for _, tt := range []struct {
		v, key       string
		refreshDelay time.Duration
		e            *SourceTestExpect
	}{
		{"", "", 0, &SourceTestExpect{err: " ", Source: &Source{name: "short refresh delay", urls: []*url.URL{}, cacheTTL: DefaultPrefetchDelay, prefetchDelay: DefaultPrefetchDelay, prefix: ""}}},
		{"v1", d.keyStr, DefaultPrefetchDelay * 2, &SourceTestExpect{err: "Unsupported source format", Source: &Source{name: "old format", urls: []*url.URL{}, cacheTTL: DefaultPrefetchDelay * 2, prefetchDelay: DefaultPrefetchDelay}}},
		{"v2", "", DefaultPrefetchDelay * 3, &SourceTestExpect{err: "Invalid encoded public key", Source: &Source{name: "invalid public key", urls: []*url.URL{}, cacheTTL: DefaultPrefetchDelay * 3, prefetchDelay: DefaultPrefetchDelay}}},
	} {
		t.Run(tt.e.Source.name, func(t *testing.T) {
			got, err := NewSource(tt.e.Source.name, d.xTransport, tt.e.urls, tt.key, tt.e.cachePath, tt.v, tt.refreshDelay, tt.e.prefix)
			checkResult(t, tt.e, got, err)
		})
	}
	for cacheTestName, cacheTest := range d.cacheTests {
		for downloadTestName, downloadTest := range d.downloadTests {
			d.n++
			for i := range d.sources {
				id, e := setupSourceTestCase(t, d, i, &cacheTest, downloadTest)
				t.Run("cache "+cacheTestName+", download "+downloadTestName+"/"+id, func(t *testing.T) {
					got, err := NewSource(id, d.xTransport, e.urls, d.keyStr, e.cachePath, "v2", DefaultPrefetchDelay*3, "")
					checkResult(t, e, got, err)
				})
			}
		}
	}
}

func TestPrefetchSources(t *testing.T) {
	teardown, d := setupSourceTest(t)
	defer teardown()
	checkResult := func(t *testing.T, expects []*SourceTestExpect, got time.Duration) {
		c := check.T(t)
		expectDelay := MinimumPrefetchInterval
		for _, e := range expects {
			if e.delay >= MinimumPrefetchInterval && (expectDelay == MinimumPrefetchInterval || expectDelay > e.delay) {
				expectDelay = e.delay
			}
		}
		c.InDelta(got, expectDelay, time.Second, "Unexpected return")
		checkTestServer(c, d)
		for _, e := range expects {
			checkSourceCache(c, e)
		}
	}
	timeNow = func() time.Time { return d.timeUpd } // since the fixtures are prepared using real now, make the tested code think it's the future
	for downloadTestName, downloadTest := range d.downloadTests {
		d.n++
		sources := []*Source{}
		expects := []*SourceTestExpect{}
		for i := range d.sources {
			_, e := setupSourceTestCase(t, d, i, nil, downloadTest)
			e.mtime = d.timeUpd
			s := &Source{}
			*s = *e.Source
			s.in = nil
			sources = append(sources, s)
			expects = append(expects, e)
		}
		t.Run("download "+downloadTestName, func(t *testing.T) {
			got := PrefetchSources(d.xTransport, sources)
			checkResult(t, expects, got)
		})
	}
}

func TestMain(m *testing.M) { check.TestMain(m) }
