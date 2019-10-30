package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jedisct1/go-minisign"
	"github.com/powerman/check"
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
	TestStateMissing                           // non-existant files
	TestStateMissingSig                        // non-existant .minisig
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
	success, download bool
	in, cachePath     string
	cache             []SourceFixture
	refresh           time.Time
	urls              []string
	prefetchUrls      []URLToPrefetch
	Source            *Source
	err               string
}

func readFixture(t *testing.T, name string) []byte {
	bin, err := ioutil.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Unable to read test fixture %s: %v", name, err)
	}
	return bin
}

func writeSourceCache(t *testing.T, basePath string, fixtures []SourceFixture) {
	for _, f := range fixtures {
		if f.content == nil {
			continue
		}
		path := basePath + f.suffix
		perms := f.perms
		if perms == 0 {
			perms = 0644
		}
		if err := ioutil.WriteFile(path, f.content, perms); err != nil {
			t.Fatalf("Unable to write cache file %s: %v", path, err)
		}
		if !f.mtime.IsZero() {
			if err := os.Chtimes(path, f.mtime, f.mtime); err != nil {
				t.Fatalf("Unable to touch cache file %s to %v: %v", path, f.mtime, err)
			}
		}
	}
}

func checkSourceCache(c *check.C, basePath string, fixtures []SourceFixture) {
	for _, f := range fixtures {
		path := basePath + f.suffix
		_ = os.Chmod(path, 0644) // don't worry if this fails, reading it will catch the same problem
		got, err := ioutil.ReadFile(path)
		c.DeepEqual(got, f.content, "Cache file '%s', err %v", path, err)
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

func loadFixtures(t *testing.T, d *SourceTestData) {
	d.fixtures = map[SourceTestState]map[string]SourceFixture{TestStateCorrect: map[string]SourceFixture{}}
	for _, source := range d.sources {
		for _, suffix := range [...]string{"", ".minisig"} {
			file := source + suffix
			d.fixtures[TestStateCorrect][file] = SourceFixture{suffix: suffix, content: readFixture(t, filepath.Join("sources", file)), mtime: d.timeNow}
			for _, state := range [...]SourceTestState{TestStateExpired, TestStatePartial, TestStateReadErr, TestStateOpenErr,
				TestStatePartialSig, TestStateMissingSig, TestStateReadSigErr, TestStateOpenSigErr} {
				if _, ok := d.fixtures[state]; !ok {
					d.fixtures[state] = map[string]SourceFixture{}
				}
				switch state {
				case TestStatePartialSig, TestStateMissingSig, TestStateReadSigErr, TestStateOpenSigErr:
					if suffix != ".minisig" {
						d.fixtures[state][file] = d.fixtures[TestStateCorrect][file]
						continue
					}
				}
				f := SourceFixture{suffix: suffix, mtime: d.timeNow}
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
		"correct": TestStateCorrect,
		//"expired":      TestStateExpired,    // TODO: an expired cache should be used if no download passes signature verification
		//"partial":      TestStatePartial,    // TODO: failed signature verification should not abort before trying additional URLs
		//"partial-sig":  TestStatePartialSig, // TODO: failed signature verification should not abort before trying additional URLs
		"missing": TestStateMissing,
		//"missing-sig":  TestStateMissingSig, // TODO: a cache without a signature should cause an attempt to download both files (not just the signature)
		"open-err": TestStateOpenErr,
		//"open-sig-err": TestStateOpenSigErr, // TODO: a cache without a signature should cause an attempt to download both files (not just the signature)
	}
	d.downloadTests = map[string][]SourceTestState{ // determines the list of URLs passed in each call and how they will respond
		"correct": {TestStateCorrect},
		//"partial":              {TestStatePartial},    // TODO: failed signature verification should not count as successfully prefetched
		//"partial-sig":          {TestStatePartialSig}, // TODO: failed signature verification should not count as successfully prefetched
		//"missing":              {TestStateMissing},    // TODO: a list download failure should not cause an attempt to download the signature for that URL
		//"missing-sig":          {TestStateMissingSig}, // TODO: failed signature verification should not count as successfully prefetched
		//"read-err":             {TestStateReadErr},    // TODO: a list download failure should not cause an attempt to download the signature for that URL
		//"read-sig-err":         {TestStateReadSigErr}, // TODO: failed signature verification should not count as successfully prefetched
		"open-err": {TestStateOpenErr},
		//"open-sig-err":         {TestStateOpenSigErr},                   // TODO: failed signature verification should not count as successfully prefetched
		//"path-err":             {TestStatePathErr},                      // TODO: invalid URLs should not be included in the prefetch list
		//"partial,correct":      {TestStatePartial, TestStateCorrect},    // TODO: all URLs should be included in the prefetch list, failed signature verification should not abort before trying additional URLs
		//"partial-sig,correct":  {TestStatePartialSig, TestStateCorrect}, // TODO: all URLs should be included in the prefetch list, failed signature verification should not abort before trying additional URLs
		//"missing,correct":      {TestStateMissing, TestStateCorrect},    // TODO: all URLs should be included in the prefetch list
		//"missing-sig,correct":  {TestStateMissingSig, TestStateCorrect}, // TODO: all URLs should be included in the prefetch list, failed signature verification should not abort before trying additional URLs
		//"read-err,correct":     {TestStateReadErr, TestStateCorrect},    // TODO: all URLs should be included in the prefetch list
		//"read-sig-err,correct": {TestStateReadSigErr, TestStateCorrect}, // TODO: all URLs should be included in the prefetch list, failed signature verification should not abort before trying additional URLs
		//"open-err,correct":     {TestStateOpenErr, TestStateCorrect},    // TODO: all URLs should be included in the prefetch list
		//"open-sig-err,correct": {TestStateOpenSigErr, TestStateCorrect}, // TODO: all URLs should be included in the prefetch list, failed signature verification should not abort before trying additional URLs
		//"path-err,correct":     {TestStatePathErr, TestStateCorrect},    // TODO: invalid URLs should not be included in the prefetch list
		"no-urls": {},
	}
	d.xTransport.rebuildTransport()
	d.timeNow = time.Now().AddDate(0, 0, 0)
	d.timeOld = d.timeNow.Add(MinSourcesUpdateDelay * -4)
	d.timeUpd = d.timeNow.Add(MinSourcesUpdateDelay)
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
		e.in, e.success, e.refresh = string(e.cache[0].content), true, d.timeUpd
	case TestStateExpired:
		e.in = string(e.cache[0].content)
	case TestStatePartial, TestStatePartialSig:
		e.err = "signature"
	case TestStateMissing, TestStateMissingSig:
		e.err = "not present"
	case TestStateOpenErr, TestStateOpenSigErr:
		e.err = os.ErrPermission.Error()
	}
	writeSourceCache(t, e.cachePath, e.cache)
}

func prepSourceTestDownload(t *testing.T, d *SourceTestData, e *SourceTestExpect, source string, downloadTest []SourceTestState) {
	if len(downloadTest) > 0 {
		for _, state := range downloadTest {
			path := "/" + strconv.FormatUint(uint64(state), 10) + "/" + source
			if !e.success {
				switch state {
				case TestStateCorrect:
					e.cache = []SourceFixture{d.fixtures[state][source], d.fixtures[state][source+".minisig"]}
					e.in, e.success, e.refresh = string(e.cache[0].content), true, d.timeUpd
					fallthrough
				case TestStateMissingSig, TestStatePartial, TestStatePartialSig, TestStateReadSigErr:
					d.reqExpect[path+".minisig"]++
					fallthrough
				case TestStateMissing, TestStateReadErr:
					d.reqExpect[path]++
				}
			}
			switch state {
			case TestStateMissing, TestStateMissingSig:
				e.err = "404 Not Found"
			case TestStatePartial, TestStatePartialSig:
				e.err = "signature"
			case TestStateReadErr, TestStateReadSigErr:
				e.err = "unexpected EOF"
			case TestStateOpenErr, TestStateOpenSigErr:
				path = "00000" + path // high numeric port is parsed but then fails to connect
				e.err = "invalid port"
			case TestStatePathErr:
				path = "..." + path // non-numeric port fails URL parsing
				e.err = "parse"
			}
			e.urls = append(e.urls, d.server.URL+path)
			if state != TestStatePathErr {
				e.prefetchUrls = append(e.prefetchUrls, URLToPrefetch{d.server.URL + path, e.cachePath, e.refresh})
				e.prefetchUrls = append(e.prefetchUrls, URLToPrefetch{d.server.URL + path + ".minisig", e.cachePath + ".minisig", e.refresh})
			}
		}
		if e.success {
			e.err = ""
		}
	} else if !e.success {
		e.err = "no URL"
	}
}

func setupSourceTestCase(t *testing.T, d *SourceTestData, i int,
	cacheTest *SourceTestState, downloadTest []SourceTestState) (id string, e *SourceTestExpect) {
	id = strconv.Itoa(d.n) + "-" + strconv.Itoa(i)
	e = &SourceTestExpect{
		cachePath:    filepath.Join(d.tempDir, id),
		refresh:      d.timeNow,
		urls:         []string{},
		prefetchUrls: []URLToPrefetch{},
	}
	if cacheTest != nil {
		prepSourceTestCache(t, d, e, d.sources[i], *cacheTest)
		i = (i + 1) % len(d.sources) // make the cached and downloaded fixtures different
	}
	prepSourceTestDownload(t, d, e, d.sources[i], downloadTest)
	e.Source = &Source{e.urls, SourceFormatV2, e.in, d.key}
	return
}

func TestNewSource(t *testing.T) {
	teardown, d := setupSourceTest(t)
	defer teardown()
	doTest := func(t *testing.T, e *SourceTestExpect, got Source, urls []URLToPrefetch, err error) {
		c := check.T(t)
		if len(e.err) > 0 {
			c.Match(err, e.err, "Unexpected error")
		} else {
			c.Nil(err, "Unexpected error")
		}
		c.DeepEqual(got, *e.Source, "Unexpected return Source")
		c.DeepEqual(urls, e.prefetchUrls, "Unexpected return prefetch URLs")
		checkTestServer(c, d)
		checkSourceCache(c, e.cachePath, e.cache)
	}
	d.n++
	for _, tt := range []struct {
		name, key, v string
		refresh      time.Duration
		e            *SourceTestExpect
	}{
		{"old format", d.keyStr, "v1", MinSourcesUpdateDelay * 3, &SourceTestExpect{
			Source: &Source{urls: nil}, prefetchUrls: []URLToPrefetch{}, err: "Unsupported source format"}},
		{"invalid public key", "", "v2", MinSourcesUpdateDelay * 3, &SourceTestExpect{
			Source: &Source{urls: nil}, prefetchUrls: []URLToPrefetch{}, err: "Invalid encoded public key"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, urls, err := NewSource(d.xTransport, tt.e.urls, tt.key, tt.e.cachePath, tt.v, tt.refresh)
			doTest(t, tt.e, got, urls, err)
		})
	}
	for cacheTestName, cacheTest := range d.cacheTests {
		for downloadTestName, downloadTest := range d.downloadTests {
			d.n++
			for i := range d.sources {
				id, e := setupSourceTestCase(t, d, i, &cacheTest, downloadTest)
				t.Run("cache "+cacheTestName+", download "+downloadTestName+"/"+id, func(t *testing.T) {
					got, urls, err := NewSource(d.xTransport, e.urls, d.keyStr, e.cachePath, "v2", MinSourcesUpdateDelay*3)
					doTest(t, e, got, urls, err)
				})
			}
		}
	}
}

func TestPrefetchSourceURL(t *testing.T) {
	teardown, d := setupSourceTest(t)
	defer teardown()
	doTest := func(t *testing.T, expects []*SourceTestExpect) {
		c := check.T(t)
		for _, e := range expects {
			for _, url := range e.urls {
				for _, suffix := range []string{"", ".minisig"} {
					pf := &URLToPrefetch{url + suffix, e.cachePath + suffix, d.timeOld}
					PrefetchSourceURL(d.xTransport, pf)
					c.InDelta(pf.when, e.refresh, time.Second, "Unexpected prefetch refresh time")
				}
			}
		}
		checkTestServer(c, d)
		for _, e := range expects {
			checkSourceCache(c, e.cachePath, e.cache)
		}
	}
	for downloadTestName, downloadTest := range d.downloadTests {
		d.n++
		expects := []*SourceTestExpect{}
		for i := range d.sources {
			_, e := setupSourceTestCase(t, d, i, nil, downloadTest)
			expects = append(expects, e)
		}
		t.Run("download "+downloadTestName, func(t *testing.T) {
			doTest(t, expects)
		})
	}
}

func TestMain(m *testing.M) { check.TestMain(m) }
