/**
 *  Copyright 2015 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package cacheobject

import (
	"github.com/stretchr/testify/require"

	"fmt"
	"math"
	"testing"
)

func TestMaxAge(t *testing.T) {
	cd, err := ParseResponseCacheControl("")
	require.NoError(t, err)
	require.Equal(t, cd.MaxAge, DeltaSeconds(-1))

	cd, err = ParseResponseCacheControl("max-age")
	require.Error(t, err)

	cd, err = ParseResponseCacheControl("max-age=20")
	require.NoError(t, err)
	require.Equal(t, cd.MaxAge, DeltaSeconds(20))

	cd, err = ParseResponseCacheControl("max-age=0")
	require.NoError(t, err)
	require.Equal(t, cd.MaxAge, DeltaSeconds(0))

	cd, err = ParseResponseCacheControl("max-age=-1")
	require.Error(t, err)
}

func TestSMaxAge(t *testing.T) {
	cd, err := ParseResponseCacheControl("")
	require.NoError(t, err)
	require.Equal(t, cd.SMaxAge, DeltaSeconds(-1))

	cd, err = ParseResponseCacheControl("s-maxage")
	require.Error(t, err)

	cd, err = ParseResponseCacheControl("s-maxage=20")
	require.NoError(t, err)
	require.Equal(t, cd.SMaxAge, DeltaSeconds(20))

	cd, err = ParseResponseCacheControl("s-maxage=0")
	require.NoError(t, err)
	require.Equal(t, cd.SMaxAge, DeltaSeconds(0))

	cd, err = ParseResponseCacheControl("s-maxage=-1")
	require.Error(t, err)
}

func TestResNoCache(t *testing.T) {
	cd, err := ParseResponseCacheControl("")
	require.NoError(t, err)
	require.Equal(t, cd.SMaxAge, DeltaSeconds(-1))

	cd, err = ParseResponseCacheControl("no-cache")
	require.NoError(t, err)
	require.Equal(t, cd.NoCachePresent, true)
	require.Equal(t, len(cd.NoCache), 0)

	cd, err = ParseResponseCacheControl("no-cache=MyThing")
	require.NoError(t, err)
	require.Equal(t, cd.NoCachePresent, true)
	require.Equal(t, len(cd.NoCache), 1)
}

func TestResSpaceOnly(t *testing.T) {
	cd, err := ParseResponseCacheControl(" ")
	require.NoError(t, err)
	require.Equal(t, cd.SMaxAge, DeltaSeconds(-1))
}

func TestResTabOnly(t *testing.T) {
	cd, err := ParseResponseCacheControl("\t")
	require.NoError(t, err)
	require.Equal(t, cd.SMaxAge, DeltaSeconds(-1))
}

func TestResPrivateExtensionQuoted(t *testing.T) {
	cd, err := ParseResponseCacheControl(`private="Set-Cookie,Request-Id" public`)
	require.NoError(t, err)
	require.Equal(t, cd.Public, true)
	require.Equal(t, cd.PrivatePresent, true)
	require.Equal(t, len(cd.Private), 2)
	require.Equal(t, len(cd.Extensions), 0)
	require.Equal(t, cd.Private["Set-Cookie"], true)
	require.Equal(t, cd.Private["Request-Id"], true)
}

func TestResCommaFollowingBare(t *testing.T) {
	cd, err := ParseResponseCacheControl(`public, max-age=500`)
	require.NoError(t, err)
	require.Equal(t, cd.Public, true)
	require.Equal(t, cd.MaxAge, DeltaSeconds(500))
	require.Equal(t, cd.PrivatePresent, false)
	require.Equal(t, len(cd.Extensions), 0)
}

func TestResCommaFollowingKV(t *testing.T) {
	cd, err := ParseResponseCacheControl(`max-age=500, public`)
	require.NoError(t, err)
	require.Equal(t, cd.Public, true)
	require.Equal(t, cd.MaxAge, DeltaSeconds(500))
	require.Equal(t, cd.PrivatePresent, false)
	require.Equal(t, len(cd.Extensions), 0)
}

func TestResPrivateTrailingComma(t *testing.T) {
	cd, err := ParseResponseCacheControl(`private=Set-Cookie, public`)
	require.NoError(t, err)
	require.Equal(t, cd.Public, true)
	require.Equal(t, cd.PrivatePresent, true)
	require.Equal(t, len(cd.Private), 1)
	require.Equal(t, len(cd.Extensions), 0)
	require.Equal(t, cd.Private["Set-Cookie"], true)
}

func TestResPrivateExtension(t *testing.T) {
	cd, err := ParseResponseCacheControl(`private=Set-Cookie,Request-Id public`)
	require.NoError(t, err)
	require.Equal(t, cd.Public, true)
	require.Equal(t, cd.PrivatePresent, true)
	require.Equal(t, len(cd.Private), 2)
	require.Equal(t, len(cd.Extensions), 0)
	require.Equal(t, cd.Private["Set-Cookie"], true)
	require.Equal(t, cd.Private["Request-Id"], true)
}

func TestResMultipleNoCacheTabExtension(t *testing.T) {
	cd, err := ParseResponseCacheControl("no-cache " + "\t" + "no-cache=Mything aasdfdsfa")
	require.NoError(t, err)
	require.Equal(t, cd.NoCachePresent, true)
	require.Equal(t, len(cd.NoCache), 1)
	require.Equal(t, len(cd.Extensions), 1)
	require.Equal(t, cd.NoCache["Mything"], true)
}

func TestResExtensionsEmptyQuote(t *testing.T) {
	cd, err := ParseResponseCacheControl(`foo="" bar="hi"`)
	require.NoError(t, err)
	require.Equal(t, cd.SMaxAge, DeltaSeconds(-1))
	require.Equal(t, len(cd.Extensions), 2)
	require.Contains(t, cd.Extensions, "bar=hi")
	require.Contains(t, cd.Extensions, "foo=")
}

func TestResQuoteMismatch(t *testing.T) {
	cd, err := ParseResponseCacheControl(`foo="`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrQuoteMismatch)
}

func TestResMustRevalidateNoArgs(t *testing.T) {
	cd, err := ParseResponseCacheControl(`must-revalidate=234`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrMustRevalidateNoArgs)
}

func TestResNoTransformNoArgs(t *testing.T) {
	cd, err := ParseResponseCacheControl(`no-transform="xxx"`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrNoTransformNoArgs)
}

func TestResNoStoreNoArgs(t *testing.T) {
	cd, err := ParseResponseCacheControl(`no-store=""`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrNoStoreNoArgs)
}

func TestResProxyRevalidateNoArgs(t *testing.T) {
	cd, err := ParseResponseCacheControl(`proxy-revalidate=23432`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrProxyRevalidateNoArgs)
}

func TestResPublicNoArgs(t *testing.T) {
	cd, err := ParseResponseCacheControl(`public=999Vary`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrPublicNoArgs)
}

func TestResMustRevalidate(t *testing.T) {
	cd, err := ParseResponseCacheControl(`must-revalidate`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.MustRevalidate, true)
}

func TestResNoTransform(t *testing.T) {
	cd, err := ParseResponseCacheControl(`no-transform`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.NoTransform, true)
}

func TestResNoStore(t *testing.T) {
	cd, err := ParseResponseCacheControl(`no-store`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.NoStore, true)
}

func TestResProxyRevalidate(t *testing.T) {
	cd, err := ParseResponseCacheControl(`proxy-revalidate`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.ProxyRevalidate, true)
}

func TestResPublic(t *testing.T) {
	cd, err := ParseResponseCacheControl(`public`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.Public, true)
}

func TestResPrivate(t *testing.T) {
	cd, err := ParseResponseCacheControl(`private`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Len(t, cd.Private, 0)
	require.Equal(t, cd.PrivatePresent, true)
}

func TestParseDeltaSecondsZero(t *testing.T) {
	ds, err := parseDeltaSeconds("0")
	require.NoError(t, err)
	require.Equal(t, ds, DeltaSeconds(0))
}

func TestParseDeltaSecondsLarge(t *testing.T) {
	ds, err := parseDeltaSeconds(fmt.Sprintf("%d", int64(math.MaxInt32)*2))
	require.NoError(t, err)
	require.Equal(t, ds, DeltaSeconds(math.MaxInt32))
}

func TestParseDeltaSecondsVeryLarge(t *testing.T) {
	ds, err := parseDeltaSeconds(fmt.Sprintf("%d", math.MaxInt64))
	require.NoError(t, err)
	require.Equal(t, ds, DeltaSeconds(math.MaxInt32))
}

func TestParseDeltaSecondsNegative(t *testing.T) {
	ds, err := parseDeltaSeconds("-60")
	require.Error(t, err)
	require.Equal(t, DeltaSeconds(-1), ds)
}

func TestReqNoCacheNoArgs(t *testing.T) {
	cd, err := ParseRequestCacheControl(`no-cache=234`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrNoCacheNoArgs)
}

func TestReqNoStoreNoArgs(t *testing.T) {
	cd, err := ParseRequestCacheControl(`no-store=,,x`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrNoStoreNoArgs)
}

func TestReqNoTransformNoArgs(t *testing.T) {
	cd, err := ParseRequestCacheControl(`no-transform=akx`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrNoTransformNoArgs)
}

func TestReqOnlyIfCachedNoArgs(t *testing.T) {
	cd, err := ParseRequestCacheControl(`only-if-cached=no-store`)
	require.Error(t, err)
	require.Nil(t, cd)
	require.Equal(t, err, ErrOnlyIfCachedNoArgs)
}

func TestReqMaxAge(t *testing.T) {
	cd, err := ParseRequestCacheControl(`max-age=99999`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.MaxAge, DeltaSeconds(99999))
	require.Equal(t, cd.MaxStale, DeltaSeconds(-1))
}

func TestReqMaxStale(t *testing.T) {
	cd, err := ParseRequestCacheControl(`max-stale=99999`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.MaxStale, DeltaSeconds(99999))
	require.Equal(t, cd.MaxAge, DeltaSeconds(-1))
	require.Equal(t, cd.MinFresh, DeltaSeconds(-1))
}

func TestReqMaxAgeBroken(t *testing.T) {
	cd, err := ParseRequestCacheControl(`max-age`)
	require.Error(t, err)
	require.Equal(t, ErrMaxAgeDeltaSeconds, err)
	require.Nil(t, cd)
}

func TestReqMaxStaleBroken(t *testing.T) {
	cd, err := ParseRequestCacheControl(`max-stale`)
	require.Error(t, err)
	require.Equal(t, ErrMaxStaleDeltaSeconds, err)
	require.Nil(t, cd)
}

func TestReqMinFresh(t *testing.T) {
	cd, err := ParseRequestCacheControl(`min-fresh=99999`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.MinFresh, DeltaSeconds(99999))
	require.Equal(t, cd.MaxAge, DeltaSeconds(-1))
	require.Equal(t, cd.MaxStale, DeltaSeconds(-1))
}

func TestReqMinFreshBroken(t *testing.T) {
	cd, err := ParseRequestCacheControl(`min-fresh`)
	require.Error(t, err)
	require.Equal(t, ErrMinFreshDeltaSeconds, err)
	require.Nil(t, cd)
}

func TestReqMinFreshJunk(t *testing.T) {
	cd, err := ParseRequestCacheControl(`min-fresh=a99a`)
	require.Equal(t, ErrMinFreshDeltaSeconds, err)
	require.Nil(t, cd)
}

func TestReqMinFreshBadValue(t *testing.T) {
	cd, err := ParseRequestCacheControl(`min-fresh=-1`)
	require.Equal(t, ErrMinFreshDeltaSeconds, err)
	require.Nil(t, cd)
}

func TestReqExtensions(t *testing.T) {
	cd, err := ParseRequestCacheControl(`min-fresh=99999 foobar=1 cats`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.MinFresh, DeltaSeconds(99999))
	require.Equal(t, cd.MaxAge, DeltaSeconds(-1))
	require.Equal(t, cd.MaxStale, DeltaSeconds(-1))
	require.Len(t, cd.Extensions, 2)
	require.Contains(t, cd.Extensions, "foobar=1")
	require.Contains(t, cd.Extensions, "cats")
}

func TestReqMultiple(t *testing.T) {
	cd, err := ParseRequestCacheControl(`no-store no-transform`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.NoStore, true)
	require.Equal(t, cd.NoTransform, true)
	require.Equal(t, cd.OnlyIfCached, false)
	require.Len(t, cd.Extensions, 0)
}

func TestReqMultipleComma(t *testing.T) {
	cd, err := ParseRequestCacheControl(`no-cache,only-if-cached`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.NoCache, true)
	require.Equal(t, cd.NoStore, false)
	require.Equal(t, cd.NoTransform, false)
	require.Equal(t, cd.OnlyIfCached, true)
	require.Len(t, cd.Extensions, 0)
}

func TestReqLeadingComma(t *testing.T) {
	cd, err := ParseRequestCacheControl(`,no-cache`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Len(t, cd.Extensions, 0)
	require.Equal(t, cd.NoCache, true)
	require.Equal(t, cd.NoStore, false)
	require.Equal(t, cd.NoTransform, false)
	require.Equal(t, cd.OnlyIfCached, false)
}

func TestReqMinFreshQuoted(t *testing.T) {
	cd, err := ParseRequestCacheControl(`min-fresh="99999"`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.MinFresh, DeltaSeconds(99999))
	require.Equal(t, cd.MaxAge, DeltaSeconds(-1))
	require.Equal(t, cd.MaxStale, DeltaSeconds(-1))
}

func TestNoSpacesIssue3(t *testing.T) {
	cd, err := ParseResponseCacheControl(`no-cache,no-store,max-age=0,must-revalidate`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.NoCachePresent, true)
	require.Equal(t, cd.NoStore, true)
	require.Equal(t, cd.MaxAge, DeltaSeconds(0))
	require.Equal(t, cd.MustRevalidate, true)
}

func TestNoSpacesIssue3PrivateFields(t *testing.T) {
	cd, err := ParseResponseCacheControl(`no-cache, no-store, private=set-cookie,hello, max-age=0, must-revalidate`)
	require.NoError(t, err)
	require.NotNil(t, cd)
	require.Equal(t, cd.NoCachePresent, true)
	require.Equal(t, cd.NoStore, true)
	require.Equal(t, cd.MaxAge, DeltaSeconds(0))
	require.Equal(t, cd.MustRevalidate, true)
	require.Equal(t, true, cd.Private["Set-Cookie"])
	require.Equal(t, true, cd.Private["Hello"])
}
