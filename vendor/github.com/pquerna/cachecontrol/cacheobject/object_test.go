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

	"net/http"
	"testing"
	"time"
)

func TestCachableStatusCode(t *testing.T) {
	ok := []int{200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501}
	for _, v := range ok {
		require.True(t, cachableStatusCode(v), "status code should be cacheable: %d", v)
	}

	notok := []int{201, 429, 500, 504}
	for _, v := range notok {
		require.False(t, cachableStatusCode(v), "status code should not be cachable: %d", v)
	}
}

func fill(t *testing.T, now time.Time) Object {
	RespDirectives, err := ParseResponseCacheControl("")
	require.NoError(t, err)
	ReqDirectives, err := ParseRequestCacheControl("")
	require.NoError(t, err)

	obj := Object{
		RespDirectives: RespDirectives,
		RespHeaders:    http.Header{},
		RespStatusCode: 200,
		RespDateHeader: now,

		ReqDirectives: ReqDirectives,
		ReqHeaders:    http.Header{},
		ReqMethod:     "GET",

		NowUTC: now,
	}

	return obj
}

func TestGETPrivate(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	RespDirectives, err := ParseResponseCacheControl("private")
	require.NoError(t, err)

	obj.RespDirectives = RespDirectives

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonResponsePrivate)
}

func TestGETPrivateWithPrivateCache(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	RespDirectives, err := ParseResponseCacheControl("private")
	require.NoError(t, err)

	obj.CacheIsPrivate = true
	obj.RespDirectives = RespDirectives

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)
}

func TestUncachableMethods(t *testing.T) {
	type methodPair struct {
		m string
		r Reason
	}

	tc := []methodPair{
		{"PUT", ReasonRequestMethodPUT},
		{"DELETE", ReasonRequestMethodDELETE},
		{"CONNECT", ReasonRequestMethodCONNECT},
		{"OPTIONS", ReasonRequestMethodOPTIONS},
		{"CONNECT", ReasonRequestMethodCONNECT},
		{"TRACE", ReasonRequestMethodTRACE},
		{"MADEUP", ReasonRequestMethodUnkown},
	}

	for _, mp := range tc {
		now := time.Now().UTC()

		obj := fill(t, now)
		obj.ReqMethod = mp.m

		rv := ObjectResults{}
		CachableObject(&obj, &rv)
		require.NoError(t, rv.OutErr)
		require.Len(t, rv.OutReasons, 1)
		require.Contains(t, rv.OutReasons, mp.r)
	}
}

func TestHEAD(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "HEAD"
	obj.RespLastModifiedHeader = now.Add(time.Hour * -1)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)

	ExpirationObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)
	require.False(t, rv.OutExpirationTime.IsZero())
}

func TestHEADLongLastModified(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "HEAD"
	obj.RespLastModifiedHeader = now.Add(time.Hour * -70000)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)

	ExpirationObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)
	require.False(t, rv.OutExpirationTime.IsZero())
	require.WithinDuration(t, now.Add(twentyFourHours), rv.OutExpirationTime, time.Second*60)
}

func TestNonCachablePOST(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "POST"

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonRequestMethodPOST)
}

func TestCachablePOSTExpiresHeader(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "POST"
	obj.RespExpiresHeader = now.Add(time.Hour * 1)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)
}

func TestCachablePOSTSMax(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "POST"
	obj.RespDirectives.SMaxAge = DeltaSeconds(900)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)
}

func TestNonCachablePOSTSMax(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "POST"
	obj.CacheIsPrivate = true
	obj.RespDirectives.SMaxAge = DeltaSeconds(900)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonRequestMethodPOST)
}

func TestCachablePOSTMax(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "POST"
	obj.RespDirectives.MaxAge = DeltaSeconds(9000)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)
}

func TestPUTs(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "PUT"

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonRequestMethodPUT)
}

func TestPUTWithExpires(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqMethod = "PUT"
	obj.RespExpiresHeader = now.Add(time.Hour * 1)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonRequestMethodPUT)
}

func TestAuthorization(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqHeaders.Set("Authorization", "bearer random")

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonRequestAuthorizationHeader)
}

func TestCachableAuthorization(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqHeaders.Set("Authorization", "bearer random")
	obj.RespDirectives.Public = true
	obj.RespDirectives.MaxAge = DeltaSeconds(300)

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.NoError(t, rv.OutErr)
	require.Len(t, rv.OutReasons, 0)
}

func TestRespNoStore(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.RespDirectives.NoStore = true

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonResponseNoStore)
}

func TestReqNoStore(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.ReqDirectives.NoStore = true

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonRequestNoStore)
}

func TestResp500(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.RespStatusCode = 500

	rv := ObjectResults{}
	CachableObject(&obj, &rv)
	require.Len(t, rv.OutReasons, 1)
	require.Contains(t, rv.OutReasons, ReasonResponseUncachableByDefault)
}

func TestExpirationSMaxShared(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.RespDirectives.SMaxAge = DeltaSeconds(60)

	rv := ObjectResults{}
	ExpirationObject(&obj, &rv)
	require.Len(t, rv.OutWarnings, 0)
	require.WithinDuration(t, now.Add(time.Second*60), rv.OutExpirationTime, time.Second*1)
}

func TestExpirationSMaxPrivate(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.CacheIsPrivate = true
	obj.RespDirectives.SMaxAge = DeltaSeconds(60)

	rv := ObjectResults{}
	ExpirationObject(&obj, &rv)
	require.Len(t, rv.OutWarnings, 0)
	require.True(t, rv.OutExpirationTime.IsZero())
}

func TestExpirationMax(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	obj.RespDirectives.MaxAge = DeltaSeconds(60)

	rv := ObjectResults{}
	ExpirationObject(&obj, &rv)
	require.Len(t, rv.OutWarnings, 0)
	require.WithinDuration(t, now.Add(time.Second*60), rv.OutExpirationTime, time.Second*1)
}

func TestExpirationMaxAndSMax(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	// cache should select the SMax age since this is a shared cache.
	obj.RespDirectives.MaxAge = DeltaSeconds(60)
	obj.RespDirectives.SMaxAge = DeltaSeconds(900)

	rv := ObjectResults{}
	ExpirationObject(&obj, &rv)
	require.Len(t, rv.OutWarnings, 0)
	require.WithinDuration(t, now.Add(time.Second*900), rv.OutExpirationTime, time.Second*1)
}

func TestExpirationExpires(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	// cache should select the SMax age since this is a shared cache.
	obj.RespExpiresHeader = now.Add(time.Second * 1500)

	rv := ObjectResults{}
	ExpirationObject(&obj, &rv)
	require.Len(t, rv.OutWarnings, 0)
	require.WithinDuration(t, now.Add(time.Second*1500), rv.OutExpirationTime, time.Second*1)
}

func TestExpirationExpiresNoServerDate(t *testing.T) {
	now := time.Now().UTC()

	obj := fill(t, now)
	// cache should select the SMax age since this is a shared cache.
	obj.RespDateHeader = time.Time{}
	obj.RespExpiresHeader = now.Add(time.Second * 1500)

	rv := ObjectResults{}
	ExpirationObject(&obj, &rv)
	require.Len(t, rv.OutWarnings, 0)
	require.WithinDuration(t, now.Add(time.Second*1500), rv.OutExpirationTime, time.Second*1)
}
