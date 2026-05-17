package parser

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParse_SetsIsStreamForExecAttachPortforward closes UAT-K2 HIGH-K2-05.
// The URL parser is the only layer that can decide is_stream + stream_kind
// for exec/attach/portforward when a client doesn't send an Upgrade
// header on the initial request. The proxy still combines this with the
// header-based classifier; the URL-level signal is the floor.
func TestParse_SetsIsStreamForExecAttachPortforward(t *testing.T) {
	cases := []struct {
		name           string
		method         string
		url            string
		wantIsStream   bool
		wantStreamKind string
	}{
		{
			name:           "POST exec",
			method:         http.MethodPost,
			url:            "/api/v1/namespaces/default/pods/my-pod/exec",
			wantIsStream:   true,
			wantStreamKind: "exec",
		},
		{
			name:           "POST attach",
			method:         http.MethodPost,
			url:            "/api/v1/namespaces/default/pods/my-pod/attach",
			wantIsStream:   true,
			wantStreamKind: "attach",
		},
		{
			name:           "POST portforward",
			method:         http.MethodPost,
			url:            "/api/v1/namespaces/default/pods/my-pod/portforward",
			wantIsStream:   true,
			wantStreamKind: "portforward",
		},
		{
			name:           "GET log without follow",
			method:         http.MethodGet,
			url:            "/api/v1/namespaces/default/pods/my-pod/log",
			wantIsStream:   false,
			wantStreamKind: "",
		},
		{
			name:           "GET log with follow=true",
			method:         http.MethodGet,
			url:            "/api/v1/namespaces/default/pods/my-pod/log?follow=true",
			wantIsStream:   true,
			wantStreamKind: "log",
		},
		{
			name:           "GET watch list",
			method:         http.MethodGet,
			url:            "/api/v1/namespaces/default/pods?watch=true",
			wantIsStream:   true,
			wantStreamKind: "watch",
		},
		{
			name:           "GET regular list",
			method:         http.MethodGet,
			url:            "/api/v1/namespaces/default/pods",
			wantIsStream:   false,
			wantStreamKind: "",
		},
		{
			name:           "POST create (non-stream)",
			method:         http.MethodPost,
			url:            "/api/v1/namespaces/default/pods",
			wantIsStream:   false,
			wantStreamKind: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := MustParseTestURL(tc.method, tc.url)
			got, err := Parse(req)
			require.NoError(t, err)
			assert.Equal(t, tc.wantIsStream, got.IsStream, "IsStream")
			assert.Equal(t, tc.wantStreamKind, got.StreamKind, "StreamKind")
		})
	}
}
