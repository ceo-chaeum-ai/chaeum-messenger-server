// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package searchproto

// Request and Response are the socket protocol: one JSON value each way per call.
type Request struct {
	Op      string   `json:"op"` // status, reset, ready, index, delete, delete_channel, delete_user, search
	Since   int64    `json:"since,omitempty"`
	Docs    []Doc    `json:"docs,omitempty"`
	IDs     []string `json:"ids,omitempty"`
	Channel string   `json:"channel,omitempty"`
	User    string   `json:"user,omitempty"`
	Query   *Query   `json:"query,omitempty"`
	Files   bool     `json:"files,omitempty"` // the request is for the file index instead of the post index
}

type Response struct {
	Err   string `json:"err,omitempty"`
	Hits  []Hit  `json:"hits,omitempty"`
	Total int    `json:"total,omitempty"`
	Count int    `json:"count"`
	Since int64  `json:"since"`
	Ready bool   `json:"ready"`
}
