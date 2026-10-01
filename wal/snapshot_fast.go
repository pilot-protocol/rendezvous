// SPDX-License-Identifier: AGPL-3.0-or-later

package wal

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
)

// AppendSnapshot appends the JSON encoding of s to dst, without the
// reflection-based encoding/json overhead on the hot collections. The output
// is byte-identical to json.Encoder(SetEscapeHTML(false)) over the same
// struct (differential-tested), which load() depends on when it re-encodes to
// verify the checksum.
//
// Hot fields (Nodes, PubKeyIdx) are hand-encoded; TrustPairs is emitted
// verbatim from its pre-encoded RawMessage (cached); the remaining small/rare
// fields fall back to encoding/json per value so their bytes are exactly
// right.
func AppendSnapshot(dst []byte, s *Snapshot) []byte {
	dst = append(dst, '{')
	first := true
	key := func(name string) {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, '"')
		dst = append(dst, name...)
		dst = append(dst, '"', ':')
	}

	key("version")
	dst = strconv.AppendInt(dst, int64(s.Version), 10)
	key("next_node")
	dst = strconv.AppendUint(dst, uint64(s.NextNode), 10)
	key("next_net")
	dst = strconv.AppendUint(dst, uint64(s.NextNet), 10)
	key("nodes")
	dst = s.Nodes.appendTo(dst)
	key("networks")
	dst = appendStdValue(dst, s.Networks)

	if len(s.TrustPairs) > 0 {
		key("trust_pairs")
		dst = append(dst, s.TrustPairs...)
	}
	if len(s.PubKeyIdx) > 0 {
		key("pub_key_idx")
		dst = appendPubKeyIdx(dst, s.PubKeyIdx)
	}
	if len(s.HandshakeInbox) > 0 {
		key("handshake_inbox")
		dst = appendStdValue(dst, s.HandshakeInbox)
	}
	if len(s.HandshakeResponses) > 0 {
		key("handshake_responses")
		dst = appendStdValue(dst, s.HandshakeResponses)
	}
	if len(s.InviteInbox) > 0 {
		key("invite_inbox")
		dst = appendStdValue(dst, s.InviteInbox)
	}
	if s.TotalRequests != 0 {
		key("total_requests")
		dst = strconv.AppendInt(dst, s.TotalRequests, 10)
	}
	if s.TotalNodes != 0 {
		key("total_nodes")
		dst = strconv.AppendInt(dst, int64(s.TotalNodes), 10)
	}
	if s.OnlineNodes != 0 {
		key("online_nodes")
		dst = strconv.AppendInt(dst, int64(s.OnlineNodes), 10)
	}
	if s.TrustLinks != 0 {
		key("trust_links")
		dst = strconv.AppendInt(dst, int64(s.TrustLinks), 10)
	}
	if s.UniqueTags != 0 {
		key("unique_tags")
		dst = strconv.AppendInt(dst, int64(s.UniqueTags), 10)
	}
	if s.TaskExecutors != 0 {
		key("task_executors")
		dst = strconv.AppendInt(dst, int64(s.TaskExecutors), 10)
	}
	if s.StartTime != "" {
		key("start_time")
		dst = appendJSONString(dst, s.StartTime)
	}
	if len(s.RestartEvents) > 0 {
		key("restart_events")
		dst = appendStdValue(dst, s.RestartEvents)
	}
	if len(s.DowntimeIntervals) > 0 {
		key("downtime_intervals")
		dst = appendStdValue(dst, s.DowntimeIntervals)
	}
	if s.LastHeartbeat != 0 {
		key("last_heartbeat")
		dst = strconv.AppendInt(dst, s.LastHeartbeat, 10)
	}
	if len(s.ProbeStates) > 0 {
		key("probe_states")
		dst = appendStdValue(dst, s.ProbeStates)
	}
	if len(s.HourlyHistory) > 0 {
		key("hourly_history")
		dst = appendStdValue(dst, s.HourlyHistory)
	}
	if len(s.DailyHistory) > 0 {
		key("daily_history")
		dst = appendStdValue(dst, s.DailyHistory)
	}
	if len(s.NetHourlyHistory) > 0 {
		key("net_hourly_history")
		dst = appendStdValue(dst, s.NetHourlyHistory)
	}
	if len(s.NetDailyHistory) > 0 {
		key("net_daily_history")
		dst = appendStdValue(dst, s.NetDailyHistory)
	}
	if len(s.AuditLog) > 0 {
		key("audit_log")
		dst = appendStdValue(dst, s.AuditLog)
	}
	if s.IDPConfig != nil {
		key("idp_config")
		dst = appendStdValue(dst, s.IDPConfig)
	}
	if s.AuditExportCfg != nil {
		key("audit_export_config")
		dst = appendStdValue(dst, s.AuditExportCfg)
	}
	if len(s.RBACPreAssign) > 0 {
		key("rbac_pre_assign")
		dst = appendStdValue(dst, s.RBACPreAssign)
	}
	if s.Term != 0 {
		key("term")
		dst = strconv.AppendUint(dst, s.Term, 10)
	}
	if s.Checksum != "" {
		key("checksum")
		dst = appendJSONString(dst, s.Checksum)
	}
	return append(dst, '}')
}

// appendPubKeyIdx writes a map[string]uint32 the way encoding/json does
// (ascending keys, decimal values).
func appendPubKeyIdx(dst []byte, m map[string]uint32) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	dst = append(dst, '{')
	for i, k := range keys {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, k)
		dst = append(dst, ':')
		dst = strconv.AppendUint(dst, uint64(m[k]), 10)
	}
	return append(dst, '}')
}

// appendStdValue appends v's standard encoding, with the snapshot encoder's
// settings (HTML escaping off), so the bytes match encoding/json exactly.
func appendStdValue(dst []byte, v interface{}) []byte {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	_ = e.Encode(v)
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return append(dst, b...)
}
