// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import "testing"

func TestJsonUint16_HelperBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   map[string]interface{}
		key  string
		want uint16
	}{
		{map[string]interface{}{"k": float64(42)}, "k", 42},
		{map[string]interface{}{"k": float64(-1)}, "k", 0},
		{map[string]interface{}{"k": float64(70000)}, "k", 0},
		{map[string]interface{}{"k": "string"}, "k", 0},
		{map[string]interface{}{}, "missing", 0},
	}
	for _, tc := range cases {
		if got := jsonUint16(tc.in, tc.key); got != tc.want {
			t.Errorf("jsonUint16(%v, %q) = %d, want %d", tc.in, tc.key, got, tc.want)
		}
	}
}

func TestJsonUint32_HelperBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   map[string]interface{}
		key  string
		want uint32
	}{
		{map[string]interface{}{"k": float64(42)}, "k", 42},
		{map[string]interface{}{"k": float64(-1)}, "k", 0},
		{map[string]interface{}{"k": float64(1e20)}, "k", 0},
		{map[string]interface{}{"k": "string"}, "k", 0},
		{map[string]interface{}{}, "missing", 0},
	}
	for _, tc := range cases {
		if got := jsonUint32(tc.in, tc.key); got != tc.want {
			t.Errorf("jsonUint32(%v, %q) = %d, want %d", tc.in, tc.key, got, tc.want)
		}
	}
}
