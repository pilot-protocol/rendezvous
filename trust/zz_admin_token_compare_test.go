// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestCheckAdminTokenComparesInConstantTime pins that the admin-token
// check does not short-circuit on the first differing byte, which would
// let the time a rejection takes reveal how much of the token was
// correct and make the secret recoverable byte by byte.
//
// Constant-time behaviour cannot be asserted by measuring: the
// difference is nanoseconds and any timing threshold is a flake. So this
// inspects the comparison the function actually performs — it must go
// through crypto/subtle, and must not compare the supplied token against
// the expected one with a language-level string operator, which is what
// every sibling admin-token check in this repo (authz, membership,
// dashboard, accept) already does.
func TestCheckAdminTokenComparesInConstantTime(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "trust.go", nil, 0)
	if err != nil {
		t.Fatalf("parse trust.go: %v", err)
	}

	fn := findFunc(file, "checkAdminToken")
	if fn == nil {
		t.Fatal("checkAdminToken not found in trust.go")
	}

	var usesSubtle bool
	var directCompares []string
	ast.Inspect(fn, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok &&
					pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
					usesSubtle = true
				}
			}
		case *ast.BinaryExpr:
			if v.Op != token.EQL && v.Op != token.NEQ {
				return true
			}
			l, r := exprName(v.X), exprName(v.Y)
			if (l == "token" && r == "adminToken") || (l == "adminToken" && r == "token") {
				directCompares = append(directCompares, l+" "+v.Op.String()+" "+r)
			}
		}
		return true
	})

	if !usesSubtle {
		t.Error("checkAdminToken does not call subtle.ConstantTimeCompare")
	}
	if len(directCompares) > 0 {
		t.Errorf("checkAdminToken compares the token directly (%s); the comparison must not short-circuit",
			strings.Join(directCompares, ", "))
	}
}

func findFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name && fn.Recv == nil {
			return fn
		}
	}
	return nil
}

func exprName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// TestCheckAdminTokenOutcomesUnchanged pins that swapping the comparison
// did not change which tokens are accepted, including the cases where a
// length-based shortcut would be tempting.
func TestCheckAdminTokenOutcomesUnchanged(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		supplied interface{}
		expected string
		wantErr  bool
	}{
		{"exact match", "s3cret", "s3cret", false},
		{"no token configured", "anything", "", true},
		{"empty supplied", "", "s3cret", true},
		{"field absent", nil, "s3cret", true},
		{"wrong type", 42.0, "s3cret", true},
		{"correct prefix", "s3c", "s3cret", true},
		{"correct prefix plus suffix", "s3cretX", "s3cret", true},
		{"same length, last byte differs", "s3crey", "s3cret", true},
		{"case differs", "S3CRET", "s3cret", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := map[string]interface{}{}
			if tc.supplied != nil {
				msg["admin_token"] = tc.supplied
			}
			err := checkAdminToken(msg, tc.expected)
			if tc.wantErr && err == nil {
				t.Fatalf("checkAdminToken(%v, %q) = nil; want an error", tc.supplied, tc.expected)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkAdminToken(%v, %q) = %v; want nil", tc.supplied, tc.expected, err)
			}
		})
	}
}
