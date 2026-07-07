// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"fmt"
	"sort"
	"strings"
)

// This is a deliberately small template engine used to render service files.
// A template is parsed once into a tree of nodes and then executed by walking
// that tree, so rendering scans nothing. A value is either a string or a
// []string; a []string is iterable with {{range Key}}…{{end}} and is truthy
// when non-empty.
//
// It exists to avoid text/template. text/template reaches
// reflect.Value.MethodByName, which forces the Go linker into conservative
// mode: it must then keep every exported method of every concrete type that
// implements any interface used in the binary, defeating dead-code elimination
// and inflating binaries that merely import this package (issue #418).

// tmplFunc is the only function shape the engine supports: string in, string
// out. Because every value is a string, functions are called directly and the
// engine never needs reflection.
type tmplFunc func(string) (string, error)

type nodeKind uint8

const (
	nodeText  nodeKind = iota // literal text
	nodeValue                 // {{ Key }}, {{ Key | fn | fn }}, or {{ . }}
	nodeIf                    // {{ if Key }} body {{ else }} alt {{ end }}
	nodeRange                 // {{ range Key }} body {{ end }}
)

// node is a single template operation. text holds literal text for nodeText or
// the lookup key for the other kinds; body/alt hold nested nodes for the block
// forms.
type node struct {
	kind  nodeKind
	text  string
	funcs []string // pipeline of function names (nodeValue only)
	body  []node   // nodeIf / nodeRange body
	alt   []node   // nodeIf else-branch
}

// tmpl is a parsed template. Parsing scans the source once; a tmpl can then be
// rendered any number of times, so the constant service-file templates are
// parsed a single time at package init and rendered per install.
type tmpl struct {
	nodes []node
}

// parseTemplate parses text into a reusable tmpl.
func parseTemplate(text string) (*tmpl, error) {
	nodes, _, _, _, err := parseNodes(text, false)
	if err != nil {
		return nil, err
	}
	return &tmpl{nodes: nodes}, nil
}

// mustParse is parseTemplate for the built-in templates, which are constants
// and cannot fail at runtime. It panics on a malformed template, surfacing the
// mistake at init time.
func mustParse(text string) *tmpl {
	t, err := parseTemplate(text)
	if err != nil {
		panic(err)
	}
	return t
}

// render executes the template against data and funcs. Each value in data is a
// string or a []string; funcs supplies the string transforms usable in a
// {{ Key | fn }} pipeline. render does not mutate the tmpl and is safe to call
// repeatedly.
func (t *tmpl) render(data map[string]any, funcs map[string]tmplFunc) (string, error) {
	var b strings.Builder
	if err := execNodes(&b, t.nodes, data, nil, funcs); err != nil {
		return "", err
	}
	return b.String(), nil
}

// renderTemplate is a one-shot convenience that parses text and renders it
// once. Prefer parseTemplate + (*tmpl).render when the same template is used
// more than once.
func renderTemplate(text string, data map[string]any, funcs map[string]tmplFunc) (string, error) {
	t, err := parseTemplate(text)
	if err != nil {
		return "", err
	}
	return t.render(data, funcs)
}

// parseNodes parses src into nodes, stopping when it reaches one of the given
// terminator keywords (used to bound if/range bodies). trimLeading requests
// that leading whitespace of the first literal be trimmed (a {{... -}} carried
// in from the caller). It returns the parsed nodes, the terminator that
// stopped it ("" at end of input), the unparsed remainder of src, and whether
// that terminator asked to trim the whitespace that follows it. This is the
// only code that scans the template.
func parseNodes(src string, trimLeading bool, terminators ...string) (nodes []node, term, rest string, trimNext bool, err error) {
	for {
		open := strings.Index(src, "{{")

		lit := src
		var action string
		var haveAction, trimBefore, trimAfter bool
		if open >= 0 {
			close := strings.Index(src[open:], "}}")
			if close < 0 {
				return nil, "", "", false, fmt.Errorf(`service: unclosed "{{" in template`)
			}
			lit = src[:open]
			action = src[open+2 : open+close]
			src = src[open+close+2:]
			haveAction = true

			if strings.HasPrefix(action, "-") {
				trimBefore, action = true, action[1:]
			}
			if strings.HasSuffix(action, "-") {
				trimAfter, action = true, action[:len(action)-1]
			}
			action = strings.TrimSpace(action)
		} else {
			src = ""
		}

		if trimLeading {
			lit = strings.TrimLeft(lit, " \t\r\n")
		}
		if trimBefore {
			lit = strings.TrimRight(lit, " \t\r\n")
		}
		if lit != "" {
			nodes = append(nodes, node{kind: nodeText, text: lit})
		}
		trimLeading = trimAfter

		if !haveAction {
			return nodes, "", "", false, nil
		}

		// Dispatch on the first word, delimited by a space or a pipe.
		kw := action
		if i := strings.IndexAny(action, " \t|"); i >= 0 {
			kw = action[:i]
		}
		switch kw {
		case "end", "else":
			for _, t := range terminators {
				if kw == t {
					return nodes, kw, src, trimAfter, nil
				}
			}
			return nil, "", "", false, fmt.Errorf("service: unexpected %q in template", kw)
		case "if", "range":
			key := strings.TrimSpace(action[len(kw):])
			if key == "" {
				return nil, "", "", false, fmt.Errorf("service: %q requires a key", kw)
			}
			n := node{kind: nodeIf, text: key}
			var stop string
			var tn bool
			if kw == "range" {
				n.kind = nodeRange
				n.body, stop, src, tn, err = parseNodes(src, trimAfter, "end")
			} else {
				n.body, stop, src, tn, err = parseNodes(src, trimAfter, "else", "end")
			}
			if err != nil {
				return nil, "", "", false, err
			}
			if stop == "else" {
				if n.alt, _, src, tn, err = parseNodes(src, tn, "end"); err != nil {
					return nil, "", "", false, err
				}
			}
			trimLeading = tn
			nodes = append(nodes, n)
		default:
			parts := strings.Split(action, "|")
			n := node{kind: nodeValue, text: strings.TrimSpace(parts[0])}
			for _, p := range parts[1:] {
				n.funcs = append(n.funcs, strings.TrimSpace(p))
			}
			nodes = append(nodes, n)
		}
	}
}

// execNodes walks nodes, writing output to b. dot is the current element while
// inside a range and is referenced as {{ . }}.
func execNodes(b *strings.Builder, nodes []node, data map[string]any, dot any, funcs map[string]tmplFunc) error {
	for i := range nodes {
		n := &nodes[i]
		switch n.kind {
		case nodeText:
			b.WriteString(n.text)
		case nodeValue:
			v, err := lookup(data, dot, n.text)
			if err != nil {
				return err
			}
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("service: template key %q is not a string", n.text)
			}
			for _, name := range n.funcs {
				fn, ok := funcs[name]
				if !ok {
					return fmt.Errorf("service: unknown template function %q", name)
				}
				if s, err = fn(s); err != nil {
					return err
				}
			}
			b.WriteString(s)
		case nodeIf:
			v, err := lookup(data, dot, n.text)
			if err != nil {
				return err
			}
			if truthy(v) {
				err = execNodes(b, n.body, data, dot, funcs)
			} else {
				err = execNodes(b, n.alt, data, dot, funcs)
			}
			if err != nil {
				return err
			}
		case nodeRange:
			v, err := lookup(data, dot, n.text)
			if err != nil {
				return err
			}
			items, ok := v.([]string)
			if !ok {
				return fmt.Errorf("service: template key %q is not a list", n.text)
			}
			for _, item := range items {
				if err := execNodes(b, n.body, data, item, funcs); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// lookup resolves a key to its value. The special key "." is the current range
// element.
func lookup(data map[string]any, dot any, key string) (any, error) {
	if key == "." {
		return dot, nil
	}
	v, ok := data[key]
	if !ok {
		return nil, fmt.Errorf("service: unknown template key %q", key)
	}
	return v, nil
}

// envVars renders vars as a []string, one entry per key formatted by f, sorted
// by key so the output is deterministic (text/template also ranged maps in
// sorted key order). The result is meant to be iterated with {{range}}. It
// returns nil when vars is empty. Each platform supplies its own f because the
// per-entry syntax differs (Environment=, export, plist key/string, …).
func envVars(vars map[string]string, f func(key, value string) string) []string {
	if len(vars) == 0 {
		return nil
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, f(k, vars[k]))
	}
	return out
}

// truthy reports whether v selects the {{if}} body: a non-empty string or a
// non-empty list.
func truthy(v any) bool {
	switch t := v.(type) {
	case string:
		return t != ""
	case []string:
		return len(t) > 0
	}
	return false
}
