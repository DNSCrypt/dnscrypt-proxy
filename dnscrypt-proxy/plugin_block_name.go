package main

import (
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginBlockType int

const (
	PluginBlockTypeNone = iota
	PluginBlockTypePrefix
	PluginBlockTypeSuffix
	PluginBlockTypeSubstring
	PluginBlockTypePattern
)

type PluginBlockName struct {
	blockedPrefixes   *iradix.Tree
	blockedSuffixes   *iradix.Tree
	blockedSubstrings []string
	blockedPatterns   []string
}

func (plugin *PluginBlockName) Name() string {
	return "block_name"
}

func (plugin *PluginBlockName) Description() string {
	return "Block DNS queries matching name patterns"
}

func (plugin *PluginBlockName) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of blocking rules from [%s]", proxy.blockNameFile)
	bin, err := ioutil.ReadFile(proxy.blockNameFile)
	if err != nil {
		return err
	}
	plugin.blockedPrefixes = iradix.New()
	plugin.blockedSuffixes = iradix.New()
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = strings.Trim(line, " \t\r\n")
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		leadingStar := strings.HasPrefix(line, "*")
		trailingStar := strings.HasSuffix(line, "*")
		blockType := PluginBlockTypeNone
		if isGlobCandidate(line) {
			blockType = PluginBlockTypePattern
			_, err := filepath.Match(line, "example.com")
			if len(line) < 2 || err != nil {
				dlog.Errorf("Syntax error in block rules at line %d", 1+lineNo)
				continue
			}
		} else if leadingStar && trailingStar {
			blockType = PluginBlockTypeSubstring
			if len(line) < 3 {
				dlog.Errorf("Syntax error in block rules at line %d", 1+lineNo)
				continue
			}
			line = line[1 : len(line)-1]
		} else if trailingStar {
			blockType = PluginBlockTypePrefix
			if len(line) < 2 {
				dlog.Errorf("Syntax error in block rules at line %d", 1+lineNo)
				continue
			}
			line = line[:len(line)-1]
		} else {
			blockType = PluginBlockTypeSuffix
			if leadingStar {
				line = line[1:]
			}
			if strings.HasPrefix(line, ".") {
				line = line[1:]
			}
		}
		if len(line) == 0 {
			dlog.Errorf("Syntax error in block rule at line %d", 1+lineNo)
			continue
		}
		line = strings.ToLower(line)
		switch blockType {
		case PluginBlockTypeSubstring:
			plugin.blockedSubstrings = append(plugin.blockedSubstrings, line)
		case PluginBlockTypePattern:
			plugin.blockedPatterns = append(plugin.blockedPatterns, line)
		case PluginBlockTypePrefix:
			plugin.blockedPrefixes, _, _ = plugin.blockedPrefixes.Insert([]byte(line), 0)
		case PluginBlockTypeSuffix:
			plugin.blockedSuffixes, _, _ = plugin.blockedSuffixes.Insert([]byte(StringReverse(line)), 0)
		default:
			dlog.Fatal("Unexpected block type")
		}
	}
	return nil
}

func (plugin *PluginBlockName) Drop() error {
	return nil
}

func (plugin *PluginBlockName) Reload() error {
	return nil
}

func (plugin *PluginBlockName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := strings.ToLower(StripTrailingDot(questions[0].Name))
	revQuestion := StringReverse(question)
	match, _, found := plugin.blockedSuffixes.Root().LongestPrefix([]byte(revQuestion))
	if found {
		if len(match) == len(question) || question[len(match)] == '.' {
			pluginsState.action = PluginsActionReject
			return nil
		}
	}
	_, _, found = plugin.blockedPrefixes.Root().LongestPrefix([]byte(question))
	if found {
		pluginsState.action = PluginsActionReject
		return nil
	}
	for _, substring := range plugin.blockedSubstrings {
		if strings.Contains(substring, question) {
			pluginsState.action = PluginsActionReject
			return nil
		}
	}
	for _, pattern := range plugin.blockedPatterns {
		if found, _ := filepath.Match(pattern, question); found {
			pluginsState.action = PluginsActionReject
			return nil
		}
	}
	return nil
}

func isGlobCandidate(str string) bool {
	for i, c := range str {
		if c == '?' || c == '[' {
			return true
		} else if c == '*' && i != 0 && i != len(str)-1 {
			return true
		}
	}
	return false
}
