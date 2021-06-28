package config

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/mgechev/revive/formatter"

	"github.com/BurntSushi/toml"
	"github.com/mgechev/revive/lint"
	"github.com/mgechev/revive/rule"
)

var defaultRules = []lint.Rule{
	&rule.VarDeclarationsRule{},
	&rule.PackageCommentsRule{},
	&rule.DotImportsRule{},
	&rule.BlankImportsRule{},
	&rule.ExportedRule{},
	&rule.VarNamingRule{},
	&rule.IndentErrorFlowRule{},
	&rule.IfReturnRule{},
	&rule.RangeRule{},
	&rule.ErrorfRule{},
	&rule.ErrorNamingRule{},
	&rule.ErrorStringsRule{},
	&rule.ReceiverNamingRule{},
	&rule.IncrementDecrementRule{},
	&rule.ErrorReturnRule{},
	&rule.UnexportedReturnRule{},
	&rule.TimeNamingRule{},
	&rule.ContextKeysType{},
	&rule.ContextAsArgumentRule{},
}

var allRules = append([]lint.Rule{
	&rule.ArgumentsLimitRule{},
	&rule.CyclomaticRule{},
	&rule.FileHeaderRule{},
	&rule.EmptyBlockRule{},
	&rule.SuperfluousElseRule{},
	&rule.ConfusingNamingRule{},
	&rule.GetReturnRule{},
	&rule.ModifiesParamRule{},
	&rule.ConfusingResultsRule{},
	&rule.DeepExitRule{},
	&rule.UnusedParamRule{},
	&rule.UnreachableCodeRule{},
	&rule.AddConstantRule{},
	&rule.FlagParamRule{},
	&rule.UnnecessaryStmtRule{},
	&rule.StructTagRule{},
	&rule.ModifiesValRecRule{},
	&rule.ConstantLogicalExprRule{},
	&rule.BoolLiteralRule{},
	&rule.RedefinesBuiltinIDRule{},
	&rule.ImportsBlacklistRule{},
	&rule.FunctionResultsLimitRule{},
	&rule.MaxPublicStructsRule{},
	&rule.RangeValInClosureRule{},
	&rule.RangeValAddress{},
	&rule.WaitGroupByValueRule{},
	&rule.AtomicRule{},
	&rule.EmptyLinesRule{},
	&rule.LineLengthLimitRule{},
	&rule.CallToGCRule{},
	&rule.DuplicatedImportsRule{},
	&rule.ImportShadowingRule{},
	&rule.BareReturnRule{},
	&rule.UnusedReceiverRule{},
	&rule.UnhandledErrorRule{},
	&rule.CognitiveComplexityRule{},
	&rule.StringOfIntRule{},
	&rule.EarlyReturnRule{},
	&rule.UnconditionalRecursionRule{},
	&rule.IdenticalBranchesRule{},
	&rule.DeferRule{},
	&rule.UnexportedNamingRule{},
	&rule.FunctionLength{},
}, defaultRules...)

var allFormatters = []lint.Formatter{
	&formatter.Stylish{},
	&formatter.Friendly{},
	&formatter.JSON{},
	&formatter.NDJSON{},
	&formatter.Default{},
	&formatter.Unix{},
	&formatter.Checkstyle{},
	&formatter.Plain{},
	&formatter.Sarif{},
}

func getFormatters() map[string]lint.Formatter {
	result := map[string]lint.Formatter{}
	for _, f := range allFormatters {
		result[f.Name()] = f
	}
	return result
}

// GetLintingRules yields the linting rules activated in the configuration
func GetLintingRules(config *lint.Config) ([]lint.Rule, error) {
	rulesMap := map[string]lint.Rule{}
	for _, r := range allRules {
		rulesMap[r.Name()] = r
	}

	lintingRules := []lint.Rule{}
	for name := range config.Rules {
		rule, ok := rulesMap[name]
		if !ok {
			return nil, fmt.Errorf("cannot find rule: %s", name)
		}
		lintingRules = append(lintingRules, rule)
	}

	return lintingRules, nil
}

func parseConfig(path string) (*lint.Config, error) {
	config := &lint.Config{}
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read the config file")
	}
	_, err = toml.Decode(string(file), config)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the config file: %v", err)
	}
	return config, nil
}

func normalizeConfig(config *lint.Config) {
	if config.Confidence == 0 {
		config.Confidence = 0.8
	}
	severity := config.Severity
	if severity != "" {
		for k, v := range config.Rules {
			if v.Severity == "" {
				v.Severity = severity
			}
			config.Rules[k] = v
		}
		for k, v := range config.Directives {
			if v.Severity == "" {
				v.Severity = severity
			}
			config.Directives[k] = v
		}
	}
}

// GetConfig yields the configuration
func GetConfig(configPath string) (*lint.Config, error) {
	config := defaultConfig()
	if configPath != "" {
		var err error
		config, err = parseConfig(configPath)
		if err != nil {
			return nil, err
		}
	}
	normalizeConfig(config)
	return config, nil
}

// GetFormatter yields the formatter for lint failures
func GetFormatter(formatterName string) (lint.Formatter, error) {
	formatters := getFormatters()
	formatter := formatters["default"]
	if formatterName != "" {
		f, ok := formatters[formatterName]
		if !ok {
			return nil, fmt.Errorf("unknown formatter %v", formatterName)
		}
		formatter = f
	}
	return formatter, nil
}

func defaultConfig() *lint.Config {
	defaultConfig := lint.Config{
		Confidence: 0.0,
		Severity:   lint.SeverityWarning,
		Rules:      map[string]lint.RuleConfig{},
	}
	for _, r := range defaultRules {
		defaultConfig.Rules[r.Name()] = lint.RuleConfig{}
	}
	return &defaultConfig
}
