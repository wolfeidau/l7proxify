package l7proxify

// Copyright 2016 Mark Wolfe. All rights reserved.
// Use of this source code is governed by the MIT
// license which can be found in the LICENSE file.

import (
	"fmt"
	"regexp"

	"github.com/apex/log"
	"github.com/mitchellh/mapstructure"
)

// Rule a filter rule for hosts
type Rule struct {
	Name    string
	Match   string
	Action  string
	Enabled bool

	cregx *regexp.Regexp
}

func (r *Rule) validate() (err error) {
	if r.Name == "" {
		return fmt.Errorf("Rule is missing name: %v", r)
	}

	switch r.Action {
	case "allow":
	case "deny":
	default:
		return fmt.Errorf("Rule has an invalid action: %v", r.Action)
	}

	r.cregx, err = regexp.Compile(r.Match)

	if err != nil {
		return fmt.Errorf("Error compiling match regexp %s", err)
	}

	return nil
}

// ruleset is global to the application and stored here
var ruleset = []*Rule{}

// LoadRuleset load the rule set supplied by configuration
//
// Need to rejig this to return a list of errors as it will be a pain for
// larger rule sets.
func LoadRuleset(rules map[string]interface{}) error {
	for k, v := range rules {
		r := new(Rule)

		if err := mapstructure.Decode(v, r); err != nil {
			return err
		}

		r.Name = k

		if err := r.validate(); err != nil {
			return err
		}

		ruleset = append(ruleset, r)

		log.WithField("rule", r).Debug("parsed rule")
	}

	return nil
}

const (
	// ActionReject reject the connection
	ActionReject = iota
	// ActionAccept accept the connection
	ActionAccept
)

// RuleMatch match information returned for a given rule scan
type RuleMatch struct {
	Action int
	Rule   *Rule
}

// MatchRule run through the ruleset looking for matches
//
// This routine will loop over the ruleset and if a rule matches then
// return the corresponding action, otherwise return nil which
// enables the caller to decide on the default action
//
func MatchRule(host string) *RuleMatch {

	for _, r := range ruleset {
		if r.cregx.MatchString(host) {
			switch r.Action {
			case "allow":
				return &RuleMatch{Rule: r, Action: ActionAccept}
			case "deny":
				return &RuleMatch{Rule: r, Action: ActionReject}
			}
		}
	}

	return nil
}
