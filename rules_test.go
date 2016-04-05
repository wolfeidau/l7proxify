package l7proxify

// Copyright 2016 Mark Wolfe. All rights reserved.
// Use of this source code is governed by the MIT
// license which can be found in the LICENSE file.

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

type vals map[string]interface{}

func TestParseRulesMap(t *testing.T) {

	var parsetests = []struct {
		expected []*rule
		mapval   vals
	}{
		{
			expected: []*rule{
				&rule{
					Name:    "001",
					Match:   "*.amazon.com",
					Enabled: true,
					Action:  "permit",
				},
			},
			mapval: vals{
				"001": vals{
					"match":   "*.amazon.com",
					"enabled": true,
					"action":  "permit",
				},
			},
		},
	}
	for _, tt := range parsetests {

		err := LoadRuleset(tt.mapval)

		assert.Nil(t, err)
		assert.Equal(t, 1, len(ruleset))
		assert.True(t, reflect.DeepEqual(tt.expected, ruleset))

	}

}
