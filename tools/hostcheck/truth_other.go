//go:build !linux && !windows

package main

import "github.com/s4e-io/openness-collector/internal/schema"

// The collector has no native modules on this OS; only the command checks run.
var expectedModules []string

func (c *checker) hostTruth(doc *schema.Document) {
	c.note("no host truth checks on this OS")
}

func (c *checker) platformExtras() {}
