//go:build !windows

package windows

func readServerComponentCache() ([]serverComponent, error) { return nil, nil }
