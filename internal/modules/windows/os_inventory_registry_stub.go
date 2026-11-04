//go:build !windows

package windows

import "fmt"

func readOSIdentityFromRegistry() (map[string]any, error) {
	return nil, fmt.Errorf("native registry os inventory is only available on windows")
}
