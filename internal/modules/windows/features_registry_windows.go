//go:build windows

package windows

import (
	"golang.org/x/sys/windows/registry"
)

const serverComponentCacheKey = `SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache`

// readServerComponentCache enumerates the Server Manager component cache.
// Each subkey is a role/feature name with an InstallState DWORD. The key is
// absent on client SKUs and on servers where Server Manager never ran; that
// is reported as an empty list, not an error.
func readServerComponentCache() ([]serverComponent, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, serverComponentCacheKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil, nil
		}
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	out := make([]serverComponent, 0, len(names))
	for _, n := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, serverComponentCacheKey+`\`+n, registry.QUERY_VALUE)
		if err != nil {
			out = append(out, serverComponent{Name: n})
			continue
		}
		c := serverComponent{Name: n}
		if v, _, err := sk.GetIntegerValue("InstallState"); err == nil {
			c.InstallState = int64(v)
			c.HasState = true
		}
		sk.Close()
		out = append(out, c)
	}
	return out, nil
}
