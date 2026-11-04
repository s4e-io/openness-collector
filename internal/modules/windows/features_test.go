package windows

import (
	"context"
	"errors"
	"testing"
	"time"
)

func withFeatureStubs(t *testing.T, cache func() ([]serverComponent, error), cmdlet func(context.Context) ([]map[string]any, error)) {
	t.Helper()
	oldC, oldR := readServerComponentCacheFn, runFeaturesCmdletFn
	readServerComponentCacheFn, runFeaturesCmdletFn = cache, cmdlet
	t.Cleanup(func() { readServerComponentCacheFn, runFeaturesCmdletFn = oldC, oldR })
}

func TestWindowsFeaturesCmdletTimeoutKeepsCacheRows(t *testing.T) {
	withFeatureStubs(t,
		func() ([]serverComponent, error) {
			return []serverComponent{
				{Name: "Web-Server", InstallState: 1, HasState: true},
				{Name: "Telnet-Client", InstallState: 0, HasState: true},
				{Name: "Odd", InstallState: 7, HasState: true},
			}, nil
		},
		func(ctx context.Context) ([]map[string]any, error) {
			<-ctx.Done() // behaves like a hung Get-WindowsOptionalFeature
			return nil, ctx.Err()
		},
	)
	// Shrink the deadline for the test by wrapping ctx; the module takes the
	// min of its own constant and the parent deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	res := (&WindowsFeatures{}).Run(ctx)
	if time.Since(started) > 5*time.Second {
		t.Fatal("module did not honour the deadline")
	}
	if res.Status != "partial" {
		t.Fatalf("status=%s errors=%v", res.Status, res.Errors)
	}
	if len(res.Errors) != 1 || res.Errors[0].Code != "FEATURE_API_TIMEOUT" {
		t.Fatalf("errors=%v", res.Errors)
	}
	// context + 3 cache rows
	if len(res.Evidence) != 4 {
		t.Fatalf("evidence=%d", len(res.Evidence))
	}
	ctxRow := res.Evidence[0].Value.(map[string]any)
	if ctxRow["cmdlet_status"] != "timeout" || ctxRow["cache_rows"] != 3 {
		t.Fatalf("%v", ctxRow)
	}
	states := map[string]string{}
	for _, ev := range res.Evidence[1:] {
		v := ev.Value.(map[string]any)
		states[asString(v["feature_name"])] = asString(v["state"])
		if v["source"] != "servermanager_component_cache" {
			t.Fatalf("source %v", v["source"])
		}
	}
	if states["Web-Server"] != "enabled" || states["Telnet-Client"] != "disabled" || states["Odd"] != "unknown" {
		t.Fatalf("%v", states)
	}
}

func TestWindowsFeaturesNothingAvailable(t *testing.T) {
	withFeatureStubs(t,
		func() ([]serverComponent, error) { return nil, nil },
		func(ctx context.Context) ([]map[string]any, error) {
			return nil, errors.New("powershell.exe not found")
		},
	)
	res := (&WindowsFeatures{}).Run(context.Background())
	if res.Status != "unavailable" {
		t.Fatalf("status=%s", res.Status)
	}
	if len(res.Errors) != 1 || res.Errors[0].Code != "FEATURE_API_UNAVAILABLE" {
		t.Fatalf("errors=%v", res.Errors)
	}
}

func TestWindowsFeaturesLiveRowWinsOverCache(t *testing.T) {
	withFeatureStubs(t,
		func() ([]serverComponent, error) {
			return []serverComponent{{Name: "Web-Server", InstallState: 0, HasState: true}}, nil
		},
		func(ctx context.Context) ([]map[string]any, error) {
			return []map[string]any{
				{"entity_type": "windows_feature", "entity_id": "feature:role:Web-Server", "feature_name": "Web-Server", "state": "enabled", "source": "Get-WindowsFeature"},
				{"entity_type": "windows_feature", "entity_id": "feature:TelnetClient", "feature_name": "TelnetClient", "state": "disabled", "source": "Get-WindowsOptionalFeature"},
			}, nil
		},
	)
	res := (&WindowsFeatures{}).Run(context.Background())
	if res.Status != "success" || len(res.Evidence) != 3 {
		t.Fatalf("status=%s evidence=%d", res.Status, len(res.Evidence))
	}
	for _, ev := range res.Evidence[1:] {
		v := ev.Value.(map[string]any)
		if v["feature_name"] == "Web-Server" {
			if v["state"] != "enabled" || v["source"] != "Get-WindowsFeature" || v["cache_install_state_raw"] != int64(0) {
				t.Fatalf("merged row %v", v)
			}
		}
	}
}
