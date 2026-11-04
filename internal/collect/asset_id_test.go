package collect

import (
	"testing"

	"github.com/s4e-io/openness-collector/internal/schema"
)

func TestStableAssetID(t *testing.T) {
	a := schema.AssetInfo{Platform: "linux", MachineID: "2d791d5cce6240faa3c626058b1ffc7d"}
	first := stableAssetID(a, "random1")
	if first == "random1" || len(first) != 16 {
		t.Fatalf("machine id must derive the asset id, got %q", first)
	}
	if again := stableAssetID(a, "random2"); again != first {
		t.Fatalf("same machine must keep its asset id: %q vs %q", first, again)
	}
	a.MachineID = " 2D791D5CCE6240FAA3C626058B1FFC7D "
	if got := stableAssetID(a, "random3"); got != first {
		t.Fatalf("case and spaces must not change the id: %q", got)
	}
	if got := stableAssetID(schema.AssetInfo{Platform: "windows", MachineID: "2d791d5cce6240faa3c626058b1ffc7d"}, "x"); got == first {
		t.Fatal("platform is part of the identity")
	}
	if got := stableAssetID(schema.AssetInfo{Platform: "linux"}, "random4"); got != "random4" {
		t.Fatalf("no machine id keeps the fallback, got %q", got)
	}
}
