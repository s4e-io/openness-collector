package linux

import (
	"reflect"
	"strings"
	"testing"

	"github.com/s4e-io/openness-collector/internal/modules/common"
)

func originOf(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("value is %T", v)
	}
	o, ok := m["origin"].(map[string]any)
	if !ok {
		t.Fatalf("no origin object in %#v", m)
	}
	return o
}

func wantOrigin(t *testing.T, o map[string]any, vendor, maintainer, url any, basis []string) {
	t.Helper()
	if o["vendor"] != vendor || o["maintainer"] != maintainer || o["repository_url"] != url {
		t.Fatalf("origin = %#v", o)
	}
	if got, _ := o["basis"].([]string); !reflect.DeepEqual(got, basis) {
		t.Fatalf("basis = %#v, want %#v", o["basis"], basis)
	}
}

func TestDPKGOriginFromMaintainerAndAptLists(t *testing.T) {
	res := common.NewResult("packages", "t")
	appendDPKGQueryLine(&res, "packages", "docker-ce\t5:28.5.0-1~ubuntu.24.04~noble\tamd64\tinstall ok installed\t\tDocker <support@docker.com>")
	appendDPKGQueryLine(&res, "packages", "localdeb\t1.0\tamd64\tinstall ok installed\t\tJane Doe <jane@example.org>")
	appendDPKGQueryLine(&res, "packages", "bare\t1.0\tamd64\tinstall ok installed")

	idx := &aptListsIndex{
		ByNVRA: map[string]aptListOrigin{
			"docker-ce|5:28.5.0-1~ubuntu.24.04~noble|amd64": {
				URL: "https://download.docker.com/linux/ubuntu", Origin: "Docker", Label: "Docker CE", Suite: "noble",
			},
		},
		Candidates: map[string]aptCandidate{},
	}
	for i := range res.Evidence {
		applyAptOriginToPackage(res.Evidence[i].Value.(map[string]any), idx)
	}

	wantOrigin(t, originOf(t, res.Evidence[0].Value), "Docker", "Docker <support@docker.com>",
		"https://download.docker.com/linux/ubuntu", []string{originBasisAptRelease, originBasisDpkgMaintainer})
	// Not in the apt lists: the maintainer is still reported, nothing is guessed.
	wantOrigin(t, originOf(t, res.Evidence[1].Value), nil, "Jane Doe <jane@example.org>", nil, []string{originBasisDpkgMaintainer})
	wantOrigin(t, originOf(t, res.Evidence[2].Value), nil, nil, nil, []string{})
}

func TestDPKGStatusOriginMaintainer(t *testing.T) {
	res := common.NewResult("packages", "t")
	status := "Package: containerd.io\nStatus: install ok installed\nMaintainer: Containerd team <help@containerd.io>\nArchitecture: amd64\nVersion: 1.7.28-1\n\n"
	if _, err := appendDPKGStatus(&res, "packages", strings.NewReader(status)); err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) != 1 {
		t.Fatalf("evidence = %d", len(res.Evidence))
	}
	wantOrigin(t, originOf(t, res.Evidence[0].Value), nil, "Containerd team <help@containerd.io>", nil, []string{originBasisDpkgMaintainer})
}

func TestRPMOriginVendorAndPackager(t *testing.T) {
	res := common.NewResult("packages", "t")
	appendRPMLine(&res, "packages", "docker-ce\t3\t28.5.0\t1.el9\tx86_64\tDocker\t1730000000\tdocker-ce-28.5.0-1.el9.src.rpm\tDocker <support@docker.com>")
	appendRPMLine(&res, "packages", "localrpm\t(none)\t1.0\t1\tx86_64\t(none)\t1730000000\tlocalrpm-1.0-1.src.rpm\t(none)\t(none)\t(none)")
	// A vendor repository package: no Vendor, no Packager, only a signature.
	appendRPMLine(&res, "packages", "containerd.io\t(none)\t1.7.28\t1.el9\tx86_64\t(none)\t1730000000\tcontainerd.io-1.7.28-1.el9.src.rpm\t(none)\tRSA/SHA512, Thu Nov 12 10:38:47 2026, Key ID C52FEB6B621E9F35\t(none)")
	// Output of an older format string without the packager column.
	appendRPMLine(&res, "packages", "bash\t(none)\t5.1.8\t9.el9\tx86_64\tRed Hat, Inc.\t1730000000\tbash-5.1.8-9.el9.src.rpm")

	wantOrigin(t, originOf(t, res.Evidence[0].Value), "Docker", "Docker <support@docker.com>", nil, []string{originBasisRPMVendor, originBasisRPMPackager})
	wantOrigin(t, originOf(t, res.Evidence[1].Value), nil, nil, nil, []string{})
	wantOrigin(t, originOf(t, res.Evidence[3].Value), "Red Hat, Inc.", nil, nil, []string{originBasisRPMVendor})
	signed := originOf(t, res.Evidence[2].Value)
	wantOrigin(t, signed, nil, nil, nil, []string{originBasisRPMSignature})
	if signed["signing_key_id"] != "c52feb6b621e9f35" {
		t.Fatalf("signing_key_id = %#v", signed["signing_key_id"])
	}
	if k := originOf(t, res.Evidence[1].Value)["signing_key_id"]; k != nil {
		t.Fatalf("unsigned package got key %#v", k)
	}
}

func TestAPKOriginMaintainer(t *testing.T) {
	res := common.NewResult("packages", "t")
	appendAPKPackage(&res, "packages", apkPackage{Name: "musl", Version: "1.2.5-r0", Arch: "x86_64", Origin: "musl", Maintainer: "Natanael Copa <ncopa@alpinelinux.org>"}, "/lib/apk/db/installed")
	appendAPKPackage(&res, "packages", apkPackage{Name: "local-tool", Version: "0.1", Arch: "noarch"}, "/lib/apk/db/installed")

	wantOrigin(t, originOf(t, res.Evidence[0].Value), nil, "Natanael Copa <ncopa@alpinelinux.org>", nil, []string{originBasisAPKMaintainer})
	wantOrigin(t, originOf(t, res.Evidence[1].Value), nil, nil, nil, []string{})
}
