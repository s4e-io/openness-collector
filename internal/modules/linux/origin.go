package linux

import "strings"

// Origin basis labels: which observation a field of the origin object came
// from. The collector reports what it saw and does not decide whether an
// origin is the distribution or a third party.
const (
	originBasisAptRelease     = "apt_release_origin"
	originBasisDpkgMaintainer = "dpkg_maintainer"
	originBasisRPMVendor      = "rpm_vendor"
	originBasisRPMPackager    = "rpm_packager"
	originBasisRPMSignature   = "rpm_signature"
	originBasisAPKMaintainer  = "apk_maintainer"
)

// packageOrigin builds the origin object that every package record carries,
// with the same shape for every package manager. Fields that were not
// observed are null and basis lists only what was observed.
func packageOrigin(vendor, vendorBasis, maintainer, maintainerBasis string) map[string]any {
	vendor = cleanOriginValue(vendor)
	maintainer = cleanOriginValue(maintainer)
	basis := []string{}
	if vendor != "" {
		basis = append(basis, vendorBasis)
	}
	if maintainer != "" {
		basis = append(basis, maintainerBasis)
	}
	return map[string]any{
		"vendor":         nullIfEmpty(vendor),
		"maintainer":     nullIfEmpty(maintainer),
		"repository_url": nil,
		"signing_key_id": nil,
		"basis":          basis,
	}
}

// setOriginSigningKey records the key id of the package signature. pgpsig is
// rpm's rendering, for example "RSA/SHA256, <date>, Key ID 702d426d350d275d".
// Vendor repositories often leave the rpm Vendor tag empty; the signing key
// is then the only origin fact the package itself carries.
func setOriginSigningKey(value map[string]any, pgpsigs ...string) {
	o, ok := value["origin"].(map[string]any)
	if !ok {
		return
	}
	for _, sig := range pgpsigs {
		_, id, found := strings.Cut(sig, "Key ID ")
		id = strings.ToLower(strings.TrimSpace(id))
		if !found || id == "" || strings.ContainsAny(id, " ,\t") {
			continue
		}
		o["signing_key_id"] = id
		basis, _ := o["basis"].([]string)
		o["basis"] = append(basis, originBasisRPMSignature)
		return
	}
}

// setOriginRepository records the repository the installed version was
// matched to. vendor is the repository's own name for itself (APT Release
// Origin, else Label).
func setOriginRepository(value map[string]any, vendor, url string) {
	o, ok := value["origin"].(map[string]any)
	if !ok {
		o = packageOrigin("", "", "", "")
		value["origin"] = o
	}
	vendor = cleanOriginValue(vendor)
	if vendor != "" {
		o["vendor"] = vendor
		basis, _ := o["basis"].([]string)
		o["basis"] = append([]string{originBasisAptRelease}, basis...)
	}
	if url = strings.TrimSpace(url); url != "" {
		o["repository_url"] = url
	}
}

// cleanOriginValue drops the placeholders package managers print for an
// unset tag.
func cleanOriginValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "(none)" {
		return ""
	}
	return s
}
