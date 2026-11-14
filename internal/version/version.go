package version

// Values are overridden at link time by Go ldflags in CI and scripts/build.sh.
var (
	Version = "0.9.0"
	Commit  = "unknown"
	Date    = "unknown"
)

func SemVer() string {
	if Version == "" {
		return "0.0.0"
	}
	return Version
}
