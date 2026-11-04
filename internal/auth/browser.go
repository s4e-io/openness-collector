package auth

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return openBrowserLinux(url)
	}
}

func openBrowserLinux(url string) error {
	// Root cannot talk to the desktop session; relaunch as the GUI/sudo user.
	if os.Geteuid() == 0 {
		if err := openBrowserAsDesktopUser(url); err == nil {
			return nil
		}
	}
	return openBrowserLinuxAsSelf(url)
}

func openBrowserLinuxAsSelf(url string) error {
	var candidates [][]string
	if b := strings.TrimSpace(os.Getenv("BROWSER")); b != "" {
		parts := strings.Fields(b)
		if len(parts) > 0 {
			args := append(append([]string{}, parts[1:]...), url)
			candidates = append(candidates, append([]string{parts[0]}, args...))
		}
	}
	candidates = append(candidates,
		[]string{"xdg-open", url},
		[]string{"firefox", url},
		[]string{"chromium-browser", url},
		[]string{"chromium", url},
		[]string{"google-chrome", url},
		[]string{"google-chrome-stable", url},
	)
	var tried []string
	for _, c := range candidates {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		tried = append(tried, c[0])
		if err := exec.Command(c[0], c[1:]...).Start(); err != nil {
			continue
		}
		return nil
	}
	if len(tried) == 0 {
		return fmt.Errorf("no browser found (set $BROWSER or install xdg-open/firefox/chromium)")
	}
	return fmt.Errorf("could not launch browser (tried %s)", strings.Join(tried, ", "))
}

func openBrowserAsDesktopUser(url string) error {
	u, err := desktopUser()
	if err != nil {
		return err
	}
	display := strings.TrimSpace(os.Getenv("DISPLAY"))
	if display == "" {
		display = ":0"
	}
	xauth := strings.TrimSpace(os.Getenv("XAUTHORITY"))
	if xauth == "" {
		xauth = filepath.Join(u.HomeDir, ".Xauthority")
	}
	uid := u.Uid
	dbus := fmt.Sprintf("unix:path=/run/user/%s/bus", uid)

	envPrefix := []string{
		"env",
		"DISPLAY=" + display,
		"XAUTHORITY=" + xauth,
		"DBUS_SESSION_BUS_ADDRESS=" + dbus,
		"HOME=" + u.HomeDir,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"XDG_RUNTIME_DIR=/run/user/" + uid,
	}
	if b := strings.TrimSpace(os.Getenv("BROWSER")); b != "" {
		envPrefix = append(envPrefix, "BROWSER="+b)
	}

	// runuser is available on most modern distros; fall back to sudo -u.
	runners := [][]string{
		{"runuser", "-u", u.Username, "--"},
		{"sudo", "-u", u.Username, "-H", "--"},
	}
	browsers := [][]string{
		{"xdg-open", url},
		{"firefox", url},
		{"chromium-browser", url},
		{"chromium", url},
	}
	var last error
	for _, runner := range runners {
		if _, err := exec.LookPath(runner[0]); err != nil {
			continue
		}
		for _, br := range browsers {
			if _, err := exec.LookPath(br[0]); err != nil {
				continue
			}
			args := append([]string{}, runner[1:]...)
			args = append(args, envPrefix...)
			args = append(args, br...)
			cmd := exec.Command(runner[0], args...)
			if err := cmd.Start(); err != nil {
				last = err
				continue
			}
			return nil
		}
	}
	if last != nil {
		return last
	}
	return fmt.Errorf("no desktop user/browser available for root launch")
}

func desktopUser() (*user.User, error) {
	candidates := []string{
		strings.TrimSpace(os.Getenv("SUDO_USER")),
		strings.TrimSpace(os.Getenv("PKEXEC_UID")), // may be uid; handled below
	}
	// Active seat user via loginctl (best effort).
	if out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			// SESSION UID USER SEAT TTY ...
			if len(fields) >= 3 && fields[2] != "root" {
				candidates = append(candidates, fields[2])
				break
			}
		}
	}
	for _, c := range candidates {
		if c == "" || c == "root" {
			continue
		}
		if _, err := strconv.Atoi(c); err == nil {
			u, err := user.LookupId(c)
			if err == nil && u.Username != "root" {
				return u, nil
			}
			continue
		}
		u, err := user.Lookup(c)
		if err == nil && u.Username != "root" {
			return u, nil
		}
	}
	return nil, fmt.Errorf("could not detect desktop user (try: sudo -u $USER openness-collector login)")
}

// DefaultWebBrowser reports the desktop default browser id when available (Linux xdg-settings).
func DefaultWebBrowser() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if b := strings.TrimSpace(os.Getenv("BROWSER")); b != "" {
		return b
	}
	out, err := exec.Command("xdg-settings", "get", "default-web-browser").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
