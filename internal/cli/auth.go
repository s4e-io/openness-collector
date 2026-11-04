package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/s4e-io/openness-collector/internal/auth"
)

func newLogin() *cobra.Command {
	var (
		token     string
		tokenPage string
		checkURL  string
		noBrowser bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Save an S4E API token for uploads (opens app.s4e.io/api-token)",
		Long: `KISS login for openness-collector:

1. Opens https://app.s4e.io/api-token in your browser
2. You create/copy an API Token there
3. Paste it here; openness-collector checks it against api.s4e.io and stores it locally

No OAuth device flow yet. Same credential type the Chrome extension ends up with,
just obtained manually from the API Token page.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tokenPage == "" {
				tokenPage = auth.DefaultTokenPage
			}
			if checkURL == "" {
				checkURL = auth.DefaultCheckURL
			}

			if strings.TrimSpace(token) == "" {
				fmt.Fprintf(os.Stderr, "Create/copy an API Token here:\n  %s\n\n", tokenPage)
				if !noBrowser {
					if def := auth.DefaultWebBrowser(); def != "" {
						fmt.Fprintf(os.Stderr, "Default browser: %s\n", def)
					}
					if os.Geteuid() == 0 {
						fmt.Fprintln(os.Stderr, "Running as root: opening browser as the desktop user (SUDO_USER / active session).")
					}
					if err := auth.OpenBrowser(tokenPage); err != nil {
						fmt.Fprintf(os.Stderr, "Browser open failed: %v\n", err)
						fmt.Fprintln(os.Stderr, "Open the URL above in Firefox/Chromium, then paste the token below.")
					} else if os.Geteuid() == 0 {
						fmt.Fprintln(os.Stderr, "Opened browser as desktop user.")
					} else {
						fmt.Fprintln(os.Stderr, "Opened via default browser ($BROWSER / xdg-open).")
					}
					fmt.Fprintln(os.Stderr)
				}
				fmt.Fprint(os.Stderr, "Paste API Token, then press Enter: ")
				line, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil {
					return err
				}
				token = strings.TrimSpace(line)
			}
			if token == "" {
				return fmt.Errorf("empty token")
			}

			fmt.Fprintln(os.Stderr, "Checking token against", checkURL, "...")
			res, err := auth.CheckToken(cmd.Context(), checkURL, token)
			if err != nil {
				return err
			}
			if !res.OK {
				return fmt.Errorf("login failed: %s", res.Message)
			}

			if err := auth.Save(auth.Credentials{
				Token:     token,
				Source:    "login",
				CheckURL:  checkURL,
				TokenPage: tokenPage,
			}); err != nil {
				return err
			}
			path, _ := auth.CredentialsPath()
			fmt.Fprintf(os.Stderr, "login OK; saved %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "API token (skip paste prompt)")
	cmd.Flags().StringVar(&tokenPage, "token-page", auth.DefaultTokenPage, "URL opened for token creation")
	cmd.Flags().StringVar(&checkURL, "check-url", auth.DefaultCheckURL, "token validation URL")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open a browser")
	return cmd
}

func newLogout() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the locally saved API token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := auth.Delete(); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "logged out")
			return nil
		},
	}
}

func newWhoAmI() *cobra.Command {
	var checkURL string
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Validate the saved (or env) API token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if checkURL == "" {
				checkURL = auth.DefaultCheckURL
			}
			tok, src, err := auth.ResolveToken("", "OPENNESS_API_KEY")
			if err != nil {
				return err
			}
			res, err := auth.CheckToken(cmd.Context(), checkURL, tok)
			if err != nil {
				return err
			}
			if !res.OK {
				return fmt.Errorf("token invalid (%s): %s", src, res.Message)
			}
			fmt.Printf("ok source=%s check=%s\n", src, checkURL)
			return nil
		},
	}
	cmd.Flags().StringVar(&checkURL, "check-url", auth.DefaultCheckURL, "token validation URL")
	return cmd
}
