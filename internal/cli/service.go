package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"text/template"

	"github.com/spf13/cobra"
)

const launchLabel = "dev.mumudevx.dpb"

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Exe}}</string>
		<string>run</string>
		<string>--profile</string>
		<string>{{.Profile}}</string>
		<string>--port</string>
		<string>{{.Port}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>{{.LogPath}}</string>
	<key>StandardErrorPath</key>
	<string>{{.LogPath}}</string>
</dict>
</plist>
`

func plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchLabel+".plist")
}

func logPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Logs", "dpb.log")
}

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage the dpb launchd background service",
	}

	var profile string
	var port int
	install := &cobra.Command{
		Use:   "install",
		Short: "Install and start the launchd agent",
		RunE: func(*cobra.Command, []string) error {
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			path := plistPath()
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			tmpl := template.Must(template.New("plist").Parse(plistTemplate))
			out, err := os.Create(path)
			if err != nil {
				return err
			}
			data := map[string]string{
				"Label": launchLabel, "Exe": exe, "Profile": profile,
				"Port": strconv.Itoa(port), "LogPath": logPath(),
			}
			if err := tmpl.Execute(out, data); err != nil {
				out.Close()
				return err
			}
			out.Close()
			if err := runLaunchctl("load", "-w", path); err != nil {
				return err
			}
			fmt.Printf("installed %s (profile=%s port=%d)\nlogs: %s\n", launchLabel, profile, port, logPath())
			return nil
		},
	}
	install.Flags().StringVar(&profile, "profile", "turkey", "region profile for the service")
	install.Flags().IntVar(&port, "port", 8080, "proxy port")

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the launchd agent",
		RunE: func(*cobra.Command, []string) error {
			_ = runLaunchctl("unload", "-w", plistPath())
			if err := os.Remove(plistPath()); err != nil && !os.IsNotExist(err) {
				return err
			}
			fmt.Println("uninstalled", launchLabel)
			return nil
		},
	}

	start := &cobra.Command{
		Use:   "start",
		Short: "Start the service",
		RunE:  func(*cobra.Command, []string) error { return runLaunchctl("start", launchLabel) },
	}
	stop := &cobra.Command{
		Use:   "stop",
		Short: "Stop the service",
		RunE:  func(*cobra.Command, []string) error { return runLaunchctl("stop", launchLabel) },
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show service status",
		RunE: func(*cobra.Command, []string) error {
			out, _ := exec.Command("launchctl", "list").Output()
			for _, line := range splitLines(string(out)) {
				if contains(line, launchLabel) {
					fmt.Println(line)
					return nil
				}
			}
			fmt.Println("not running")
			return nil
		},
	}
	logs := &cobra.Command{
		Use:   "logs",
		Short: "Print the service log path",
		RunE: func(*cobra.Command, []string) error {
			fmt.Println(logPath())
			return nil
		},
	}

	cmd.AddCommand(install, uninstall, start, stop, status, logs)
	return cmd
}

func runLaunchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %v: %s", args, out)
	}
	return nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
