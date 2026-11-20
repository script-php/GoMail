package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gomail/config"
)

// Resolve existing symlinks even when the proposed output file does not yet
// exist. A lexical check alone can miss a backup directory linked into the
// attachment or ACME tree.
func canonicalCandidate(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	ancestor := abs
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(ancestor)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", err
		}
		missing = append(missing, filepath.Base(ancestor))
		ancestor = parent
	}
}

func validateBackupDestination(cfg *config.Config, configPath, outputPath string) error {
	output, err := canonicalCandidate(outputPath)
	if err != nil {
		return fmt.Errorf("resolving backup destination: %w", err)
	}
	for _, protected := range []struct {
		path      string
		directory bool
	}{
		{cfg.Store.DBPath, false},
		{configPath, false},
		{cfg.Store.AttachmentsPath, true},
		{cfg.TLS.ACMEDir, true},
	} {
		if protected.path == "" {
			continue
		}
		base, err := canonicalCandidate(protected.path)
		if err != nil {
			return fmt.Errorf("resolving protected backup path: %w", err)
		}
		if output == base {
			return fmt.Errorf("backup output must be outside the configured database, attachments, ACME and configuration paths")
		}
		if protected.directory {
			relative, err := filepath.Rel(base, output)
			if err != nil {
				return err
			}
			if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return fmt.Errorf("backup output must be outside the configured database, attachments, ACME and configuration paths")
			}
		}
	}
	return nil
}
