package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// runSoulDiff implements `starfly soul diff <file1> <file2>` and
// `starfly soul diff --anchor <path> --fabric <id> <seq1> <seq2>`.
func runSoulDiff(args []string) int {
	fs := flag.NewFlagSet("soul diff", flag.ExitOnError)
	var (
		jsonOutput bool
		anchorPath string
		fabricID   string
	)
	fs.BoolVar(&jsonOutput, "json", false, "output as JSON")
	fs.StringVar(&anchorPath, "anchor", "", "FSAnchor root directory (requires --fabric)")
	fs.StringVar(&fabricID, "fabric", "", "fabric ID (used with --anchor)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  starfly soul diff <file1> <file2>                            Compare two manifest files
  starfly soul diff --anchor <dir> --fabric <id> <seq1> <seq2> Compare two sequences from anchor

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()

	var from, to *soul.SoulManifest
	var err error

	if anchorPath != "" {
		if fabricID == "" {
			fmt.Fprintf(os.Stderr, "error: --fabric is required with --anchor\n")
			return 1
		}
		if len(remaining) != 2 {
			fmt.Fprintf(os.Stderr, "error: --anchor mode requires exactly two sequence numbers\n")
			fs.Usage()
			return 1
		}
		from, to, err = loadFromAnchor(anchorPath, fabricID, remaining[0], remaining[1])
	} else {
		if len(remaining) != 2 {
			fmt.Fprintf(os.Stderr, "error: expected exactly two manifest file paths\n")
			fs.Usage()
			return 1
		}
		from, err = loadManifestFile(remaining[0])
		if err == nil {
			to, err = loadManifestFile(remaining[1])
		}
	}

	if err != nil {
		slog.Error("loading manifests", "error", err)
		return 1
	}

	diff := soul.Diff(from, to)

	if jsonOutput {
		data, jsonErr := diff.FormatJSON()
		if jsonErr != nil {
			slog.Error("formatting JSON", "error", jsonErr)
			return 1
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(diff.Format())
	}

	return 0
}

func loadManifestFile(path string) (*soul.SoulManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	m, err := soul.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return m, nil
}

func loadFromAnchor(anchorRoot, fabricID, seqA, seqB string) (*soul.SoulManifest, *soul.SoulManifest, error) {
	var fromSeq, toSeq uint64
	if _, err := fmt.Sscanf(seqA, "%d", &fromSeq); err != nil {
		return nil, nil, fmt.Errorf("invalid sequence %q: %w", seqA, err)
	}
	if _, err := fmt.Sscanf(seqB, "%d", &toSeq); err != nil {
		return nil, nil, fmt.Errorf("invalid sequence %q: %w", seqB, err)
	}

	archDir := filepath.Join(anchorRoot, fabricID, "archive")

	from, err := loadArchiveManifest(archDir, fromSeq)
	if err != nil {
		return nil, nil, err
	}
	to, err := loadArchiveManifest(archDir, toSeq)
	if err != nil {
		return nil, nil, err
	}
	return from, to, nil
}

func loadArchiveManifest(archDir string, seq uint64) (*soul.SoulManifest, error) {
	path := filepath.Join(archDir, fmt.Sprintf("soul-manifest-%d.yaml", seq))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading sequence %d from %s: %w", seq, archDir, err)
	}
	return soul.Unmarshal(data)
}
