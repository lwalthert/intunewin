package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lwalthert/intunewin/pkg"
)

const version = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("intunewin", flag.ContinueOnError)
	flags.SetOutput(stderr)

	// Microsoft Win32 Content Prep Tool compatible flags
	contentDir := flags.String("c", "", "Setup folder for all setup files. All files in this folder will be compressed into .intunewin file.")
	setupFile := flags.String("s", "", "Setup file (e.g. setup.exe or setup.msi), relative to the setup folder.")
	outputDir := flags.String("o", "", "Output folder for the generated .intunewin file (or extracted contents).")
	quiet := flags.Bool("q", false, "Quiet mode (suppress unnecessary output).")
	_ = flags.String("a", "", "Catalog folder for Win10 S mode (optional compatibility flag).")

	// Extraction and utility flags
	extractFile := flags.String("e", "", "Path to the .intunewin file to extract.")
	showVersion := flags.Bool("v", false, "Display intunewin version.")
	showHelp := flags.Bool("h", false, "Display help information.")

	flags.Usage = func() {
		printHelp(stderr)
	}

	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "intunewin version %s\n", version)
		return 0
	}

	if *showHelp || len(args) == 0 {
		if len(args) == 0 {
			printHelp(stderr)
			return 1
		}
		printHelp(stdout)
		return 0
	}

	// Mode 1: Extraction (-e)
	if *extractFile != "" {
		if *contentDir != "" || *setupFile != "" {
			fmt.Fprintln(stderr, "error: cannot specify packaging flags (-c, -s) when extracting (-e)")
			return 1
		}

		iw, err := pkg.OpenPackage(*extractFile)
		if err != nil {
			fmt.Fprintf(stderr, "error: failed to open package: %v\n", err)
			return 1
		}
		defer iw.Close()

		targetDir := *outputDir
		if targetDir == "" {
			var err error
			targetDir, err = os.Getwd()
			if err != nil {
				fmt.Fprintf(stderr, "error: failed to get working directory: %v\n", err)
				return 1
			}
		}

		if err := iw.ExtractContent(targetDir); err != nil {
			fmt.Fprintf(stderr, "error: extraction failed: %v\n", err)
			return 1
		}

		if !*quiet {
			fmt.Fprintf(stdout, "Extracted package to %s\n", targetDir)
		}
		return 0
	}

	// Mode 2: Packaging (-c, -s, -o)
	if *contentDir == "" || *setupFile == "" || *outputDir == "" {
		fmt.Fprintln(stderr, "error: missing required arguments: -c, -s, and -o are required to create a package")
		fmt.Fprintln(stderr, "run 'intunewin -h' for usage information")
		return 1
	}

	absContentDir, err := filepath.Abs(*contentDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid content directory: %v\n", err)
		return 1
	}

	absOutputDir, err := filepath.Abs(*outputDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid output directory: %v\n", err)
		return 1
	}

	name := strings.TrimSuffix(filepath.Base(*setupFile), filepath.Ext(*setupFile))
	packager := pkg.NewPackager(name, absContentDir, *setupFile, absOutputDir)

	pkgResult, err := packager.Package()
	if err != nil {
		fmt.Fprintf(stderr, "error: packaging failed: %v\n", err)
		return 1
	}

	if !*quiet {
		fmt.Fprintf(stdout, "Successfully created %s\n", pkgResult.Path)
	}
	return 0
}
