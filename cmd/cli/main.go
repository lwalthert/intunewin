package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lwalthert/intunewin/pkg"
)

const version = "1.0.0"

func main() {
	flags := flag.NewFlagSet("intunewin", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

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

	flags.Usage = printHelp

	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Fprintf(os.Stdout, "intunewin version %s\n", version)
		return
	}

	if *showHelp || len(os.Args) == 1 {
		printHelp()
		if len(os.Args) == 1 {
			os.Exit(1)
		}
		return
	}

	// Mode 1: Extraction (-e)
	if *extractFile != "" {
		if *contentDir != "" || *setupFile != "" {
			fmt.Fprintln(os.Stderr, "error: cannot specify packaging flags (-c, -s) when extracting (-e)")
			os.Exit(1)
		}

		iw, err := pkg.OpenPackage(*extractFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to open package: %v\n", err)
			os.Exit(1)
		}
		defer iw.Close()

		targetDir := *outputDir
		if targetDir == "" {
			var err error
			targetDir, err = os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: failed to get working directory: %v\n", err)
				os.Exit(1)
			}
		}

		if err := iw.ExtractContent(targetDir); err != nil {
			fmt.Fprintf(os.Stderr, "error: extraction failed: %v\n", err)
			os.Exit(1)
		}

		if !*quiet {
			fmt.Fprintf(os.Stdout, "Extracted package to %s\n", targetDir)
		}
		return
	}

	// Mode 2: Packaging (-c, -s, -o)
	if *contentDir == "" || *setupFile == "" || *outputDir == "" {
		fmt.Fprintln(os.Stderr, "error: missing required arguments: -c, -s, and -o are required to create a package")
		fmt.Fprintln(os.Stderr, "run 'intunewin -h' for usage information")
		os.Exit(1)
	}

	absContentDir, err := filepath.Abs(*contentDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid content directory: %v\n", err)
		os.Exit(1)
	}

	absOutputDir, err := filepath.Abs(*outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid output directory: %v\n", err)
		os.Exit(1)
	}

	name := strings.TrimSuffix(filepath.Base(*setupFile), filepath.Ext(*setupFile))
	packager := pkg.NewPackager(name, absContentDir, *setupFile, absOutputDir)

	pkgResult, err := packager.Package()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: packaging failed: %v\n", err)
		os.Exit(1)
	}

	if !*quiet {
		fmt.Fprintf(os.Stdout, "Successfully created %s\n", pkgResult.Path)
	}
}
