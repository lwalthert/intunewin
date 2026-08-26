package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/lwalthert/intunewin/pkg"
)

const version = "1.0.0"

func main() {
	generate := flag.NewFlagSet("generate", flag.ExitOnError)
	contentDir := generate.String("c", "", "Setup folder for all setup files. All files in this folder will be compressed into .intunewin file.")
	setupFile := generate.String("s", "", "Setup file (e.g. setup.exe or setup.msi).")
	outputDir := generate.String("o", "", "Output folder for the generated .intunewin file.")
	// catalogDir := generate.String("a", "", "Catalog folder for all catalog files. All files in this folder will be treated as catalog file for Win10 S mode.")
	// quietRun := generate.Bool("q", false, "If -q is specified, it will be in quiet mode. If the output file already exists, it will be overwritten.")

	extract := flag.NewFlagSet("extract", flag.ExitOnError)
	extractFile := extract.String("e", "", "Path to the .intunewin file to extract.")

	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "-v":
		fmt.Fprintf(os.Stdout, "intunewin version: %s\n", version)
	case "-h":
		printHelp()
		generate.Usage()
		extract.Usage()
	case "-c":
		err := generate.Parse(os.Args[1:])
		if err != nil {
			generate.Usage()
			os.Exit(1)
		}

		contentDir, err := filepath.Abs(*contentDir)
		if err != nil {
			log.Fatal(err)
		}
		outputDir, err := filepath.Abs(*outputDir)
		if err != nil {
			log.Fatal(err)
		}

		name := strings.TrimSuffix(path.Base(*setupFile), path.Ext(*setupFile))

		p := pkg.NewPackager(name, contentDir, *setupFile, outputDir)
		_, err = p.Package()
		if err != nil {
			log.Fatal(err)
		}
	case "-e":
		err := extract.Parse(os.Args[1:])
		if err != nil {
			extract.Usage()
			os.Exit(1)
		}
		iw, err := pkg.OpenPackage(*extractFile)
		if err != nil {
			log.Fatal(err)
		}

		defer iw.Close()

		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		err = iw.ExtractContent(wd)
		if err != nil {
			log.Fatal(err)
		}
	default:
		printHelp()
		os.Exit(1)
	}
}
