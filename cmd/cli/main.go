package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const version = "1.0.0"

type config struct {
	setupFolder  string
	setupFile    string
	outputFolder string
	// catalogFolder string
	quietMode bool
}

type application struct {
}

func main() {
	var cfg config
	packaging := flag.NewFlagSet("packaging", flag.ExitOnError)
	packaging.StringVar(&cfg.setupFolder, "c", "", "Setup folder for all setup files. All files in this folder will be compressed into .intunewin file.")
	packaging.StringVar(&cfg.setupFile, "s", "", "Setup file (e.g. setup.exe or setup.msi).")
	packaging.StringVar(&cfg.outputFolder, "o", "", "Output folder for the generated .intunewin file.")
	// packaging.StringVar(&cfg.catalogFolder, "a", "", "Catalog folder for all catalog files. All files in this folder will be treated as catalog file for Win10 S mode.")
	// packaging.BoolVar(&cfg.quietMode, "q", false, "If -q is specified, it will be in quiet mode. If the output file already exists, it will be overwritten.")

	if len(os.Args) < 2 {
		packaging.Usage()
		return
	}

	switch os.Args[1] {
	case "-v":
		fmt.Fprintf(os.Stdout, "intunewin version: %s\n", version)
		return
	case "-h":
		packaging.Usage()
		return
	case "-c":
		err := packaging.Parse(os.Args[1:])
		if err != nil {
			packaging.Usage()
			return
		}

		setupFolder, _ := filepath.Abs(cfg.setupFolder)
		outputFolder, _ := filepath.Abs(cfg.outputFolder)

		log.Printf("Setup Folder: %q", setupFolder)
		log.Printf("Setup File: %q", cfg.setupFile)
		log.Printf("Output Folder: %q", outputFolder)

		_, err = NewIntunewin(setupFolder, cfg.setupFile, outputFolder)
		if err != nil {
			log.Println(err)
			return
		}
	case "-e":
		path := string(os.Args[2])
		absPath, _ := filepath.Abs(path)
		Extract(absPath)

		return
	default:
		packaging.Usage()
		return
	}

}
