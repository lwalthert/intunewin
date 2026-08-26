package main

import (
	"fmt"
	"os"
)

func printHelp() {
	fmt.Fprintf(os.Stdout, "Usage: intunewin [flags]\n\n")
	fmt.Fprintf(os.Stdout, "Create an .intunewin package:\n")
	fmt.Fprintf(os.Stdout, "  intunewin -c <setup_folder> -s <setup_file> -o <output_folder> [-q]\n\n")
	fmt.Fprintf(os.Stdout, "Extract an .intunewin package:\n")
	fmt.Fprintf(os.Stdout, "  intunewin -e <package_file> [-o <output_folder>] [-q]\n\n")
	fmt.Fprintf(os.Stdout, "Flags:\n")
	fmt.Fprintf(os.Stdout, "  -c <folder> \t Setup folder containing all source files\n")
	fmt.Fprintf(os.Stdout, "  -s <file>   \t Setup file (e.g. setup.exe or setup.msi), relative to setup folder\n")
	fmt.Fprintf(os.Stdout, "  -o <folder> \t Output folder for the generated package or extracted files\n")
	fmt.Fprintf(os.Stdout, "  -e <file>   \t Path to the .intunewin package to extract\n")
	fmt.Fprintf(os.Stdout, "  -q          \t Quiet mode (suppress output)\n")
	fmt.Fprintf(os.Stdout, "  -a <folder> \t Catalog folder for Win10 S mode (optional compatibility flag)\n")
	fmt.Fprintf(os.Stdout, "  -v          \t Show version\n")
	fmt.Fprintf(os.Stdout, "  -h          \t Show help\n")
}
