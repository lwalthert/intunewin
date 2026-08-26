package main

import (
	"fmt"
	"io"
)

func printHelp(w io.Writer) {
	fmt.Fprintf(w, "Usage: intunewin [flags]\n\n")
	fmt.Fprintf(w, "Create an .intunewin package:\n")
	fmt.Fprintf(w, "  intunewin -c <setup_folder> -s <setup_file> -o <output_folder> [-q]\n\n")
	fmt.Fprintf(w, "Extract an .intunewin package:\n")
	fmt.Fprintf(w, "  intunewin -e <package_file> [-o <output_folder>] [-q]\n\n")
	fmt.Fprintf(w, "Flags:\n")
	fmt.Fprintf(w, "  -c <folder> \t Setup folder containing all source files\n")
	fmt.Fprintf(w, "  -s <file>   \t Setup file (e.g. setup.exe or setup.msi), relative to setup folder\n")
	fmt.Fprintf(w, "  -o <folder> \t Output folder for the generated package or extracted files\n")
	fmt.Fprintf(w, "  -e <file>   \t Path to the .intunewin package to extract\n")
	fmt.Fprintf(w, "  -q          \t Quiet mode (suppress output)\n")
	fmt.Fprintf(w, "  -a <folder> \t Catalog folder for Win10 S mode (optional compatibility flag)\n")
	fmt.Fprintf(w, "  -v          \t Show version\n")
	fmt.Fprintf(w, "  -h          \t Show help\n")
}
