package main

import (
	"fmt"
	"os"
)

func printHelp() {
	fmt.Fprintf(os.Stdout, "Usage: intunewin [flags] [args] {command [args]}\n")
	fmt.Fprintf(os.Stdout, "Flags:\n")
	fmt.Fprintf(os.Stdout, "  -h, \t help for intunewin\n")
	fmt.Fprintf(os.Stdout, "  -c, \t runs the command to generate an .intunewin file\n")
	fmt.Fprintf(os.Stdout, "  -e, \t runs the command to extract an .intunewin file\n")
	fmt.Fprintf(os.Stdout, "  -v, \t version for intunewin\n")
}
