build:
	go build -o ./bin/intunewin ./cmd/cli

# Build with msitools support so .msi metadata can be read on Linux/macOS.
# Requires the msitools "msiinfo" command to be installed at runtime.
build-msitools:
	go build -tags msitools -o ./bin/intunewin ./cmd/cli

# Run the test suite, including the msitools-backed MSI reader tests.
# Requires msitools (for msiinfo and wixl) to be installed.
test-msitools:
	go test -tags msitools ./...

testpackage:
	./bin/intunewin -c ./tmp/setup -s Install.ps1 -o ./tmp
