build:
	go build -o ./bin/intunewin ./cmd/cli

# Build linking directly against the libmsi C library (cgo). Requires the
# libmsi development headers and library to be installed at build time.
build-libmsi:
	go build -tags libmsi -o ./bin/intunewin ./cmd/cli

# Run the test suite against the libmsi (cgo) MSI reader.
# Requires libmsi and wixl to be installed.
test-libmsi:
	go test -tags libmsi ./...

testpackage:
	./bin/intunewin -c ./tmp/setup -s Install.ps1 -o ./tmp
