build:
	go build -o ./bin/intunewin ./cmd/cli

testpackage:
	./bin/intunewin -c ./tmp/setup -s Install.ps1 -o ./tmp
