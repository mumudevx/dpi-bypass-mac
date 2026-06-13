BINARY := dpb
PKG := github.com/mumudevx/dpi-bypass-mac

.PHONY: build test vet e2e clean run

build:
	go build -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

e2e:
	go test -tags e2e ./internal/proxy/

run: build
	./$(BINARY) run --profile turkey

clean:
	rm -f $(BINARY)
	rm -rf dist/
