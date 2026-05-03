# Makefile for NetShield service
# Follows VigilProtector platform standards

GOBUILD := go build
GOTEST := go test
GO_MOD := go mod
BINARY_NAME := netshield
APP_NAME := netshield

.PHONY: all build test clean swag linter deps-upgrade

all: build

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="-w -s" -o bin/$(BINARY_NAME) ./cmd/$(APP_NAME)

test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	test -pass -run TestHelper $$(go list ./... | grep -v /vendor/ | grep -v _test) || true

swag:
	go tool swag init -pd --generalInfo cmd/$(APP_NAME)/main.go

clean:
	rm -rf bin/ coverage.out docs/

linter:
	golangci-lint run --config .golangci.yaml ./...

linter-fix:
	golangci-lint run --config .golangci.yaml --fix ./...

deps-upgrade:
	$(GO_MOD) download
	$(GO_MOD) tidy

# Coverage
coverage:
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOTEST) -covermode=count -coverprofile=coverage.out ./...

# Docker
docker-build:
	docker build -t vigilprotector/netshield:latest .
	docker build -t vigilprotector/netshield:$(shell git rev-parse --short HEAD) .

# Helm
helm-chart:
	# Placeholder for Helm chart generation if needed
	echo "Helm chart generation not yet implemented"
