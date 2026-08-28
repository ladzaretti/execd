.DEFAULT_GOAL = build

BIN_NAME ?= execd

VERSION ?= v0.0.0

# renovate: datasource=github-releases depName=golangci/golangci-lint
GOLANGCI_VERSION ?= v2.13.2
TEST_ARGS = -v -timeout 40s -coverpkg=./...

PKG_PATH ?= main
LDFLAGS=-X 'main.Version=$(VERSION)'

bin/golangci-lint-$(GOLANGCI_VERSION):
	@mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
    	| sh -s $(GOLANGCI_VERSION)
	@mv bin/golangci-lint "$@"

bin/golangci-lint: bin/golangci-lint-$(GOLANGCI_VERSION)
	@ln -sf golangci-lint-$(GOLANGCI_VERSION) bin/golangci-lint

bin/$(BIN_NAME): go-mod-tidy
	go build -ldflags "$(LDFLAGS)" -o bin/$(BIN_NAME) .

.PHONY: build
build: bin/$(BIN_NAME)

.PHONY: build-dist
build-dist: build
	mkdir -p dist
	cp ./bin/$(BIN_NAME) LICENSE ./dist/
	cp ./scripts/install.sh ./dist/install.sh
	cp ./assets/default-config.toml ./dist/execd.toml
	cp -r ./systemd ./dist/

assets/default-config.toml: bin/$(BIN_NAME)
	./bin/$(BIN_NAME) config generate > $@

assets/usage.txt: bin/$(BIN_NAME)
	./bin/$(BIN_NAME) -h > $@ 2>&1

.PHONY: readme.md
readme.md: readme.templ.md assets/default-config.toml assets/usage.txt scripts/readme_gen.sh
	./scripts/readme_gen.sh readme.templ.md readme.md

.PHONY: go-mod-tidy
go-mod-tidy:
	go mod tidy

.PHONY: clean
clean:
	go clean -testcache
	rm -rf coverage/ bin/ dist/

.PHONY: test
test:
	go test $(TEST_ARGS) ./...

.PHONY: cover
cover:
	@mkdir -p coverage
	go test $(TEST_ARGS) ./... -coverprofile coverage/cover.out ./...
	@go tool cover -func=./coverage/cover.out | grep total | awk '{print "total coverage: " $$3}'

.PHONY: coverage-html
coverage-html: cover
	go tool cover -html=coverage/cover.out -o coverage/index.html

.PHONY: lint
lint: bin/golangci-lint
	bin/golangci-lint run

.PHONY: fix
fix: bin/golangci-lint
	bin/golangci-lint run --fix

.PHONY: check
check: lint test
