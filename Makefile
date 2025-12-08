# Makefile for hop-gate
#
# 기본 빌드/테스트/도커 이미지 생성을 위한 Makefile 입니다.
# 사용 예:
#   make all
#   make server
#   make client
#   make docker-server
#   make clean

GO ?= go
MODULE ?= github.com/dalbodeule/hop-gate

SERVER_PKG := ./cmd/server
CLIENT_PKG := ./cmd/client

BIN_DIR := ./bin
SERVER_BIN := $(BIN_DIR)/hop-gate-server
CLIENT_BIN := $(BIN_DIR)/hop-gate-client

VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)

.PHONY: all server client clean docker-server run-server run-client errors-css

all: server client

# Build Tailwind-based error page CSS (internal/errorpages/assets/errors.css).
# Tailwind 기반 에러 페이지 CSS 빌드 (internal/errorpages/assets/errors.css).
errors-css:
	@if [ -f package.json ]; then \
		if [ ! -d node_modules ]; then \
			echo "Installing npm dependencies..."; \
			npm install; \
		fi; \
		echo "Building Tailwind CSS for error pages..."; \
		npm run build:errors-css; \
	else \
		echo "package.json not found; skipping errors-css build"; \
	fi

server: errors-css
	@echo "Building server..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(SERVER_BIN) $(SERVER_PKG)
	@echo "Server binary: $(SERVER_BIN)"

client:
	@echo "Building client..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(CLIENT_BIN) $(CLIENT_PKG)
	@echo "Client binary: $(CLIENT_BIN)"

clean:
	@echo "Cleaning binaries..."
	rm -rf $(BIN_DIR)

run-server: server
	@echo "Running server..."
	$(SERVER_BIN)

run-client: client
	@echo "Running client..."
	$(CLIENT_BIN)

docker-server:
	@echo "Building server Docker image..."
	docker build -f Dockerfile.server -t hop-gate-server:$(VERSION) .

# --- Protobuf code generation -------------------------------------------------
# Requires:
#   - protoc (https://grpc.io/docs/protoc-installation/)
#   - protoc-gen-go (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)
#
# Generates Go types under internal/protocol/pb from internal/protocol/hopgate_stream.proto.
# NOTE:
#   - go_package in hopgate_stream.proto is set to:
#       github.com/dalbodeule/hop-gate/internal/protocol/pb;protocolpb
#   - With --go_out=. (without paths=source_relative), protoc will place the
#     generated file under internal/protocol/pb according to go_package.
proto:
	@echo "Generating Go code from Protobuf schemas..."
	protoc \
		--go_out=. \
		internal/protocol/hopgate_stream.proto
	@echo "Protobuf generation completed."

