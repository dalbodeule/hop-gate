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

.PHONY: all server client clean docker-server run-server run-client

all: server client

server:
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

