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

# .env 파일 로드
include .env
export $(shell sed 's/=.*//' .env)

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

server: errors-css check-env-server
	@echo "Building server..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(SERVER_BIN) $(SERVER_PKG)
	@echo "Server binary: $(SERVER_BIN)"

client: check-env-client
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

check-env-server:
	@if [ -z "$$HOP_SERVER_HTTP_LISTEN" ]; then echo "필수 환경 변수 HOP_SERVER_HTTP_LISTEN이 설정되지 않았습니다."; exit 1; fi
	@if [ -z "$$HOP_SERVER_HTTPS_LISTEN" ]; then echo "필수 환경 변수 HOP_SERVER_HTTPS_LISTEN가 설정되지 않았습니다."; exit 1; fi
	@if [ -z "$$HOP_SERVER_DTLS_LISTEN" ]; then echo "필수 환경 변수 HOP_SERVER_DTLS_LISTEN가 설정되지 않았습니다."; exit 1; fi
	@if [ -z "$$HOP_SERVER_DOMAIN" ]; then echo "필수 환경 변수 HOP_SERVER_DOMAIN가 설정되지 않았습니다."; exit 1; fi

check-env-client:
	@if [ -z "$$HOP_CLIENT_SERVER_ADDR" ]; then echo "필수 환경 변수 HOP_CLIENT_SERVER_ADDR가 설정되지 않았습니다."; exit 1; fi
	@if [ -z "$$HOP_CLIENT_DOMAIN" ]; then echo "필수 환경 변수 HOP_CLIENT_DOMAIN가 설정되지 않았습니다."; exit 1; fi
	@if [ -z "$$HOP_CLIENT_API_KEY" ]; then echo "필수 환경 변수 HOP_CLIENT_API_KEY가 설정되지 않았습니다."; exit 1; fi
	@if [ -z "$$HOP_CLIENT_LOCAL_TARGET" ]; then echo "필수 환경 변수 HOP_CLIENT_LOCAL_TARGET가 설정되지 않았습니다."; exit 1; fi
	@if [ -z "$$HOP_CLIENT_DEBUG" ]; then echo "필수 환경 변수 HOP_CLIENT_DEBUG가 설정되지 않았습니다."; exit 1; fi