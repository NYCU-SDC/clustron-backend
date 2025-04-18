GREEN = \033[0;32m
BLUE = \033[0;34m
RED = \033[0;31m
NC = \033[0m

all: build

prepare:
	@echo -e ":: $(GREEN) Preparing environment...$(NC)"
	@echo -e ":: $(GREEN) Downloading go dependencies...$(NC)"
	@go mod download \
		&& echo -e ":: $(BLUE) Successfully downloaded go dependencies$(NC)" \
		|| (echo -e ":: $(RED) Failed to download go dependencies$(NC)" && exit 1)

run:
	@echo -e ":: $(GREEN)Starting backend...$(NC)"
	@go build -o bin/backend cmd/backend/main.go && \
		DEBUG=true ./bin/backend \
		&& echo -e "==> &(BLUE)Successfully shout down backend$(NC)" \
		|| (echo -e "==> $(RED)Backend failed to start $(NC)" && exit 1)

build:
	@echo -e ":: $(GREEN)Building backend...$(NC)"
	@echo -e "  -> Building backend binary..."
	@go build -o bin/backend cmd/backend/main.go && echo -e "==> $(BLUE)Build completed successfully$(NC)" || (echo -e "==> $(RED)Build failed$(NC)" && exit 1)

test:
	@echo -e ":: $(GREEN)Running tests...$(NC)"
	@go test -cover ./... && echo -e "==> $(BLUE)All tests passed$(NC)" || echo -e "==> $(RED)Tests failed$(NC)"