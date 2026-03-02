GREEN = \033[0;32m
BLUE = \033[0;34m
RED = \033[0;31m
NC = \033[0m

.PHONY: all prepare run build test gen fuzz

all: build

prepare:
	@echo -e ":: $(GREEN) Preparing environment...$(NC)"
	@echo -e "-> Downloading go dependencies..."
	@go mod download \
		|| (echo -e "-> $(RED) Failed to download go dependencies$(NC)" && exit 1)
	@echo -e "-> Deploying depending services..."
	@cd ./.deploy/local \
    	&& ./deploy.sh \
    	|| (echo -e "  -> $(RED)Depending services deploy failed$(NC)" && exit 1)
	@echo -e "==> $(BLUE)Environment preparation completed$(NC)"

run:
	@echo -e ":: $(GREEN)Starting backend...$(NC)"
	@echo -e "-> Starting depending services..."
	@cd ./.deploy/local \
		&& ./start.sh \
		|| (echo -e "  -> $(RED)Depending services start failed. Make sure you run 'make prepare' previously.$(NC)" && exit 1)
	@make gen
	@echo -e "-> starting backend..."
	@go build -o bin/backend cmd/backend/main.go && \
		DEBUG=true ./bin/backend \
		&& (echo -e "==> $(BLUE)Successfully shout down backend$(NC)") \
		|| (echo -e "==> $(RED)Backend failed to start $(NC)" && exit 1)

build: gen
	@echo -e ":: $(GREEN)Building backend...$(NC)"
	@echo -e "  -> Building backend binary..."
	@go build -o bin/backend cmd/backend/main.go && echo -e "==> $(BLUE)Build completed successfully$(NC)" || (echo -e "==> $(RED)Build failed$(NC)" && exit 1)

test: gen
	@echo -e ":: $(GREEN)Running tests...$(NC)"
	@go test -cover ./... && echo -e "==> $(BLUE)All tests passed$(NC)" || (echo -e "==> $(RED)Tests failed$(NC)" && exit 1)

fuzz:
	@echo -e ":: $(GREEN) Preparing fuzz environment...$(NC)"
	@cd ./test/fuzzing && ./prepare.sh || (echo -e "-> $(RED) Fuzz environment preparation failed$(NC)" && exit 1)
	@echo -e ":: $(GREEN) Running fuzz tests...$(NC)"
	@cd ./test/fuzzing && ./run.sh || (echo -e "-> $(RED) Fuzz tests failed. Cleaning up$(NC)" && ./cleanup.sh && exit 1)
	@cd ./test/fuzzing && ./cleanup.sh
	@echo -e "==> $(BLUE) Fuzz tests completed$(NC)"

gen:
	@echo -e ":: $(GREEN)Generating schema and code...$(NC)"
	@echo -e "  -> Running schema creation script..."
	@./scripts/create_full_schema.sh || (echo -e "  -> $(RED)Schema creation failed$(NC)" && exit 1)
	@echo -e "  -> Generating SQLC code..."
	@sqlc generate || (echo -e "  -> $(RED)SQLC generation failed$(NC)" && exit 1)
	@echo -e "  -> Generating Casbin Policyfile..."
	@./scripts/create_full_policy.sh || (echo -e "  -> $(RED)Policyfile generation failed$(NC)" && exit 1)
	@echo -e "  -> Running go generate..."
	@go generate ./... || (echo -e "  -> $(RED)Go generate failed$(NC)" && exit 1)
	@echo -e "==> $(BLUE)Generation completed$(NC)"