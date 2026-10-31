export MSYS_NO_PATHCONV := 1

include .env
export


db-up:
	@docker compose up -d postgres

db-down:
	@docker compose stop postgres

db-status:
	@docker compose ps postgres

ps:
	@docker ps


migrate-create:
	@if [ -z "$(seq)" ]; then \
		echo "Required parameter 'seq' is missing. Example: make migrate-create seq=init"; \
		exit 1; \
	fi; \
	docker compose run --rm postgres-migrate create \
		-ext sql -dir /migrations -seq "$(seq)"	


migrate-up:
	@make migrate-action action=up


migrate-down:
	@make migrate-action action=down

migrate-action:
	@if [ -z "$(action)" ]; then \
		echo "Required parameter 'action' is missing. Example: make migrate-create action=up"; \
		exit 1; \
	fi; \
	docker compose run --rm postgres-migrate \
		-path /migrations \
		-database postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable \
		"$(action)"

run:
	@go run ./cmd/threatinfoservice