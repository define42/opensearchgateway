all:
	docker compose build
run:
	docker compose stop
	docker compose build
	docker compose up

test:
	go test
