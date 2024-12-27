run:
	cargo run

test:
	cargo test

doc:
	cargo doc --open

docker_build:
	docker build -t dnsserver .

docker_run:
	docker run -p 2053:2053/udp dnsserver

docker_compose_up:
	docker-compose up

docker_compose_down:
	docker-compose down