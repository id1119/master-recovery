.PHONY: test lint demo gui network-up network-setup network-recover network-cancel network-demo network-v3-smoke network-dashboard network-down

test:
	cargo test --workspace --all-features

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

demo:
	cargo run -p gp-cli -- demo --seed 424242 --mode strong

gui:
	cargo run -p gp-cli -- serve --port 8787

network-up:
	docker compose -f compose.network.yml up -d --build --wait
	docker compose -f compose.network.yml build client

network-setup: network-up
	docker compose -f compose.network.yml run --rm client setup \
		--secret "$${GP_DEMO_SECRET:-correct horse battery staple}" \
		--config-store http://config-store:8080 \
		--config-store http://config-store-2:8080 \
		--config-store http://config-store-3:8080 \
		--relay http://relay:8080 --relay http://relay-2:8080 --relay http://relay-3:8080 \
		--admin-token local-demo-admin-token \
		--signer http://signer-1:8080 --signer http://signer-2:8080 --signer http://signer-3:8080 \
		--guardian http://guardian-1:8080 --guardian http://guardian-2:8080 \
		--guardian http://guardian-3:8080 --guardian http://guardian-4:8080 \
		--guardian http://guardian-5:8080 --guardian http://guardian-6:8080 \
		--guardian http://guardian-7:8080 --guardian http://guardian-8:8080 \
		--signer-threshold 2 --guardian-threshold 5 \
		--delay-secs 5 --card /demo/recovery-card.json \
		--owner-control /demo/owner-control.json

network-recover:
	docker compose -f compose.network.yml run --rm client recover \
		--card /demo/recovery-card.json --output /demo/recovered-secret.bin

network-cancel:
	$(MAKE) network-setup
	docker compose -f compose.network.yml run --rm client recover \
		--card /demo/recovery-card.json --owner-control /demo/owner-control.json \
		--cancel-before-release

network-demo: network-setup network-recover

network-v3-smoke:
	tools/test-v3-network.sh

network-dashboard:
	python3 tools/node-dashboard/dashboard.py

network-down:
	docker compose -f compose.network.yml down
