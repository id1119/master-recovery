.PHONY: test lint demo gui

test:
	cargo test --workspace

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

demo:
	cargo run -p gp-cli -- demo --seed 424242 --mode strong

gui:
	cargo run -p gp-cli -- serve --port 8787

