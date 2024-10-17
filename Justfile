clippy:
    cargo clippy --workspace --all-targets --all-features

test-all:
    cargo test --workspace --all-targets --all-features -- --nocapture

test TEST:
    cargo test --all-targets --all-features -- {{TEST}} --exact --nocapture