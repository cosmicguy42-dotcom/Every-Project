.PHONY: all build release test clean install start new-id status purge

all: release

build:
	cargo build

release:
	cargo build --release
	cp /home/xmv22/.cache/cargo_target/ouija/release/ouija ./ouija
	chmod +x ./ouija

test:
	cargo test
	./tests/integration_test.sh

install: release
	mkdir -p $(HOME)/.local/bin
	cp ./ouija $(HOME)/.local/bin/ouija
	chmod +x $(HOME)/.local/bin/ouija
	@echo "Ouija installed to $(HOME)/.local/bin/ouija"

start:
	./ouija start

new-id:
	./ouija new id

status:
	./ouija status

purge:
	./ouija purge

clean:
	cargo clean
	rm -f ./ouija
