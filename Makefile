export SODIUM_LIB_DIR := ./libs/
export SODIUM_STATIC := yes

.PHONY: all
all: %.rs
	cargo build --release

%.rs:
	echo "Hmm..."