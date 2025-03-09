TARGET=armv7-linux-androideabi
HOOK_OUT=injector/assets/
FLAGS ?= --release

.PHONY: all hook inject debug clean

all: injector

hook:
	cross build --target $(TARGET) --manifest-path hook/Cargo.toml $(FLAGS)
	mkdir -p ${HOOK_OUT}
	cp hook/target/$(TARGET)/$(if $(findstring --release,$(FLAGS)),release,debug)/libhook.so $(HOOK_OUT)

injector: hook
	cross build --target $(TARGET) --manifest-path injector/Cargo.toml $(FLAGS)

debug:
	$(MAKE) FLAGS= hook
	$(MAKE) FLAGS= injector

clean:
	cargo clean --manifest-path hook/Cargo.toml
	cargo clean --manifest-path injector/Cargo.toml