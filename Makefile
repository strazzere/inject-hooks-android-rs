# Default target triple (used only if cross is available)
TARGET ?= armv7-linux-androideabi
HOOK_OUT ?= injector/assets/
FLAGS ?= --release

# Check if cross is installed
HAS_CROSS := $(shell command -v cross >/dev/null 2>&1 && echo 1 || echo 0)

# User override to force local build (LOCAL=1), otherwise auto-detect
LOCAL ?= 0
ifeq ($(LOCAL),1)
  USE_LOCAL := 1
else ifeq ($(HAS_CROSS),0)
  USE_LOCAL := 1
else
  USE_LOCAL := 0
endif

ifeq ($(USE_LOCAL),1)
  BUILD_TOOL := cargo
  TARGET_ARG :=
  TARGET_DIR :=
else
  BUILD_TOOL := cross
  TARGET_ARG := --target $(TARGET)
  TARGET_DIR := $(TARGET)/
endif

SHARED_EXT := so

.PHONY: all hook injector debug clean

all: injector

hook:
	$(BUILD_TOOL) build $(TARGET_ARG) --manifest-path hook/Cargo.toml $(FLAGS)
	mkdir -p $(HOOK_OUT)
	cp hook/target/$(TARGET_DIR)$(if $(findstring --release,$(FLAGS)),release,debug)/libhook.$(SHARED_EXT) $(HOOK_OUT)

injector: hook
	$(BUILD_TOOL) build $(TARGET_ARG) --manifest-path injector/Cargo.toml $(FLAGS)

debug:
	$(MAKE) FLAGS= USE_LOCAL=$(USE_LOCAL) hook
	$(MAKE) FLAGS= USE_LOCAL=$(USE_LOCAL) injector

clean:
	cargo clean --manifest-path hook/Cargo.toml
	cargo clean --manifest-path injector/Cargo.toml
