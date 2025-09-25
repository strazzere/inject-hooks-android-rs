# Target triples for Android
ARM_TARGETS := armv7-linux-androideabi aarch64-linux-android
DEFAULT_TARGET ?= armv7-linux-androideabi
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
  TARGETS := $(DEFAULT_TARGET)
else
  BUILD_TOOL := cross
  TARGETS := $(ARM_TARGETS)
endif

SHARED_EXT := so

.PHONY: all hook injector debug clean

all: injector

hook:
ifeq ($(USE_LOCAL),1)
	$(BUILD_TOOL) build --manifest-path hook/Cargo.toml $(FLAGS)
	mkdir -p $(HOOK_OUT)
	cp hook/target/$(if $(findstring --release,$(FLAGS)),release,debug)/libhook.$(SHARED_EXT) $(HOOK_OUT)
else
	@for target in $(TARGETS); do \
		echo "Building hook for $$target..."; \
		$(BUILD_TOOL) build --target $$target --manifest-path hook/Cargo.toml $(FLAGS); \
		mkdir -p $(HOOK_OUT); \
		cp hook/target/$$target/$(if $(findstring --release,$(FLAGS)),release,debug)/libhook.$(SHARED_EXT) $(HOOK_OUT)libhook-$$target.$(SHARED_EXT); \
	done
endif

injector: hook
ifeq ($(USE_LOCAL),1)
	$(BUILD_TOOL) build --manifest-path injector/Cargo.toml $(FLAGS)
else
	@for target in $(TARGETS); do \
		echo "Building injector for $$target..."; \
		$(BUILD_TOOL) build --target $$target --manifest-path injector/Cargo.toml $(FLAGS); \
	done
endif

debug:
	$(MAKE) FLAGS= USE_LOCAL=$(USE_LOCAL) hook
	$(MAKE) FLAGS= USE_LOCAL=$(USE_LOCAL) injector

clean:
	cargo clean --manifest-path hook/Cargo.toml
	cargo clean --manifest-path injector/Cargo.toml
