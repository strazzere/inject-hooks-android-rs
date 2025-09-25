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

.PHONY: all hook injector debug clean deploy

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

deploy: injector
	@echo "Checking for ADB devices..."
	@if ! command -v adb >/dev/null 2>&1; then \
		echo "Error: adb not found. Please install Android SDK platform-tools."; \
		exit 1; \
	fi
	@if ! adb devices | grep -q "device$$"; then \
		echo "Error: No ADB device connected. Please connect a device and enable USB debugging."; \
		exit 1; \
	fi
	@echo "Detecting device architecture..."
	@DEVICE_ARCH=$$(adb shell getprop ro.product.cpu.abi 2>/dev/null || adb shell getprop ro.product.cpu.abilist | cut -d',' -f1 2>/dev/null); \
	if [ -z "$$DEVICE_ARCH" ]; then \
		echo "Error: Could not detect device architecture."; \
		exit 1; \
	fi; \
	echo "Device architecture: $$DEVICE_ARCH"; \
	if echo "$$DEVICE_ARCH" | grep -q "arm64\|aarch64"; then \
		TARGET_ARCH="aarch64-linux-android"; \
		echo "Detected 64-bit ARM device, using $$TARGET_ARCH"; \
	elif echo "$$DEVICE_ARCH" | grep -q "armeabi\|armv7"; then \
		TARGET_ARCH="armv7-linux-androideabi"; \
		echo "Detected 32-bit ARM device, using $$TARGET_ARCH"; \
	else \
		echo "Error: Unsupported device architecture: $$DEVICE_ARCH"; \
		exit 1; \
	fi; \
	echo "Pushing binaries to device..."; \
	if [ -f "injector/target/$$TARGET_ARCH/$(if $(findstring --release,$(FLAGS)),release,debug)/injector" ]; then \
		adb push "injector/target/$$TARGET_ARCH/$(if $(findstring --release,$(FLAGS)),release,debug)/injector" /data/local/tmp/; \
		echo "Pushed injector binary"; \
	else \
		echo "Error: Injector binary not found for $$TARGET_ARCH"; \
		exit 1; \
	fi; \
	if [ -f "$(HOOK_OUT)libhook-$$TARGET_ARCH.$(SHARED_EXT)" ]; then \
		adb push "$(HOOK_OUT)libhook-$$TARGET_ARCH.$(SHARED_EXT)" /data/local/tmp/; \
		echo "Pushed hook library"; \
	elif [ -f "$(HOOK_OUT)libhook.$(SHARED_EXT)" ]; then \
		adb push "$(HOOK_OUT)libhook.$(SHARED_EXT)" /data/local/tmp/; \
		echo "Pushed hook library (fallback)"; \
	else \
		echo "Error: Hook library not found for $$TARGET_ARCH"; \
		exit 1; \
	fi; \
	echo "Deployment completed successfully!"
