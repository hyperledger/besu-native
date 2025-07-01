# Detect platform and architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Determine shared library extension and dynamic link flags
ifeq ($(UNAME_S),Darwin)
    LIB_EXT = dylib
    JNI_OS_DIR = darwin
    CC ?= clang
    LDFLAGS = -dynamiclib -undefined dynamic_lookup
else
    LIB_EXT = so
    JNI_OS_DIR = linux
    CC ?= gcc
    LDFLAGS = -shared
endif

# Directories
BUILD_DIR = build
BSSL_DIR = ../google-boringssl
BSSL_BUILD_DIR = $(BSSL_DIR)/build
INCLUDES = -I$(BSSL_DIR)/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(JNI_OS_DIR)

# Flags
CFLAGS = -O2 -fPIC $(INCLUDES)
LIBS = $(BSSL_BUILD_DIR)/libcrypto.a

# Files
LIB_NAME = libboringssl_precompiles.$(LIB_EXT)
SRCS = p256_verify.c ecrecover.c
OBJS = $(SRCS:.c=.o)
BUILD_OBJS = $(addprefix $(BUILD_DIR)/, $(OBJS))
BUILD_LIB = $(BUILD_DIR)/$(LIB_NAME)

# Default target
all: $(BUILD_DIR) $(BUILD_LIB)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_LIB): $(BUILD_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
