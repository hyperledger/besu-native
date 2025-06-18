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

LIB_NAME = libp256verify.$(LIB_EXT)

# Directories
BSSL_DIR = ../google-boringssl
BSSL_BUILD_DIR = $(BSSL_DIR)/build
INCLUDES = -I$(BSSL_DIR)/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(JNI_OS_DIR)

# Flags
CFLAGS = -O2 -fPIC $(INCLUDES)
LIBS = $(BSSL_BUILD_DIR)/libcrypto.a

# Source and object files
SRCS = p256_verify.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(LIB_NAME)

$(LIB_NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB_NAME)

.PHONY: all clean

