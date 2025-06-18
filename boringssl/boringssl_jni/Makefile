# Name of the output JNI-compatible shared library (macOS uses .dylib)
LIB_NAME = libp256verify.dylib

# Directories
BSSL_DIR = ../google-boringssl
BSSL_BUILD_DIR = $(BSSL_DIR)/build
INCLUDES = -I$(BSSL_DIR)/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin

# Tools and flags
CC = clang
CFLAGS = -O2 -fPIC $(INCLUDES)
LDFLAGS = -dynamiclib -undefined dynamic_lookup
LIBS = $(BSSL_BUILD_DIR)/libcrypto.a

# Source and object files
SRCS = p256_verify.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(LIB_NAME)

# Build shared library
$(LIB_NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f $(OBJS) $(LIB_NAME)

.PHONY: all clean

