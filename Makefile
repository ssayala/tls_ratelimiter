# Compiler and default flags
CLANG = clang
CFLAGS = -O2 -g -Wall -target bpf

# Check for a user-friendly debug flag.
# If DEBUG_LOG is set to any non-empty value (like "true", "1", "yes"),
# then add the -DDEBUG_LOG flag to CFLAGS.
ifneq ($(DEBUG_LOG),)
  CFLAGS += -DDEBUG_LOG
endif

# Pass rate-limiting variables from environment to CFLAGS
# Check for MAX_HANDSHAKES_PER_TW and add to CFLAGS if set
ifneq ($(MAX_HANDSHAKES_PER_TW),)
  CFLAGS += -DMAX_HANDSHAKES_PER_TW=$(MAX_HANDSHAKES_PER_TW)
endif

# Check for TIME_WINDOW_NS and add to CFLAGS if set
ifneq ($(TIME_WINDOW_NS),)
  CFLAGS += -DTIME_WINDOW_NS=$(TIME_WINDOW_NS)
endif

# Target object file
TARGET = tls_rate_limiter.o
# Source C file
SRC = tls_rate_limiter.c

# Default rule to build the program
all: $(TARGET)

# Rule to compile the C source into an eBPF object file
$(TARGET): $(SRC)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $@

# Rule to clean up build artifacts
clean:
	rm -f $(TARGET)
