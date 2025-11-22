# Async BOF Makefile - Production Ready Version

# Compiler
CC=x86_64-w64-mingw32-gcc
LOCAL_CC=gcc

# Directories
SRC_DIR=src
INC_DIR=include
OUT_DIR=bin

# Compile flags
CFLAGS=-c -Wall -I$(INC_DIR) -DBOF_BUILD -O2
LOCAL_CFLAGS=-c -Wall -I$(INC_DIR) -DLOCAL_TEST -O2
LDFLAGS=

# Source files
SOURCES=$(SRC_DIR)/async_bof.c $(SRC_DIR)/real_event_monitor.c $(SRC_DIR)/error_handling.c $(SRC_DIR)/opsec_utils.c
TEST_SOURCES=$(SRC_DIR)/async_bof.c $(SRC_DIR)/real_event_monitor.c $(SRC_DIR)/error_handling.c $(SRC_DIR)/opsec_utils.c $(SRC_DIR)/test_suite.c
OBJECTS=$(SOURCES:$(SRC_DIR)/%.c=$(OUT_DIR)/%.o)

# Target files
TARGET=$(OUT_DIR)/async_bof.o
REAL_MONITOR_OBJ=$(OUT_DIR)/real_event_monitor.o
ERROR_HANDLING_OBJ=$(OUT_DIR)/error_handling.o
LOCAL_TARGET=$(OUT_DIR)/async_bof_local.exe
TEST_TARGET=$(OUT_DIR)/async_bof_test.exe
COMBINED_TARGET=$(OUT_DIR)/async_bof_combined.o

# Default target - production BOF
all: $(TARGET) $(REAL_MONITOR_OBJ) $(ERROR_HANDLING_OBJ) $(COMBINED_TARGET)

# Create output directory
$(OUT_DIR):
	if not exist "$(OUT_DIR)" mkdir "$(OUT_DIR)"

# Compile main async_bof for BOF
$(TARGET): $(SRC_DIR)/async_bof.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Compile real event monitor
$(REAL_MONITOR_OBJ): $(SRC_DIR)/real_event_monitor.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Compile error handling
$(ERROR_HANDLING_OBJ): $(SRC_DIR)/error_handling.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Compile OPSEC utilities
$(OUT_DIR)/opsec_utils.o: $(SRC_DIR)/opsec_utils.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Create combined object file (for complete BOF)
$(COMBINED_TARGET): $(TARGET) $(REAL_MONITOR_OBJ) $(ERROR_HANDLING_OBJ) $(OUT_DIR)/opsec_utils.o
	ld -r -o $@ $(TARGET) $(REAL_MONITOR_OBJ) $(ERROR_HANDLING_OBJ) $(OUT_DIR)/opsec_utils.o

# Local test version
local: $(LOCAL_TARGET)

$(LOCAL_TARGET): $(TEST_SOURCES) | $(OUT_DIR)
	$(LOCAL_CC) -Wall -I$(INC_DIR) -DLOCAL_TEST -DLOCAL_TEST_BUILD -o $@ $(TEST_SOURCES)

# Test executable
test-build: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES) | $(OUT_DIR)
	$(LOCAL_CC) -Wall -I$(INC_DIR) -DLOCAL_TEST -o $@ $(TEST_SOURCES)

# Local test object file only
local-obj: $(OUT_DIR)/async_bof_local.o

$(OUT_DIR)/async_bof_local.o: $(SRC_DIR)/async_bof.c | $(OUT_DIR)
	$(LOCAL_CC) $(LOCAL_CFLAGS) -o $@ $<

# Test the local version
test: test-build
	$(TEST_TARGET)

# Clean build artifacts
clean:
	if exist "$(OUT_DIR)\*.o" del "$(OUT_DIR)\*.o"
	if exist "$(OUT_DIR)\*.exe" del "$(OUT_DIR)\*.exe"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build BOF files (default)"
	@echo "  local        - Build local test executable"
	@echo "  test-build   - Build test suite"
	@echo "  test         - Build and run test suite"
	@echo "  clean        - Clean build artifacts"
	@echo "  deploy       - Show deployment info"
	@echo "  help         - Show this help"

# Production deployment
deploy: all
	@echo "BOF files ready for deployment:"
	@echo "  Main BOF: $(TARGET)"
	@echo "  Event Monitor: $(REAL_MONITOR_OBJ)"
	@echo "  Error Handling: $(ERROR_HANDLING_OBJ)"
	@echo "  Combined BOF: $(COMBINED_TARGET)"
	@echo ""
	@echo "Usage instructions:"
	@echo "  1. Copy $(COMBINED_TARGET) to your Cobalt Strike directory"
	@echo "  2. Load async_bof.cna in Cobalt Strike Script Manager"
	@echo "  3. Use right-click menu in Beacon to access async monitoring"

.PHONY: all local local-obj test-build test clean help deploy

# Clean
clean:
	if exist "$(OUT_DIR)" rmdir /s /q "$(OUT_DIR)"

# Install to Cobalt Strike directory (needs to be modified according to actual path)
install: $(TARGET)
	cp $(TARGET) /path/to/cobaltstrike/async_bof.o

.PHONY: all clean local local-obj test install