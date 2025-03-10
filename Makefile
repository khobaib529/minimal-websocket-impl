CC = g++
CFLAGS = -std=c++11 -Wall
SRC_DIR = src
BUILD_DIR = build

CLIENT_SRC = $(SRC_DIR)/websocket_client.cc
SERVER_SRC = $(SRC_DIR)/websocket_server.cc
REALTIME_FILE_MONITOR_SRC = $(SRC_DIR)/realtime_file_monitor.cc

CLIENT_BIN = $(BUILD_DIR)/websocket_client
SERVER_BIN = $(BUILD_DIR)/websocket_server
REALTIME_FILE_MONITOR_BIN = $(BUILD_DIR)/realtime_file_monitor

all: $(BUILD_DIR) $(CLIENT_BIN) $(SERVER_BIN) $(REALTIME_FILE_MONITOR_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) $(CLIENT_SRC) $(CFLAGS) -o $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRC)
	$(CC)  $(SERVER_SRC) $(CFLAGS) -o $(SERVER_BIN)

$(REALTIME_FILE_MONITOR_BIN): $(REALTIME_FILE_MONITOR_SRC)
	$(CC) $(REALTIME_FILE_MONITOR_SRC) $(CFLAGS) -o $(REALTIME_FILE_MONITOR_BIN)

format:
	clang-format -i --style=file $(CLIENT_SRC) $(SERVER_SRC) $(REALTIME_FILE_MONITOR_SRC)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
