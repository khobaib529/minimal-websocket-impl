CC = g++
CFLAGS = -std=c++11 -Wall
SRC_DIR = src
BUILD_DIR = build

CLIENT_SRC = $(SRC_DIR)/websocket_client.cc
SERVER_SRC = $(SRC_DIR)/websocket_server.cc

CLIENT_BIN = $(BUILD_DIR)/websocket_client
SERVER_BIN = $(BUILD_DIR)/websocket_server

all: $(BUILD_DIR) $(CLIENT_BIN) $(SERVER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) $(CLIENT_SRC) $(CFLAGS) -o $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRC)
	$(CC)  $(SERVER_SRC) $(CFLAGS) -o $(SERVER_BIN)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
