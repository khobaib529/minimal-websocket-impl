# Minimal WebSocket Implementation

**Note: This project is created for my learning purpose. To better understand websocket protocol by implementing it using socket programming**

This is a minimal WebSocket implementation for better understanding of WebSocket protocol. and basic server-client interactions. To build the project, run `make` in the project directory. This will compile the source code and generate the necessary executables. To run the WebSocket server, execute `build/websocket_server`, and to run the WebSocket client, execute `build/websocket_client`. Make sure you have **Make** and a **C++ compiler** (like `g++`) installed before building.

Another standalone executable is built when you run make. If you run the executable by typing `./build/realtime_file_monitor <file-path>`, it will start a server at localhost:8080 that displays the file content in a rendered HTML page. If you change the file, the HTML page will update in real time.
