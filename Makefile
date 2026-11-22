BINARY := netscope
PKG := ./cmd/netscope

.PHONY: build run tidy clean build-linux build-win

build:
	go build -trimpath -ldflags "-s -w" -o $(BINARY) $(PKG)

run: build
	./$(BINARY)

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) netscope.exe netscope-linux

# Linux 交叉编译（cgo + libpcap，需要 libpcap 的 linux 头文件）
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
	CC=x86_64-linux-gnu-gcc go build -o netscope-linux $(PKG)

# Windows 交叉编译（需要 Npcap SDK 的 wpcap 头/库）
build-win:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
	CC=x86_64-w64-mingw32-gcc \
	CGO_CFLAGS="-I$(NPCAP_SDK)/Include" \
	CGO_LDFLAGS="-L$(NPCAP_SDK)/Lib/x64" \
	go build -o netscope.exe $(PKG)
