cd /D ./main

go mod tidy

set GOOS=windows
set GOARCH=amd64
go build -o ../bin/vproxy-win-amd64.exe  -trimpath -ldflags="-s -w"
go clean -cache

set GOOS=linux
set GOARCH=amd64
go build -o ../bin/vproxy-linux-amd64 -trimpath -ldflags="-s -w"
set GOARCH=arm
set GOARM=7
go build -o ../bin/vproxy-linux-armv7 -trimpath -ldflags="-s -w"
set GOARCH=arm64
go build -o ../bin/vproxy-linux-arm64 -trimpath -ldflags="-s -w"
set GOARCH=mips
go build -o ../bin/vproxy-linux-mips -trimpath -ldflags="-s -w"
go clean -cache

upx -9 ../bin/*