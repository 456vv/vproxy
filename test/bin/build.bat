set GO111MODULE=on

set GOOS=windows
set GOARCH=386
go build -o vproxy-win-x86.exe -ldflags="-s -w" ../vproxy/main.go
set GOARCH=amd64
go build -o vproxy-win-x64.exe -ldflags="-s -w" ../vproxy/main.go
set GOOS=linux
set GOARCH=amd64
go build -o vproxy-linux-x64 -ldflags="-s -w" ../vproxy/main.go
set GOARCH=386
go build -o vproxy-linux-x86 -ldflags="-s -w" ../vproxy/main.go
set GOARCH=arm
go build -o vproxy-linux-arm -ldflags="-s -w" ../vproxy/main.go