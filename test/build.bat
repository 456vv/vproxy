set GOOS=windows
set GOARCH=amd64
go build -o ./bin/vproxy-win-x64.exe -ldflags="-s -w" ./vproxy/main.go

set GOOS=linux
set GOARCH=amd64
go build -o ./bin/vproxy-linux-amd64 -ldflags="-s -w" ./vproxy/main.go
set GOARCH=386
go build -o ./bin/vproxy-linux-386 -ldflags="-s -w" ./vproxy/main.go
set GOARCH=arm
set GOARM=7
go build -o ./bin/vproxy-linux-armv7 -ldflags="-s -w" ./vproxy/main.go
set GOARCH=arm64
go build -o ./bin/vproxy-linux-arm64 -ldflags="-s -w" ./vproxy/main.go

upx -9 ./bin/*