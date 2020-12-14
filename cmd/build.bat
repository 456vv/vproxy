cd /D ./main
set GOPROXY=https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,https://gocenter.io,https://proxy.golang.org,https://goproxy.io,https://athens.azurefd.net,direct
set GOSUMDB=sum.golang.org

set GOOS=windows
set GOARCH=amd64
go build -o ../bin/vproxy-win-amd64.exe -ldflags="-s -w"

set GOOS=linux
set GOARCH=amd64
go build -o ../bin/vproxy-linux-amd64 -ldflags="-s -w"
set GOARCH=386
go build -o ../bin/vproxy-linux-386 -ldflags="-s -w"
set GOARCH=arm
set GOARM=7
go build -o ../bin/vproxy-linux-armv7 -ldflags="-s -w"
set GOARCH=arm64
go build -o ../bin/vproxy-linux-arm64 -ldflags="-s -w"
set GOARCH=mips
go build -o ../bin/vproxy-linux-mips -ldflags="-s -w"

upx -9 ../bin/*