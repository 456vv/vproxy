cd /D ./main
set GOPROXY=https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,https://gocenter.io,https://proxy.golang.org,https://goproxy.io,https://athens.azurefd.net,direct
set GOSUMDB=sum.golang.org

set GOOS=windows
set GOARCH=amd64
go build -o ../bin/vproxy-win-amd64.exe  -gcflags "-N -l -m"

cd /D ../bin/
gdlv exec vproxy-win-amd64.exe -addr :8081 -linkPosterior -proxy socks5://127.0.0.1:803 -logLevel 7

pause
exit 0