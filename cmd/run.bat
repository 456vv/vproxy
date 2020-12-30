cd /D ./main
set GOPROXY=https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,https://gocenter.io,https://proxy.golang.org,https://goproxy.io,https://athens.azurefd.net,direct
set GOSUMDB=sum.golang.org

set GOOS=windows
set GOARCH=amd64
go build -o ../bin/vproxy-win-amd64.exe  -gcflags "-N -l"

cd /D ../bin/
vproxy-win-amd64.exe -addr :8080 -linkPosterior -user p*P5 -pwd p*P5 -logLevel 4

pause
exit 0