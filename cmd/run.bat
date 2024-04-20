cd /D ./main

set GOOS=windows
set GOARCH=amd64
go build -o ../bin/vproxy-win-amd64.exe  -gcflags "-N -l"

cd /D ../bin/
vproxy-win-amd64.exe -addr :8080  -linkPosterior  -logLevel 4

pause
exit 0