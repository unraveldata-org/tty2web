module github.com/kost/tty2web

go 1.24

require (
	github.com/NYTimes/gziphandler v1.1.1
	github.com/creack/pty v1.1.24
	github.com/fatih/structs v1.1.0
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/yamux v0.1.2
	github.com/kost/dnstun v0.0.0-20230511164951-6e7f5656a900
	github.com/kost/go-ntlmssp v0.0.0-20190601005913-a22bdd33b2a4
	github.com/kost/gosc v0.0.0-20230110210303-490723ad1528
	github.com/kost/httpexecute v0.0.0-20211119174050-f41d120e9db6
	github.com/kost/regeorgo v0.0.0-20211119151427-d6c70e76b00e
	github.com/pkg/errors v0.9.1
	github.com/urfave/cli/v2 v2.27.6
	github.com/xlzd/gotp v0.1.0
	golang.org/x/oauth2 v0.30.0
)

require (
	github.com/Jeffail/tunny v0.1.4 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/kost/chashell v0.0.0-20230409212000-cf0fbd106275 // indirect
	github.com/miekg/dns v1.1.66 // indirect
	github.com/rs/xid v1.5.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/tools v0.32.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace (
	github.com/creack/pty => github.com/photostorm/pty v1.1.19-0.20221026012344-0a71ca4f0f8c
	github.com/creack/pty v1.1.18 => github.com/photostorm/pty v1.1.19-0.20221026012344-0a71ca4f0f8c
)
