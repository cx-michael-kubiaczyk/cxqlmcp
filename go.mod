module github.com/cxpsemea/cxqlmcp

go 1.26.3

require (
	github.com/cxpsemea/Cx1ClientGo v0.1.59
	github.com/cxpsemea/cxqlmcp/mcp v0.0.0
	github.com/sirupsen/logrus v1.9.4
	github.com/t-tomalak/logrus-easy-formatter v0.0.0-20190827215021-c074f06c5816
)

require (
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/cxpsemea/Cx1ClientGo v0.1.59 => ../Cx1ClientGo

replace github.com/cxpsemea/cxqlmcp/mcp v0.0.0 => ./mcp
