package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/cxpsemea/cxqlmcp/mcp"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.TraceLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	logger.Info("Starting")
	LogLevel := flag.String("log", "INFO", "Log level: TRACE, DEBUG, INFO, WARNING, ERROR, FATAL")

	httpClient := &http.Client{}
	if true {
		proxyURL, _ := url.Parse("http://127.0.0.1:8080")
		transport := &http.Transport{}
		transport.Proxy = http.ProxyURL(proxyURL)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = transport
		logger.Infof("Using proxy")
	}

	cx1client, err := Cx1ClientGo.NewClient(httpClient, logger)

	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}
	logger.Infof("Connected with %v", cx1client.String())

	switch strings.ToUpper(*LogLevel) {
	case "TRACE":
		logger.Info("Setting log level to TRACE")
		logger.SetLevel(logrus.TraceLevel)
	case "DEBUG":
		logger.Info("Setting log level to DEBUG")
		logger.SetLevel(logrus.DebugLevel)
	case "INFO":
		logger.Info("Setting log level to INFO")
		logger.SetLevel(logrus.InfoLevel)
	case "WARNING":
		logger.Info("Setting log level to WARNING")
		logger.SetLevel(logrus.WarnLevel)
	case "ERROR":
		logger.Info("Setting log level to ERROR")
		logger.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		logger.Info("Setting log level to FATAL")
		logger.SetLevel(logrus.FatalLevel)
	default:
		logger.Info("Log level set to default: INFO")
	}

	server := mcp.NewMCP(cx1client, logger)
	err = server.Start()
	if err != nil {
		logger.Errorf("Error running server: %s", err)
		return
	}

	defer server.Shutdown()

	runTest(server, logger)

	logger.Infof("Done")
}

func runTest(server *mcp.MCP, logger *logrus.Logger) {
	err := server.CreateSessionFromURL("https://deu.ast.checkmarx.net/sast-results/9ee3602f-94c6-4230-8be4-bdb6d9fdeb03/8130f76b-c6dc-487e-a2a4-54be9f6a5945?resultId=Z6ZsAZogrxT9WY99pVuEDiLbbFA%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName")
	if err != nil {
		logger.Errorf("Failed to create session from URL: %s", err)
		return
	}

	queries, err := server.GetQueryInfo("JavaScript", "JavaScript_Medium_Threat", "Missing_HSTS_Header")
	if err != nil {
		logger.Errorf("Failed to get query info: %s", err)
		return
	}
	logger.Infof("Query info: %s", queries)

}
