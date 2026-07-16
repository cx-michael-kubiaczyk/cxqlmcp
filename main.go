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
	/*
		Typical harness-driven flow:
		Harness -> MCP: create session (from url)
			MCP: create session
			MCP: get query info
			MCP: get code
			MCP: get finding details
			MCP: add finding details (dataflow path) as comments to code snippets
		<-- MCP: prompt containing:
				 - the explanation of the SAST system & query override process,
				 - current finding details (description, recommendation),
				 - code snippets with the dataflow path
				 - the CxQL query that was used to find the issue
		LLM -> MCP: run sub-query X
			MCP: trigger query and get results (which may be multiple dataflow paths)
			MCP: add results summaries (not full dataflow, just first+last nodes) as comments to code snippets
		<-- MCP: prompt containing:
				 - the explanation of the SAST system & query override process,
				 - current finding details (description, recommendation),
				 - code snippets with the dataflow path + sub-query results summaries
			 	 - the CxQL query that was used to find the issue
				 - the CxQL sub-query that was run
		LLM: run updated sub-query X
			MCP: trigger updated query and get results (which may be multiple dataflow paths)
			MCP: add results summaries (not full dataflow, just first+last nodes) as comments to code snippets
		<-- MCP: prompt containing:
				 - the explanation of the SAST system & query override process,
				 - current finding details (description, recommendation),
				 - code snippets with the dataflow path + sub-query results summaries
				 - the CxQL query that was used to find the issue
				 - the updated CxQL sub-query that was run
		Harness -> LLM: was this useful? (yes/no)
		<-- LLM: yes/no (save or don't save)
		Harness -> MCP: save updated sub-query or not
		LLM: decide if more queries should be changed, or run the original query again to check the status
		     - trigger update tools or "check if finding present" tool
			 -




		This test is a mock-harness flow
	*/
	testXSS(server, logger)
}

func testXSS(server *mcp.MCP, logger *logrus.Logger) {
	breaker := "=====================================================================\n\n"
	logger.Infof("CreateSessionFromURL:\n%s\n%s",
		server.CreateSessionFromURL("https://deu.ast.checkmarx.net/sast-results/e25a6a86-2d86-4b1b-8d50-6c6f706decdd/0f562295-d7a8-49d6-bd37-82177647633b?resultId=wta7MY4iw%2BJ3rxS9fiHBXIHukys%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName"),
		breaker,
	)
	/*
		logger.Infof("HLD:\n%s\n%s", server.HLD, breaker)

		logger.Infof("Finding details:\n%s\n%s",
			server.GetFindingDetails(),
			breaker,
		)

		logger.Infof("Code snippets:\n%s\n%s",
			server.GetCodeSnippets(),
			breaker,
		)

		logger.Infof("Query info:\n%s\n%s",
			server.GetQueryInfo("Java", "Java_High_Risk", "Reflected_XSS"),
			breaker,
		)

		logger.Infof("Run sub-query Find_ReflectedXSS:\n%s\n%s",
			server.RunQuery("Java", "General", "Find_ReflectedXSS"),
			breaker,
		)

		logger.Infof("Query info:\n%s\n%s",
			server.GetQueryInfo("Java", "General", "Find_ReflectedXSS"),
			breaker,
		)

		logger.Infof("Run sub-query Find_XSS_Sanitize:\n%s\n%s",
			server.RunQuery("Java", "General", "Find_XSS_Sanitize"),
			breaker,
		)

		logger.Infof("Query info:\n%s\n%s",
			server.GetQueryInfo("Java", "General", "Find_XSS_Sanitize"),
			breaker,
		)
		logger.Infof("Query info:\n%s\n%s",
			server.GetQueryInfo("Java", "General", "Find_Full_XSS_Sanitize"),
			breaker,
		)
	*/
	logger.Infof("Run sub-query Find_Full_XSS_Sanitize:\n%s\n%s",
		server.RunQuery("Java", "General", "Find_Full_XSS_Sanitize"),
		breaker,
	)
	logger.Infof("Test error in custom Find_Full_XSS_Sanitize:\n%s\n%s",
		server.TestQuery("Java", "General", "Find_Full_XSS_Sanitize", `result = base.Find_();
result.Add(Find_Methods().FindByMemberAccess("sanitizers.sanitizeEmail"));
`),
		breaker,
	)
	logger.Infof("Test custom Find_Full_XSS_Sanitize:\n%s\n%s",
		server.TestQuery("Java", "General", "Find_Full_XSS_Sanitize", `result = base.Find_Full_XSS_Sanitize();
result.Add(Find_Methods().FindByMemberAccess("sanitizers.sanitizeEmail"));
`),
		breaker,
	)
}
func testHSTS(server *mcp.MCP, logger *logrus.Logger) {
	logger.Infof("CreateSessionFromURL:\n%s\n",
		server.CreateSessionFromURL("https://deu.ast.checkmarx.net/sast-results/9ee3602f-94c6-4230-8be4-bdb6d9fdeb03/8130f76b-c6dc-487e-a2a4-54be9f6a5945?resultId=Z6ZsAZogrxT9WY99pVuEDiLbbFA%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName"),
	)

	logger.Infof("HLD:\n%s\n", server.HLD)

	logger.Infof("Finding details:\n%s\n",
		server.GetFindingDetails(),
	)

	logger.Infof("Code snippets:\n%s\n",
		server.GetCodeSnippets(),
	)

	logger.Infof("Query info:\n%s\n",
		server.GetQueryInfo("JavaScript", "JavaScript_Medium_Threat", "Missing_HSTS_Header"),
	)

	logger.Infof("Run sub-query Find_HSTS_Sanitize:\n%s\n",
		server.RunQuery("JavaScript", "General", "Find_HSTS_Sanitize"),
	)
}
