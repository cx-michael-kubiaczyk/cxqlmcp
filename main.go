package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	// Use stderr so logs don't corrupt the MCP stdio transport on stdout.
	logger.SetOutput(os.Stderr)

	logger.Info("Starting")
	LogLevel := flag.String("log", "INFO", "Log level: TRACE, DEBUG, INFO, WARNING, ERROR, FATAL")
	testMode := flag.String("test", "", "Run test harness instead of MCP server (hsts|xss)")
	cleanMode := flag.Bool("purge", false, "Set to true to automatically delete projects, applications, and presets created by this process")
	_ = flag.String("proxy", "", "Optional: Proxy server to connect to for outbound calls to Cx1")

	proxy := getProxy()
	httpClient := &http.Client{}
	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
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
		logger.SetLevel(logrus.TraceLevel)
	case "DEBUG":
		logger.SetLevel(logrus.DebugLevel)
	case "INFO":
		logger.SetLevel(logrus.InfoLevel)
	case "WARNING":
		logger.SetLevel(logrus.WarnLevel)
	case "ERROR":
		logger.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		logger.SetLevel(logrus.FatalLevel)
	}

	if *cleanMode {
		runCleanup(cx1client, logger)
		return
	}

	server := mcp.NewMCP(cx1client, logger)
	defer server.Shutdown()

	if *testMode != "" {
		runTest(server, logger, *testMode)
		return
	}

	if err := server.Start(); err != nil {
		logger.Errorf("Error running MCP server: %s", err)
	}
}

func getProxy() string {
	for i := 0; i < len(os.Args); i++ {
		// Match exact '-proxy' or '--proxy'
		if os.Args[i] == "-proxy" || os.Args[i] == "--proxy" {
			// Ensure there's a following value argument
			if i+1 < len(os.Args) {
				return os.Args[i+1]
			}
			break
		}
		// Alternatively catch inline assignments like -proxy=http://...
		if len(os.Args[i]) > 7 && os.Args[i][:7] == "-proxy=" {
			return os.Args[i][7:]
		}
		if len(os.Args[i]) > 8 && os.Args[i][:8] == "--proxy=" {
			return os.Args[i][8:]
		}
	}
	return ""
}

func runCleanup(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) {
	deleteProjects := func(projects *[]Cx1ClientGo.Project) {
		for _, p := range *projects {
			err := cx1client.DeleteProject(&p)
			if err != nil {
				logger.Errorf("Failed to delete project %s: %v", p.String(), err)
			} else {
				logger.Infof("Deleted project %s", p.String())
			}
			time.Sleep(1 * time.Second)
		}
	}
	deleteApplications := func(applications *[]Cx1ClientGo.Application) {
		for _, a := range *applications {
			err := cx1client.DeleteApplication(&a)
			if err != nil {
				logger.Errorf("Failed to delete application %s: %v", a.String(), err)
			} else {
				logger.Infof("Deleted application %s", a.String())
			}
			time.Sleep(1 * time.Second)
		}
	}
	deletePresets := func(presets *[]Cx1ClientGo.Preset) {
		for _, p := range *presets {
			if strings.HasPrefix(p.Name, "CxQL-") {
				p, err := cx1client.GetPresetByID("sast", p.PresetID)
				if err != nil {
					logger.Errorf("Failed to get details for preset %s: %v", p.String(), err)
				}
				err = cx1client.DeletePreset(p)
				if err != nil {
					logger.Errorf("Failed to delete preset %s: %v", p.String(), err)
				} else {
					logger.Infof("Deleted preset %s", p.String())
				}
				time.Sleep(1 * time.Second)
			}
		}
	}

	projects, err := cx1client.GetProjectsByName("CxQL-Target")
	if err != nil {
		logger.Errorf("Failed to get 'CxQL-Target*' projects: %s", err)
	} else {
		deleteProjects(&projects)
	}
	projects, err = cx1client.GetProjectsByName("CxQL-TP")
	if err != nil {
		logger.Errorf("Failed to get 'CxQL-TP*' projects: %s", err)
	} else {
		deleteProjects(&projects)
	}
	projects, err = cx1client.GetProjectsByName("CxQL-TN")
	if err != nil {
		logger.Errorf("Failed to get 'CxQL-TN*' projects: %s", err)
	} else {
		deleteProjects(&projects)
	}

	applications, err := cx1client.GetApplicationsByName("CxQL-")
	if err != nil {
		logger.Errorf("Failed to get 'CxQL-*' applications: %s", err)
	} else {
		deleteApplications(&applications)
	}

	presets, err := cx1client.GetAllSASTPresets()
	if err != nil {
		logger.Errorf(" -hFailed to get presets: %s", err)
	} else {
		deletePresets(&presets)
	}
}

func runTest(server *mcp.MCP, logger *logrus.Logger, mode string) {
	switch strings.ToLower(mode) {
	case "xss":
		testXSS(server, logger)
	case "hsts":
		testHSTS(server, logger)
	default:
		logger.Errorf("Unknown test mode %q (use 'xss' or 'hsts')", mode)
	}
}

func testPrint(logger *logrus.Logger, test, result string) {
	if strings.HasPrefix(result, "Error: ") {
		logger.Fatalf("Failed at step %s. %s", test, result)
	} else {
		logger.Infof("%s:\n%s\n", test, result)
	}
}
func testXSS(server *mcp.MCP, logger *logrus.Logger) {
	breaker := "=====================================================================\n\n"
	// todo: pass real TP/TN finding URLs to exercise CreateTestEnvironment
	logger.Infof("CreateSessionFromURL:\n%s\n%s",
		server.CreateSessionFromURL("https://deu.ast.checkmarx.net/sast-results/e25a6a86-2d86-4b1b-8d50-6c6f706decdd/0f562295-d7a8-49d6-bd37-82177647633b?resultId=wta7MY4iw%2BJ3rxS9fiHBXIHukys%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName", nil, nil),
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
		server.RunQuery(mcp.QUERY_LEVEL_PRODUCT, "Java", "General", "Find_Full_XSS_Sanitize"),
		breaker,
	)
	logger.Infof("Test error in custom Find_Full_XSS_Sanitize:\n%s\n%s",
		server.TestQuery(mcp.QUERY_LEVEL_APPLICATION, "Java", "General", "Find_Full_XSS_Sanitize", `result = base.Find_();
result.Add(Find_Methods().FindByMemberAccess("sanitizers.sanitizeEmail"));
`),
		breaker,
	)
	logger.Infof("Test custom Find_Full_XSS_Sanitize:\n%s\n%s",
		server.TestQuery(mcp.QUERY_LEVEL_APPLICATION, "Java", "General", "Find_Full_XSS_Sanitize", `result = base.Find_Full_XSS_Sanitize();
result.Add(Find_Methods().FindByMemberAccess("sanitizers.sanitizeEmail"));
`),
		breaker,
	)
}

func testHSTS(server *mcp.MCP, logger *logrus.Logger) {
	// todo: pass real TP/TN finding URLs to exercise CreateTestEnvironment
	testPrint(logger, "CreateSessionFromURL",
		server.CreateSessionFromURL("https://deu.ast.checkmarx.net/sast-results/9ee3602f-94c6-4230-8be4-bdb6d9fdeb03/8130f76b-c6dc-487e-a2a4-54be9f6a5945?resultId=Z6ZsAZogrxT9WY99pVuEDiLbbFA%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName",
			[]string{"https://deu.ast.checkmarx.net/sast-results/2a03108b-96dc-496a-b451-c80aac2aa1db/8e62d430-7587-4637-b99c-5d4be8ba090b?resultId=b5%2F3vdqME0D%2FfIke2QS8GEI%2FrB0%3D&pagination=pageSize%3D10%3BcurrentPage%3D1&grouping=groups%255B0%255D%3Dlanguage%3Bgroups%255B1%255D%3Dseverity%3Bgroups%255B2%255D%3DqueryName"},
			[]string{"01d5a148-9685-4051-b172-f3b6f282ec42", "d201f7ca-f66b-4f20-a491-8ac869e9e011"}),
	)

	testPrint(logger, "HLD", server.HLD)
	testPrint(logger, "Finding details", server.GetFindingDetails())
	testPrint(logger, "Code snippets", server.GetCodeSnippets())
	testPrint(logger, "Query info",
		server.GetQueryInfo("JavaScript", "JavaScript_Medium_Threat", "Missing_HSTS_Header"),
	)
	testPrint(logger, "Run sub-query Find_HSTS_Sanitize",
		server.RunQuery(mcp.QUERY_LEVEL_PRODUCT, "JavaScript", "General", "Find_HSTS_Sanitize"),
	)
	logger.Infof("%s:\n%s\n", "Test error in custom Find_HSTS_Sanitize",
		server.TestQuery(mcp.QUERY_LEVEL_APPLICATION, "JavaScript", "General", "Find_HSTS_Sanitize", "result = base.Find_();"),
	)
	testPrint(logger, "Test scratch query",
		server.TestQuery(mcp.QUERY_LEVEL_APPLICATION, "JavaScript", "CxDefaultQueryGroup", "CxDefaultQuery", "result = Find_Strings();"),
	)

	testPrint(logger, "Save no-result override of Find_HSTS_Sanitize",
		server.SaveQuery(mcp.QUERY_LEVEL_APPLICATION, "JavaScript", "General", "Find_HSTS_Sanitize", "result = All.NewCxList();"),
	)

	testPrint(logger, "Test saved query",
		server.ScanControlProjects(),
	)
}
