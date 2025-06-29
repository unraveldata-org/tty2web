package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	noesctmpl "text/template"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/gorilla/websocket"
	"github.com/kost/tty2web/utils"
	"golang.org/x/oauth2"

	"github.com/kost/httpexecute"
	"github.com/kost/regeorgo"
	"github.com/kost/tty2web/bindata"
	"github.com/kost/tty2web/pkg/homedir"
	"github.com/kost/tty2web/pkg/randomstring"
	"github.com/kost/tty2web/tlshelp"
	"github.com/kost/tty2web/webtty"
)

var (
	OauthConf       = &utils.OAuth2Config{}
	oauthCookieName = "tty2web.oauth.token"
)

// Server provides a webtty HTTP endpoint.
type Server struct {
	factory Factory
	options *Options

	upgrader      *websocket.Upgrader
	indexTemplate *template.Template
	titleTemplate *noesctmpl.Template
}

// New creates a new instance of Server.
// Server will use the New() of the factory provided to handle each request.
func New(factory Factory, options *Options) (*Server, error) {
	indexData, err := bindata.Fs.ReadFile("static/index.html")
	if err != nil {
		panic("index not found") // must be in bindata
	}
	if options.IndexFile != "" {
		path := homedir.Expand(options.IndexFile)
		indexData, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read custom index file at `%s`: %w", path, err)
		}
	}
	indexTemplate, err := template.New("index").Parse(string(indexData))
	if err != nil {
		panic("index template parse failed") // must be valid
	}

	titleTemplate, err := noesctmpl.New("title").Parse(options.TitleFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse window title format `%s`: %w", options.TitleFormat, err)
	}

	var originChekcer func(r *http.Request) bool
	if options.WSOrigin != "" {
		matcher, err := regexp.Compile(options.WSOrigin)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regular expression of Websocket Origin: %s: %w", options.WSOrigin, err)
		}
		originChekcer = func(r *http.Request) bool {
			return matcher.MatchString(r.Header.Get("Origin"))
		}
	}

	return &Server{
		factory: factory,
		options: options,

		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			Subprotocols:    webtty.Protocols,
			CheckOrigin:     originChekcer,
		},
		indexTemplate: indexTemplate,
		titleTemplate: titleTemplate,
	}, nil
}

// Run starts the main process of the Server.
// The cancelation of ctx will shutdown the server immediately with aborting
// existing connections. Use WithGracefullContext() to support gracefull shutdown.
func (server *Server) Run(ctx context.Context, options ...RunOption) error {
	cctx, cancel := context.WithCancel(ctx)
	opts := &RunOptions{gracefullCtx: context.Background()}
	for _, opt := range options {
		opt(opts)
	}

	counter := newCounter(time.Duration(server.options.Timeout) * time.Second)

	path := "/"
	if server.options.Url != "" {
		path = "/" + server.options.Url + "/"
	}
	if server.options.EnableRandomUrl {
		path = "/" + randomstring.Generate(server.options.RandomUrlLength) + "/"
	}

	handlers := server.setupHandlers(cctx, cancel, path, counter)
	srv, err := server.setupHTTPServer(handlers)
	if err != nil {
		return fmt.Errorf("failed to setup an HTTP server: %w", err)
	}

	if server.options.PermitWrite {
		log.Printf("Permitting clients to write input to the PTY.")
	}
	if server.options.Once {
		log.Printf("Once option is provided, accepting only one client")
	}

	if server.options.Port == "0" {
		log.Printf("Port number configured to `0`, choosing a random port")
	}

	srvErr := make(chan error, 1)

	if server.options.EnableTLS {
		crtFile := homedir.Expand(server.options.TLSCrtFile)
		keyFile := homedir.Expand(server.options.TLSKeyFile)
		log.Printf("TLS crt file: " + crtFile)
		log.Printf("TLS key file: " + keyFile)
		cer, err := tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			log.Printf("Error loading TLS key and crt file %s and %s: %v. Generating random one!", crtFile, keyFile, err)

			cer, err = tlshelp.GetRandomTLS(2048)
			if err != nil {
				return fmt.Errorf("error generating and failed to load tls cert and key `%s` and `%s`: %w", crtFile, keyFile, err)
			}
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		srv.TLSConfig = config
	}
	if server.options.Dns != "" {
		go func() {
			session, err = DnsConnectSocks(server.options.Dns, server.options.DnsKey, server.options.DnsDelay)
			if err != nil {
				log.Printf("Error creating sessions %s", err)
				srvErr <- err
				return
			}
			if server.options.EnableTLS {
				err = srv.ServeTLS(session, "", "")
			} else {
				err = srv.Serve(session)
			}
			if err != nil {
				srvErr <- err
			}
		}()
	} else {
		if server.options.Connect == "" {
			hostPort := net.JoinHostPort(server.options.Address, server.options.Port)
			listener, err := net.Listen("tcp", hostPort)
			if err != nil {
				return fmt.Errorf("failed to listen at `%s`: %w", hostPort, err)
			}

			scheme := "http"
			if server.options.EnableTLS {
				scheme = "https"
			}
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			log.Printf("HTTP server is listening at: %s", scheme+"://"+host+":"+port+path)
			if server.options.Address == "0.0.0.0" {
				for _, address := range listAddresses() {
					log.Printf("Alternative URL: %s", scheme+"://"+address+":"+port+path)
				}
			}
			go func() {
				if server.options.EnableTLS {
					err = srv.ServeTLS(listener, "", "")
				} else {
					err = srv.Serve(listener)
				}
				if err != nil {
					srvErr <- err
				}
			}()
		} else {
			go func() {
				session, err = connectForSocks(server.options.Connect, server.options.Proxy, server.options.ProxyAuth, server.options.Password, server.options.AgentTLS)
				if err != nil {
					log.Printf("Error creating sessions %s", err)
					srvErr <- err
					return
				}
				if server.options.EnableTLS {
					err = srv.ServeTLS(session, "", "")
				} else {
					err = srv.Serve(session)
				}
				if err != nil {
					srvErr <- err
				}
			}()
		}
	}

	go func() {
		select {
		case <-opts.gracefullCtx.Done():
			srv.Shutdown(context.Background())
		case <-cctx.Done():
		}
	}()

	select {
	case err = <-srvErr:
		if errors.Is(err, http.ErrServerClosed) { // by gracefull ctx
			err = nil
		} else {
			cancel()
		}
	case <-cctx.Done():
		srv.Close()
		err = cctx.Err()
	}

	conn := counter.count()
	if conn > 0 {
		log.Printf("Waiting for %d connections to be closed", conn)
	}
	counter.wait()

	return err
}

func (server *Server) setupHandlers(ctx context.Context, cancel context.CancelFunc, pathPrefix string, counter *counter) http.Handler {
	fs, err := fs.Sub(bindata.Fs, "static")
	if err != nil {
		log.Fatalf("failed to open static/ subdirectory of embedded filesystem: %v", err)
	}
	staticFileHandler := http.FileServer(http.FS(fs))

	var siteMux = http.NewServeMux()

	if server.options.All {
		if server.options.FileDownload == "" {
			server.options.FileDownload = "/"
		}
		if server.options.FileUpload == "" {
			server.options.FileUpload = "/"
		}
		server.options.API = true
		server.options.Regeorg = true
		server.options.Scexec = true
	}

	siteMux.HandleFunc(pathPrefix, server.handleIndex)
	siteMux.Handle(pathPrefix+"js/", http.StripPrefix(pathPrefix, staticFileHandler))
	siteMux.Handle(pathPrefix+"favicon.png", http.StripPrefix(pathPrefix, staticFileHandler))
	siteMux.Handle(pathPrefix+"css/", http.StripPrefix(pathPrefix, staticFileHandler))
	if server.options.FileDownload != "" {
		log.Printf("Serving filesystem %s as URI %s", server.options.FileDownload, pathPrefix+"dl/")
		fs := http.FileServer(http.Dir(server.options.FileDownload))
		siteMux.Handle(pathPrefix+"dl/", http.StripPrefix(pathPrefix+"dl/", fs))
	}
	siteMux.HandleFunc(pathPrefix+"auth_token.js", server.handleAuthToken)
	siteMux.HandleFunc(pathPrefix+"config.js", server.handleConfig)
	if server.options.FileUpload != "" {
		log.Printf("Upload enabled to dir %s as URI %s", server.options.FileUpload, pathPrefix+"ul/")
		siteMux.HandleFunc(pathPrefix+"ul/", server.handleUpload)
	}
	if server.options.API {
		log.Printf("Serving Command API at URI %s", pathPrefix+"api/")
		logdef := log.New(os.Stderr, "", log.LstdFlags)
		he := &httpexecute.CmdConfig{Log: logdef, VerboseLevel: 0}
		siteMux.HandleFunc(pathPrefix+"api/", he.ExecuteHandler)
	}
	if server.options.Regeorg {
		log.Printf("Serving regeorg proxy at URI %s", pathPrefix+"regeorg/")
		gh := &regeorgo.GeorgHandler{}
		gh.InitHandler()
		siteMux.HandleFunc(pathPrefix+"regeorg/", gh.RegHandler)
	}
	// func (cc *SCConfig) SCHandler(w http.ResponseWriter, r *http.Request)
	if server.options.Scexec {
		log.Printf("Serving scexec API at URI %s", pathPrefix+"sc/")
		logdef := log.New(os.Stderr, "", log.LstdFlags)
		sc := &SCConfig{Log: logdef, VerboseLevel: 9}
		siteMux.HandleFunc(pathPrefix+"sc/", sc.SCHandler)
	}

	// OAuth2 configuration
	if server.options.EnableOauth {
		log.Printf("OAuth2 authentication enabled")
		// process OauthClientID and OauthClientSecret loading from config file
		if server.options.OauthClientID == "" || server.options.OauthClientSecret == "" {
			log.Fatalf("oauth2 is enabled, but no client ID or secret provided")
		}
		if server.options.OauthRedirectURL == "" {
			log.Fatalf("oauth2 is enabled, but no redirect URL provided")
		}
		if server.options.OauthAuthUrl == "" || server.options.OauthTokenUrl == "" {
			log.Fatalf("oauth2 is enabled, but no auth or token URL provided")
		}
		OauthConf = utils.NewOAuth2Config(
			server.options.OauthClientID,
			server.options.OauthClientSecret,
			server.options.OauthRedirectURL,
			server.options.JWTSecret,
			server.options.OauthScopes,
			oauth2.Endpoint{
				AuthURL:       server.options.OauthAuthUrl,
				TokenURL:      server.options.OauthTokenUrl,
				DeviceAuthURL: server.options.OauthDeviceAuthUrl,
			},
		)
		siteMux.HandleFunc(pathPrefix+"oauth/callback", server.handleOauthCallBack)
	}

	siteHandler := http.Handler(siteMux)

	if server.options.EnableBasicAuth {
		log.Printf("Using Basic Authentication")
		siteHandler = server.wrapBasicAuth(siteHandler, server.options.Credential)
	} else if server.options.EnableOauth {
		log.Printf("Using OAuth Authentication")
		siteHandler = server.wrapOauth2(siteHandler)
	}

	withGz := gziphandler.GzipHandler(server.wrapHeaders(siteHandler))
	siteHandler = server.wrapLogger(withGz)

	wsMux := http.NewServeMux()
	wsMux.Handle("/", siteHandler)
	wsMux.HandleFunc(pathPrefix+"ws", server.generateHandleWS(ctx, cancel, counter))
	siteHandler = http.Handler(wsMux)

	return siteHandler
}

func (server *Server) setupHTTPServer(handler http.Handler) (*http.Server, error) {
	srv := &http.Server{
		Handler: handler,
	}

	if server.options.EnableTLSClientAuth {
		tlsConfig, err := server.tlsConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to setup TLS configuration: %w", err)
		}
		srv.TLSConfig = tlsConfig
	}

	return srv, nil
}

func (server *Server) tlsConfig() (*tls.Config, error) {
	caFile := homedir.Expand(server.options.TLSCACrtFile)
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("could not open CA crt file " + caFile)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("could not parse CA crt file data in " + caFile)
	}
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	return tlsConfig, nil
}
