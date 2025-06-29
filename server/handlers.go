package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/kost/tty2web/utils"

	"github.com/kost/tty2web/webtty"
)

func (server *Server) generateHandleWS(ctx context.Context, cancel context.CancelFunc, counter *counter) http.HandlerFunc {
	once := new(int64)

	go func() {
		select {
		case <-counter.timer().C:
			cancel()
		case <-ctx.Done():
		}
	}()

	return func(w http.ResponseWriter, r *http.Request) {
		if server.options.Once {
			success := atomic.CompareAndSwapInt64(once, 0, 1)
			if !success {
				http.Error(w, "Server is shutting down", http.StatusServiceUnavailable)
				return
			}
		}

		num := counter.add(1)
		closeReason := "unknown reason"

		var oauthCookieValue string
		cookie, err := r.Cookie(oauthCookieName) // Use the cookie name
		if err == nil {
			oauthCookieValue = cookie.Value
		} else if !errors.Is(err, http.ErrNoCookie) {
			log.Printf("Error getting cookie '%s' in generateHandleWS: %v\n", oauthCookieName, err)
		}

		defer func() {
			num := counter.done()
			log.Printf(
				"Connection closed by %s: %s, connections: %d/%d",
				closeReason, r.RemoteAddr, num, server.options.MaxConnection,
			)

			if server.options.Once {
				cancel()
			}
		}()

		if int64(server.options.MaxConnection) != 0 {
			if num > server.options.MaxConnection {
				closeReason = "exceeding max number of connections"
				return
			}
		}

		log.Printf("New client connected: %s, connections: %d/%d", r.RemoteAddr, num, server.options.MaxConnection)

		if r.Method != "GET" {
			http.Error(w, "Method not allowed", 405)
			return
		}

		conn, err := server.upgrader.Upgrade(w, r, nil)
		if err != nil {
			closeReason = err.Error()
			return
		}
		defer conn.Close()

		err = server.processWSConn(ctx, conn, oauthCookieValue)

		switch err {
		case ctx.Err():
			closeReason = "cancelation"
		case webtty.ErrSlaveClosed:
			closeReason = server.factory.Name()
		case webtty.ErrMasterClosed:
			closeReason = "client"
		default:
			closeReason = fmt.Sprintf("an error: %s", err)
		}
	}
}

func (server *Server) processWSConn(ctx context.Context, conn *websocket.Conn, oauthCookieValue string) error {
	typ, initLine, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to authenticate websocket connection: %w", err)
	}
	if typ != websocket.TextMessage {
		return errors.New("failed to authenticate websocket connection: invalid message type")
	}

	var init InitMessage
	err = json.Unmarshal(initLine, &init)
	if err != nil {
		return fmt.Errorf("failed to authenticate websocket connection: %w", err)
	}
	if init.AuthToken != server.options.Credential {
		return errors.New("failed to authenticate websocket connection")
	}

	queryPath := "?"
	if server.options.PermitArguments && init.Arguments != "" {
		queryPath = init.Arguments
	}

	query, err := url.Parse(queryPath)
	if err != nil {
		return fmt.Errorf("failed to parse arguments: %w", err)
	}
	params := query.Query()
	var slave Slave
	slave, err = server.factory.New(params)
	if err != nil {
		return fmt.Errorf("failed to create backend: %w", err)
	}
	defer slave.Close()

	titleVars := server.titleVariables(
		[]string{"server", "master", "slave"},
		map[string]map[string]interface{}{
			"server": server.options.TitleVariables,
			"master": map[string]interface{}{
				"remote_addr": conn.RemoteAddr(),
			},
			"slave": slave.WindowTitleVariables(),
		},
	)

	titleBuf := new(bytes.Buffer)
	err = server.titleTemplate.Execute(titleBuf, titleVars)
	if err != nil {
		return fmt.Errorf("failed to fill window title template: %w", err)
	}

	opts := []webtty.Option{
		webtty.WithWindowTitle(titleBuf.Bytes()),
	}
	if server.options.PermitWrite {
		opts = append(opts, webtty.WithPermitWrite())
	}
	if server.options.EnableReconnect {
		opts = append(opts, webtty.WithReconnect(server.options.ReconnectTime))
	}
	if server.options.Width > 0 {
		opts = append(opts, webtty.WithFixedColumns(server.options.Width))
	}
	if server.options.Height > 0 {
		opts = append(opts, webtty.WithFixedRows(server.options.Height))
	}
	if server.options.Preferences == nil {
		server.options.Preferences = &HtermPrefernces{}
	}
	if server.options.OTP != "" {
		opts = append(opts, webtty.WithOTP())
	}
	server.options.Preferences.EnableWebGL = server.options.EnableWebGL
	opts = append(opts, webtty.WithMasterPreferences(server.options.Preferences))

	tty, err := webtty.New(&wsWrapper{conn}, slave, oauthCookieValue, opts...)
	if err != nil {
		return fmt.Errorf("failed to create webtty: %w", err)
	}

	err = tty.Run(ctx)
	return err
}

func (server *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	titleVars := server.titleVariables(
		[]string{"server", "master"},
		map[string]map[string]interface{}{
			"server": server.options.TitleVariables,
			"master": map[string]interface{}{
				"remote_addr": r.RemoteAddr,
			},
		},
	)

	titleBuf := new(bytes.Buffer)
	err := server.titleTemplate.Execute(titleBuf, titleVars)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	indexVars := map[string]interface{}{
		"title": titleBuf.String(),
	}

	indexBuf := new(bytes.Buffer)
	err = server.indexTemplate.Execute(indexBuf, indexVars)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	w.Write(indexBuf.Bytes())
}

func (server *Server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	// @TODO hashing?
	w.Write([]byte("var gotty_auth_token = '" + server.options.Credential + "';"))
}

func (server *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<html><body><form method=\"post\" enctype=\"multipart/form-data\" />"))
	w.Write([]byte("<input type=\"file\" name=\"f\" /> Dir: <input name=\"d\" /><input type=\"Submit\" name=\"s\" value=\"Upload\" />"))
	w.Write([]byte("</form>"))
	if r.FormValue("s") != "" {
		var destfile string
		file, header, erru := r.FormFile("f")
		if erru != nil {
			tmpstr := fmt.Sprintf("Upload error: %v", erru)
			w.Write([]byte(tmpstr))
			w.Write([]byte("</body></html>"))
			return
		}
		defer file.Close()

		destdir := r.FormValue("d")
		if destdir == "" {
			destfile = path.Join(server.options.FileUpload, filepath.Base(header.Filename))
		} else {
			ndestdir := filepath.Clean(destdir)
			destfile = path.Join(server.options.FileUpload, ndestdir, filepath.Base(header.Filename))
			abs, errabs := filepath.Abs(destfile)
			if errabs != nil || !strings.HasPrefix(abs, server.options.FileUpload) {
				log.Printf("Request file manipulation detected %s (abs: %s) for %s", destfile, abs, r.RemoteAddr)
				destfile = path.Join(server.options.FileUpload, filepath.Base(header.Filename))
			}
		}
		deststr := fmt.Sprintf("Uploading %s", destfile)
		w.Write([]byte(deststr))

		f, errf := os.OpenFile(destfile, os.O_WRONLY|os.O_CREATE, 0666)
		if errf != nil {
			tmpstr := fmt.Sprintf("Error creating file %s: %v", destfile, errf)
			w.Write([]byte(tmpstr))
			w.Write([]byte("</body></html>"))
			return
		}
		defer f.Close()
		io.Copy(f, file)
		log.Printf("Uploaded %s to %s for %s", header.Filename, destfile, r.RemoteAddr)
	}
	w.Write([]byte("</body></html>"))
}

func (server *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte("var gotty_term = '" + server.options.Term + "';"))
	if server.options.FileDownload != "" || server.options.FileUpload != "" || server.options.API || server.options.Regeorg {
		w.Write([]byte("document.getElementById(\"topnav\").style.display = \"block\";"))
	}
	if server.options.FileDownload != "" {
		w.Write([]byte("document.getElementById(\"download\").style.display = \"block\";"))
	}
	if server.options.FileUpload != "" {
		w.Write([]byte("document.getElementById(\"upload\").style.display = \"block\";"))
	}
	if server.options.API {
		w.Write([]byte("document.getElementById(\"api\").style.display = \"block\";"))
	}
	if server.options.Regeorg {
		w.Write([]byte("document.getElementById(\"regeorg\").style.display = \"block\";"))
	}
	if server.options.Scexec {
		w.Write([]byte("document.getElementById(\"scexec\").style.display = \"block\";"))
	}
	jsurl := "./js"
	if server.options.JSURL != "" {
		jsurl = server.options.JSURL
	}
	w.Write([]byte("var jsb = document.createElement(\"script\"); jsb.src = \"" + jsurl + "/tty2web-bundle.js\";"))
	w.Write([]byte("jsb.onerror = e => console.log(\"error loading tty2web-bundle.js\"); document.head.appendChild(jsb);"))
	w.Write([]byte("var jss = document.createElement(\"script\"); jss.src = \"" + jsurl + "/sidenav.js\";"))
	w.Write([]byte("jss.onerror = e => console.log(\"error loading sidenav.js\"); document.head.appendChild(jss);"))
}

// titleVariables merges maps in a specified order.
// varUnits are name-keyed maps, whose names will be iterated using order.
func (server *Server) titleVariables(order []string, varUnits map[string]map[string]interface{}) map[string]interface{} {
	titleVars := map[string]interface{}{}

	for _, name := range order {
		vars, ok := varUnits[name]
		if !ok {
			panic("title variable name error")
		}
		for key, val := range vars {
			titleVars[key] = val
		}
	}

	// safe net for conflicted keys
	for _, name := range order {
		titleVars[name] = varUnits[name]
	}

	return titleVars
}

// handleOauthCallBack processes the OAuth2 callback and sets the local token in a cookie.
func (server *Server) handleOauthCallBack(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}
	tok := OauthConf.Exchange(code)
	if tok == nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	claims, err := utils.DecodeOauthTokenUnsafe(tok.AccessToken)
	if err != nil {
		log.Printf("Error decoding OAuth2 token: %v", err)
		http.Error(w, "Invalid access token", http.StatusInternalServerError)
		return
	}
	if claims == nil {
		log.Printf("Warning: OAuth2 token claims are empty for %s", r.RemoteAddr)
		http.Error(w, "Invalid access token", http.StatusInternalServerError)
		return
	}
	log.Printf("OAuth2 authorization successful for %s and user %s", r.RemoteAddr, claims[server.options.OauthUsernameMapField])
	localToken, _ := OauthConf.GenerateLocalToken(map[string]interface{}{"username": claims[server.options.OauthUsernameMapField]})
	// exp := time.Unix(localClaims["exp"].(int64), 0)
	http.SetCookie(w, &http.Cookie{
		Name:  oauthCookieName,
		Value: localToken,
		Path:  "/",
		// Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	sizeOfCookie := len(oauthCookieName) + len(localToken) + 20 // 20 for other cookie attributes
	if sizeOfCookie > 4096 {
		log.Printf("Warning: OAuth2 cookie size (%d bytes) exceeds the limit of 4096 bytes. Consider using a shorter token or reducing cookie attributes.", sizeOfCookie)
	}
	w.Header().Set("Content-Type", "text/html")
	p := "/"
	if server.options.Url != "" {
		p = "/" + server.options.Url + "/"
	}
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>%[1]s</title>
</head>
<body>
<h1>%[1]s</h1>
<p>Redirect to home page in 5 seconds</p>
<script>
setTimeout(function() {
	 window.location.href = "%[2]s";
}, 5000);
</script>
</body>
</html>
`,
		"Login Successful",
		p,
	)
	w.Write([]byte(body))
	w.WriteHeader(http.StatusOK)
}
