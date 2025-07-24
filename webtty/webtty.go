package webtty

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/kost/tty2web/utils"
	"github.com/pkg/errors"
)

// WebTTY bridges a PTY slave and its PTY master.
// To support text-based streams and side channel commands such as
// terminal resizing, WebTTY uses an original protocol.
type WebTTY struct {
	masterConn Master
	slave      Slave

	windowTitle []byte
	permitWrite bool
	columns     int
	rows        int
	reconnect   int
	masterPrefs []byte

	// OTP
	shouldVerifyOTP bool
	lastFailedOTP   time.Time

	bufferSize       int
	writeMutex       sync.Mutex
	inputBuffer      []byte
	oauthCookieValue string
	tabFlag          bool
	tabTime          time.Time
	historyFlag      bool
	historyTime      time.Time
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// Checks if user is giving UpArrow or DownArrow as input
func isArrowKey(data []byte) bool {
	return string(data) == "\x1b[A" || string(data) == "\x1b[B"
}

// Extract the "username" from JWT token
func (wt *WebTTY) getUsernameFromJWT() string {
	if wt.oauthCookieValue == "" {
		return ""
	}
	claims, err := utils.DecodeOauthTokenUnsafe(wt.oauthCookieValue)
	if err != nil {
		log.Printf("Error decoding JWT token unverified: %v", err)
		return ""
	}
	if username, ok := claims["username"].(string); ok {
		return username
	}
	log.Println("Username claim not found or not a string in JWT token.")
	return ""
}

// New creates a new instance of WebTTY.
func New(masterConn Master, slave Slave, oauthCookieValue string, options ...Option) (*WebTTY, error) {
	wt := &WebTTY{
		masterConn:       masterConn,
		slave:            slave,
		permitWrite:      false,
		columns:          0,
		rows:             0,
		bufferSize:       1024,
		oauthCookieValue: oauthCookieValue,
	}

	for _, option := range options {
		option(wt)
	}

	return wt, nil
}

// Run starts the main process of the WebTTY.
func (wt *WebTTY) Run(ctx context.Context) error {
	err := wt.sendInitializeMessage()
	if err != nil {
		return errors.Wrapf(err, "failed to send initializing message")
	}

	errs := make(chan error, 2)

	go func() {
		errs <- func() error {
			buffer := make([]byte, wt.bufferSize)
			for {
				n, err := wt.slave.Read(buffer)
				if err != nil {
					return ErrSlaveClosed
				}

				for wt.shouldVerifyOTP {
					time.Sleep(1 * time.Second)
				}

				err = wt.handleSlaveReadEvent(buffer[:n])
				if err != nil {
					return err
				}
			}
		}()
	}()

	go func() {
		errs <- func() error {
			buffer := make([]byte, wt.bufferSize)
			for {
				n, err := wt.masterConn.Read(buffer)
				if err != nil {
					return ErrMasterClosed
				}

				err = wt.handleMasterReadEvent(buffer[:n])
				if err != nil {
					return err
				}
			}
		}()
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
		wt.shouldVerifyOTP = false
	case err = <-errs:
		wt.shouldVerifyOTP = false
	}

	return err
}

func (wt *WebTTY) sendInitializeMessage() error {
	err := wt.masterWrite(append([]byte{SetWindowTitle}, wt.windowTitle...))
	if err != nil {
		return errors.Wrapf(err, "failed to send window title")
	}

	if wt.reconnect > 0 {
		reconnect, _ := json.Marshal(wt.reconnect)
		err := wt.masterWrite(append([]byte{SetReconnect}, reconnect...))
		if err != nil {
			return errors.Wrapf(err, "failed to set reconnect")
		}
	}

	if wt.masterPrefs != nil {
		err := wt.masterWrite(append([]byte{SetPreferences}, wt.masterPrefs...))
		if err != nil {
			return errors.Wrapf(err, "failed to set preferences")
		}
	}

	if wt.shouldVerifyOTP {
		err := wt.sentOTPMessage("please enter the OTP code:")
		if err != nil {
			return errors.Wrapf(err, "failed to send OTP message")
		}
	}

	return nil
}

func (wt *WebTTY) handleSlaveReadEvent(data []byte) error {
	safeMessage := base64.StdEncoding.EncodeToString(data)
	err := wt.masterWrite(append([]byte{Output}, []byte(safeMessage)...))
	if err != nil {
		return errors.Wrapf(err, "failed to send message to master")
	}

	if wt.tabFlag {
		if string(data) != "\a" && len(data) > 0 {
			for _, c := range data {
				if c >= 32 && c <= 126 {
					wt.inputBuffer = append(wt.inputBuffer, c)
				}
			}
		}
		wt.tabFlag = false
	}

	// Handle Up/Down arrow recall: capture echoed command
	if wt.historyFlag {
		cleaned := ansiRe.ReplaceAllString(string(data), "")
		tmp := make([]byte, 0, len(cleaned))
		for i := 0; i < len(cleaned); i++ {
			c := cleaned[i]
			if c == '\r' || c == '\n' {
				break
			}
			if c >= 32 && c <= 126 {
				tmp = append(tmp, c)
			}
		}
		if len(tmp) > 0 {
			wt.inputBuffer = tmp
		}
		wt.historyFlag = false
	}

	return nil
}

func (wt *WebTTY) masterWrite(data []byte) error {
	wt.writeMutex.Lock()
	defer wt.writeMutex.Unlock()

	_, err := wt.masterConn.Write(data)
	if err != nil {
		return errors.Wrapf(err, "failed to write to master")
	}

	return nil
}

func stripANSI(bs []byte) []byte {
	return []byte(ansiRe.ReplaceAllString(string(bs), ""))
}

func (wt *WebTTY) handleMasterReadEvent(data []byte) error {
	if len(data) == 0 {
		return errors.New("unexpected zero length read from master")
	}

	switch data[0] {
	case Input:
		if !wt.permitWrite {
			return nil
		}
		if len(data) <= 1 {
			return nil
		}
		if wt.shouldVerifyOTP {
			return nil
		}

		buf := data[1:]
		i := 0
		for i < len(buf) {
			b := buf[i]
			if b == 0x1b && i+1 < len(buf) && buf[i+1] == '[' {
				if i+2 < len(buf) {
					switch buf[i+2] {
					case 'A', 'B':
						wt.historyFlag = true
						wt.historyTime = time.Now()
						wt.inputBuffer = nil // reset before new command
						i += 3
						continue
					case 'C', 'D':
						i += 3
						continue
					default:
						i += 3
						continue
					}
				}
				break
			}

			switch b {
			case '\t':
				wt.tabFlag = true
				wt.tabTime = time.Now()
				i++
			case '\r', '\n':
				if len(wt.inputBuffer) > 0 {
					clean := stripANSI(wt.inputBuffer)
					if len(clean) > 0 {
						username := wt.getUsernameFromJWT()
						log.Printf("User %s executed command: %q", username, string(clean))
					}
					wt.inputBuffer = nil
				}
				i++
			case 127, 8:
				if len(wt.inputBuffer) > 0 {
					wt.inputBuffer = wt.inputBuffer[:len(wt.inputBuffer)-1]
				}
				i++
			default:
				wt.inputBuffer = append(wt.inputBuffer, b)
				i++
			}
		}

		if _, err := wt.slave.Write(buf); err != nil {
			return errors.Wrapf(err, "failed to write received data to slave")
		}

	case Ping:
		if err := wt.masterWrite([]byte{Pong}); err != nil {
			return errors.Wrapf(err, "failed to return Pong message to master")
		}

	case ResizeTerminal:
		if wt.columns != 0 && wt.rows != 0 {
			break
		}
		if len(data) <= 1 {
			return errors.New("received malformed remote command for terminal resize: empty payload")
		}
		var args argResizeTerminal
		if err := json.Unmarshal(data[1:], &args); err != nil {
			return errors.Wrapf(err, "received malformed data for terminal resize")
		}
		rows := wt.rows
		if rows == 0 {
			rows = int(args.Rows)
		}
		columns := wt.columns
		if columns == 0 {
			columns = int(args.Columns)
		}
		wt.slave.ResizeTerminal(columns, rows)

	case OTPInput:
		bruteForceTimeout := 1500 * time.Millisecond
		if wt.lastFailedOTP.Add(bruteForceTimeout).After(time.Now()) {
			if err := wt.sentOTPMessage("\n\rcode incorrect\n\rPlease enter the OTP code:"); err != nil {
				return errors.Wrapf(err, "failed to send OTP message")
			}
			return nil
		}
		otp := data[1:]
		log.Println("OTP code received:", string(otp))
		if utils.VerifyOTP(string(otp)) {
			wt.shouldVerifyOTP = false
			if err := wt.sentOTPMessage("\n\rcode correct\n\r"); err != nil {
				return errors.Wrapf(err, "failed to send OTP message")
			}
		} else {
			if err := wt.sentOTPMessage("\n\rcode incorrect\n\rPlease enter the OTP code:"); err != nil {
				return errors.Wrapf(err, "failed to send OTP message")
			}
			wt.writeMutex.Lock()
			wt.lastFailedOTP = time.Now()
			wt.writeMutex.Unlock()
		}

	default:
		return errors.Errorf("unknown message type `%c`", data[0])
	}

	return nil
}

func (wt *WebTTY) sentOTPMessage(message string) error {
	msg := map[string]string{
		"message":      message,
		"shouldVerify": strconv.FormatBool(wt.shouldVerifyOTP),
	}
	msgBytes, _ := json.Marshal(msg)
	err := wt.masterWrite(append([]byte{OTPRequest}, []byte(base64.StdEncoding.EncodeToString(msgBytes))...))
	if err != nil {
		return errors.Wrapf(err, "failed to send message to master")
	}
	return nil
}

type argResizeTerminal struct {
	Columns float64
	Rows    float64
}
