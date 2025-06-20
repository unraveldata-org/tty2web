package webtty

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kost/tty2web/utils"
	"github.com/pkg/errors"
	"log"
)

type WebTTY struct {
	masterConn       Master
	slave            Slave
	windowTitle      []byte
	permitWrite      bool
	columns          int
	rows             int
	reconnect        int
	masterPrefs      []byte
	shouldVerifyOTP  bool
	lastFailedOTP    time.Time
	bufferSize       int
	writeMutex       sync.Mutex
	inputBuffer      []byte
	jwtToken         string
	oauthCookieValue string
}

func isArrowKey(data []byte) bool {
	return string(data) == "\x1b[A" || string(data) == "\x1b[B"
}

func (wt *WebTTY) getUsernameFromJWT() string {
	if wt.jwtToken == "" {
		return ""
	}
	token, _, err := new(jwt.Parser).ParseUnverified(wt.jwtToken, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if username, ok := claims["username"].(string); ok {
			return username
		}
	}
	return ""
}

func New(masterConn Master, slave Slave, oauthCookieValue string, options ...Option) (*WebTTY, error) {
	wt := &WebTTY{
		masterConn:       masterConn,
		slave:            slave,
		permitWrite:      false,
		columns:          0,
		rows:             0,
		bufferSize:       1024,
		oauthCookieValue: oauthCookieValue,
		jwtToken:         oauthCookieValue,
	}

	for _, option := range options {
		option(wt)
	}

	return wt, nil
}

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
	return wt.masterWrite(append([]byte{Output}, []byte(safeMessage)...))
}

func (wt *WebTTY) masterWrite(data []byte) error {
	wt.writeMutex.Lock()
	defer wt.writeMutex.Unlock()
	_, err := wt.masterConn.Write(data)
	return errors.Wrapf(err, "failed to write to master")
}

func (wt *WebTTY) handleMasterReadEvent(data []byte) error {
	if len(data) == 0 {
		return errors.New("unexpected zero length read from master")
	}

	switch data[0] {
	case Input:
		if !wt.permitWrite || len(data) <= 1 || wt.shouldVerifyOTP {
			return nil
		}
		if isArrowKey(data[1:]) || data[1] == '\t' {
			return nil
		}
		for _, b := range data[1:] {
			switch b {
			case '\r', '\n':
				if len(wt.inputBuffer) > 0 {
					username := wt.getUsernameFromJWT()
					log.Printf("User %s executed command: %q", username, string(wt.inputBuffer))
					wt.inputBuffer = nil
				}
			case 127, 8:
				if len(wt.inputBuffer) > 0 {
					wt.inputBuffer = wt.inputBuffer[:len(wt.inputBuffer)-1]
				}
			default:
				wt.inputBuffer = append(wt.inputBuffer, b)
			}
		}
		_, err := wt.slave.Write(data[1:])
		return errors.Wrapf(err, "failed to write received data to slave")

	case Ping:
		return wt.masterWrite([]byte{Pong})

	case ResizeTerminal:
		if wt.columns != 0 && wt.rows != 0 {
			break
		}
		if len(data) <= 1 {
			return errors.New("received malformed remote command for terminal resize: empty payload")
		}
		var args argResizeTerminal
		err := json.Unmarshal(data[1:], &args)
		if err != nil {
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
			_ = wt.sentOTPMessage("\n\rcode incorrect\n\rPlease enter the OTP code:")
			return nil
		}
		otp := data[1:]
		if utils.VerifyOTP(string(otp)) {
			wt.shouldVerifyOTP = false
			_ = wt.sentOTPMessage("\n\rcode correct\n\r")
		} else {
			_ = wt.sentOTPMessage("\n\rcode incorrect\n\rPlease enter the OTP code:")
			wt.writeMutex.Lock()
			wt.lastFailedOTP = time.Now()
			wt.writeMutex.Unlock()
		}

	default:
		return errors.Errorf("unknown message type %c", data[0])
	}
	return nil
}

func (wt *WebTTY) sentOTPMessage(message string) error {
	msg := map[string]string{
		"message":      message,
		"shouldVerify": strconv.FormatBool(wt.shouldVerifyOTP),
	}
	msgBytes, _ := json.Marshal(msg)
	return wt.masterWrite(append([]byte{OTPRequest}, []byte(base64.StdEncoding.EncodeToString(msgBytes))...))
}

type argResizeTerminal struct {
	Columns float64
	Rows    float64
}
