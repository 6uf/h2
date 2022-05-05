package h2

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	tls "github.com/Carcraftz/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/proxy"
)

type ReqConn struct {
	Conn Website
}

func DefaultTLSSignatureScheme() []tls.SignatureScheme {
	return []tls.SignatureScheme{
		1027,
		2052,
		1025,
		1283,
		2053,
		1281,
		2054,
		1537,
	}
}

func (Data *Conn) ParseJA3String(ja3 string) *tls.ClientHelloSpec {
	tokens := strings.Split(ja3, ",")

	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	pointFormats := strings.Split(tokens[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	// parse curves
	var targetCurves []tls.CurveID
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	// parse point formats
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// build extenions list
	var exts []tls.TLSExtension
	for _, e := range extensions {
		te, ok := extMap[e]
		if !ok {
			return nil
		}
		exts = append(exts, te)
	}
	// build SSLVersion
	vid64, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil
	}
	vid := uint16(vid64)

	// build CipherSuites
	var suites []uint16
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil
		}
		suites = append(suites, uint16(cid))
	}

	return &tls.ClientHelloSpec{
		TLSVersMin:         vid,
		TLSVersMax:         vid,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
		GetSessionID:       sha256.Sum256,
	}
}

// This checks for JA3 strings, if so it gens the pointers, ciphers, etc. then applys them to the DefaultSpec through the extension
// variable.
func (Data *Conn) DefaultSpec(config ReqConfig) *tls.ClientHelloSpec {
	if config.Custom.JA3 != "" {
		return Data.ParseJA3String(config.Custom.JA3)
	} else {
		return &tls.ClientHelloSpec{
			CipherSuites: config.Custom.Ciphersuites,
			TLSVersMin:   tls.VersionTLS13,
			TLSVersMax:   tls.VersionTLS13,
			GetSessionID: sha256.Sum256,
			Extensions: []tls.TLSExtension{
				&tls.CompressCertificateExtension{
					Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
						tls.CertCompressionZlib,
					},
				},
				&tls.StatusRequestExtension{},
				&tls.SNIExtension{ServerName: Data.Url.Host},
				&tls.SupportedCurvesExtension{Curves: config.Custom.CurvePreferences},
				&tls.SupportedPointsExtension{SupportedPoints: config.Custom.SupportedPoints},
				&tls.SCTExtension{},
				&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				&tls.UtlsExtendedMasterSecretExtension{},
				&tls.FakeRecordSizeLimitExtension{},
				&tls.SessionTicketExtension{},
				&tls.ALPNExtension{AlpnProtocols: Data.Client.Config.Protocols},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: config.Custom.TLSSignatureScheme},
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{}},
				&tls.PSKKeyExchangeModesExtension{
					Modes: []uint8{
						tls.PskModeDHE,
					}},
				&tls.RenegotiationInfoExtension{
					Renegotiation: tls.RenegotiateFreelyAsClient,
				},
				&tls.NPNExtension{},
				&tls.SupportedVersionsExtension{
					Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10}}},
		}
	}
}

// Generate conn performs a conn to the url you supply.
// Makes all the config options and sets JA3 if given a value.
// TODO: Add proxy support.
func (Data *Conn) GenerateConn(config ReqConfig) (err error) {
	var conn net.Conn
	var tlsConn *tls.UConn
	if config.Proxy != nil {
		req, err := proxy.SOCKS5("tcp", fmt.Sprintf("%v:%v", config.Proxy.IP, config.Proxy.Port), &proxy.Auth{
			User:     config.Proxy.User,
			Password: config.Proxy.Password,
		}, proxy.Direct)
		if err != nil {
			return err
		}

		conn, err = req.Dial("tcp", CheckAddr(Data.Url))
		if err != nil {
			return err
		}
	} else {
		conn, err = net.Dial("tcp", CheckAddr(Data.Url))
		if err != nil {
			return err
		}
	}

	if config.UseCustomClientHellos {
		tlsConn = tls.UClient(conn, &tls.Config{
			ServerName:               Data.Url.Host,
			NextProtos:               Data.Client.Config.Protocols,
			InsecureSkipVerify:       config.InsecureSkipVerify,
			Renegotiation:            config.Renegotiation,
			PreferServerCipherSuites: config.PreferServerCipherSuites,
			RootCAs:                  config.RootCAs,
			ClientCAs:                config.ClientCAs,
		}, tls.HelloCustom)
		if err := tlsConn.ApplyPreset(Data.DefaultSpec(config)); err != nil {
			return err
		}
	} else {
		tlsConn = tls.UClient(conn, &tls.Config{
			ServerName:               Data.Url.Host,
			NextProtos:               Data.Client.Config.Protocols,
			InsecureSkipVerify:       config.InsecureSkipVerify,
			Renegotiation:            config.Renegotiation,
			PreferServerCipherSuites: config.PreferServerCipherSuites,
			RootCAs:                  config.RootCAs,
			ClientCAs:                config.ClientCAs,
		}, config.BuildID)
	}

	if config.SaveCookies {
		if Data.Client.Cookies == nil || len(Data.Client.Cookies) == 0 {
			Data.Client.Cookies = make(map[string][]hpack.HeaderField)
		}
	}

	fmt.Fprintf(tlsConn, http2.ClientPreface)

	if err = tlsConn.Handshake(); err != nil {
		return err
	}

	Data.Conn = http2.NewFramer(tlsConn, tlsConn)
	Data.Conn.SetReuseFrames()
	Data.WriteSettings()
	Data.Windows_Update()
	Data.Send_Prio_Frames()

	return nil
}

// gets a selected cookie based on the cookie_name variable
//			e.g. "__vf_bm" > "__vf_bm=awdawd223reqfqh32rqrf32qr"
func (Data *Conn) GetCookie(cookie_name, url string) string {
	for _, val := range Data.Client.Cookies[url] {
		if strings.Contains(val.Value, cookie_name) {
			Cookie := strings.Split(val.Value, "=")
			return fmt.Sprintf("%v=%v", Cookie[0], Cookie[1])
		}
	}

	return ""
}

// Gets a header value based on the name you supply.
func GetHeaderVal(name string, headers []hpack.HeaderField) hpack.HeaderField {
	for _, data := range headers {
		if data.Name == name {
			return data
		}
	}
	return hpack.HeaderField{}
}

// This is a helper function that gets all the cookies from a
// cached url and returns them in a format that works with the cookie: header.
func (Data *Conn) TransformCookies(url string) string {
	var cookies []string
	for _, val := range Data.Client.Cookies[url] {
		cookie_name := strings.Split(val.Value, "=")
		cookies = append(cookies, fmt.Sprintf("%v=%v", cookie_name[0], cookie_name[1]))
	}
	return strings.Join(cookies, "; ")
}

// strings.Join shortcut to turn your list of coookies into a cookie: header format.
func TurnCookieHeader(Cookies []string) string {
	return strings.Join(Cookies, "; ")
}

// Sends data through the framer
func (Data *Conn) DataSend(body []byte) {
	Data.Conn.WriteData(uint32(Data.Config.ID), true, body)
}

// Sends priority frames, this ensures the right data is sent in the correct order.
func (Data *Conn) Send_Prio_Frames() {
	Data.Conn.WritePriority(3, http2.PriorityParam{
		StreamDep: 0,
		Weight:    200,
		Exclusive: false,
	})

	Data.Conn.WritePriority(5, http2.PriorityParam{
		StreamDep: 0,
		Weight:    100,
		Exclusive: false,
	})

	Data.Conn.WritePriority(7, http2.PriorityParam{
		StreamDep: 0,
		Weight:    0,
		Exclusive: false,
	})

	Data.Conn.WritePriority(9, http2.PriorityParam{
		StreamDep: 7,
		Weight:    0,
		Exclusive: false,
	})

	Data.Conn.WritePriority(11, http2.PriorityParam{
		StreamDep: 3,
		Weight:    0,
		Exclusive: false,
	})

	Data.Conn.WritePriority(13, http2.PriorityParam{
		StreamDep: 0,
		Weight:    240,
		Exclusive: false,
	})
}

// Loops over the Config headers and applies them to the Client []string variable.
// Method for example "GET".
func (Data *Conn) GetHeaders(method string) (headers []string) {
	for _, name := range Data.Client.Config.HeaderOrder {
		switch name {
		case ":authority":
			headers = append(headers, name+": "+Data.Url.Host)
		case ":method":
			headers = append(headers, name+": "+method)
		case ":path":
			headers = append(headers, name+": "+CheckQuery(Data.Url))
		case ":scheme":
			headers = append(headers, name+": "+Data.Url.Scheme)
		default:
			if val, exists := Data.Client.Config.Headers[name]; exists {
				headers = append(headers, name+": "+val)
			}
		}
	}

	for name, val := range Data.Client.Config.Headers {
		if !strings.Contains(strings.Join(Data.Client.Config.HeaderOrder, ","), name) {
			headers = append(headers, name+": "+val)
		}
	}

	return
}

// Writes the headers to the http2 framer.
// this function also encodes the headers into a []byte
// Endstream is also called in this function, only use true values when performing GET requests.
func (Data *Conn) SendHeaders(headers []string, endStream bool) {
	Data.Conn.WriteHeaders(
		http2.HeadersFrameParam{
			StreamID:      uint32(Data.Config.ID),
			BlockFragment: Data.FormHeaderBytes(headers),
			EndHeaders:    true,
			EndStream:     endStream,
		},
	)
}

// Writes the window update frame to the http2 framer.
func (Data *Conn) Windows_Update() {
	Data.Conn.WriteWindowUpdate(0, 12517377)
}

// Write settings writes the default chrome settings to the framer
func (Data *Conn) WriteSettings() {
	Data.Conn.WriteSettings(
		http2.Setting{
			ID: http2.SettingHeaderTableSize, Val: 65536,
		},
		http2.Setting{
			ID: http2.SettingEnablePush, Val: 1,
		},
		http2.Setting{
			ID: http2.SettingMaxConcurrentStreams, Val: 1000,
		},
		http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: 131072,
		},
		http2.Setting{
			ID: http2.SettingMaxFrameSize, Val: 16384,
		},
		http2.Setting{
			ID: http2.SettingMaxHeaderListSize, Val: 262144,
		},
	)
}

// Find data is called after the prior settings/window/prio frames are performed, it goes through the
// framer and returns its data, any errors and also headers / status codes.
func (Datas *Conn) FindData(Headers []string) (Config Response, err error) {
	Config.Debug.Headers = Headers
	for {
		f, err := Datas.Conn.ReadFrame()
		if err != nil {
			return Config, err
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			f.ForeachSetting(func(s http2.Setting) error {
				Config.Debug.SentFrames = append(Config.Debug.SentFrames, Frames{
					Length:   0,
					StreamID: 0,
					Setting:  s.String(),
				})
				return nil
			})
		case *http2.DataFrame:
			Config.Debug.RecvFrames = append(Config.Debug.SentFrames, Frames{
				Length:   f.Length,
				StreamID: f.StreamID,
				Setting:  f.String(),
			})

			Config.Data = append(Config.Data, f.Data()...)
			if f.FrameHeader.Flags.Has(http2.FlagDataEndStream) {
				return Config, nil
			}
		case *http2.HeadersFrame:
			Config.Debug.RecvFrames = append(Config.Debug.SentFrames, Frames{
				Length:   f.Length,
				StreamID: f.StreamID,
				Setting:  f.String(),
			})

			Config.Headers, err = hpack.NewDecoder(100000, nil).DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return Config, err
			}
			for _, Data := range Config.Headers {
				Config.Debug.HeadersRecv = append(Config.Debug.HeadersRecv, Data.Name+":"+Data.Value)
				switch Data.Name {
				case ":status":
					Config.Status = Data.Value
				case "set-cookie":
					if Datas.Config.SaveCookies {
						Datas.Client.Cookies[Datas.Url.String()] = append(Datas.Client.Cookies[Datas.Url.String()], Data)
					}
				}
			}
			if f.FrameHeader.Flags.Has(http2.FlagDataEndStream) && f.FrameHeader.Flags.Has(http2.FlagHeadersEndStream) {
				return Config, nil
			}
		case *http2.RSTStreamFrame:
			Config.Debug.RecvFrames = append(Config.Debug.SentFrames, Frames{
				Length:   f.Length,
				StreamID: f.StreamID,
				Setting:  f.String(),
			})

			return Config, errors.New(f.ErrCode.String())
		case *http2.GoAwayFrame:
			Config.Debug.RecvFrames = append(Config.Debug.SentFrames, Frames{
				Length:   f.Length,
				StreamID: f.StreamID,
				Setting:  f.String(),
			})

			return Config, errors.New(f.ErrCode.String())
		}
	}
}

//Turns the addr into a url.URL variable.
func GrabUrl(addr string) *url.URL {
	URL, _ := url.Parse(addr)
	if URL.Path == "" {
		URL.Path = "/"
	}
	return URL
}

// Checks if there are params in your url and adds it to your path.
//				e.g. "/api/name?code=12343&scope=1234"
func CheckQuery(Data *url.URL) string {
	if Data.Query().Encode() != "" {
		Data.Path += "?" + Data.Query().Encode()
	}
	return Data.Path
}

// Form header bytes takes the []string of headers and turns it into []byte data
// this is so it can be compatiable for the http2 headers.
func (Data *Conn) FormHeaderBytes(headers []string) []byte {
	var val []string
	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)
	if Data.Client.Config.CapitalizeHeaders {
		for i, header := range headers {
			if !strings.HasPrefix(header, ":") {
				parts := strings.Split(header, "-")
				for i, data := range parts {
					parts[i] = strings.Title(data)
				}
				headers[i] = strings.Join(parts, "-")
			}
		}
	}
	for _, header := range headers {
		switch data := strings.Split(header, ":"); len(data) {
		case 3:
			val = data[1:]
			val[0] = fmt.Sprintf(":%v", val[0])
		default:
			val = data[0:]
		}
		encoder.WriteField(hpack.HeaderField{Name: strings.TrimSpace(val[0]), Value: strings.TrimSpace(val[1])})
	}
	return hbuf.Bytes()
}

// Takes in the url and returns the host + port of the url.
//				e.g. "www.google.com:443"
func CheckAddr(url *url.URL) string {
	switch url.Scheme {
	case "https":
		return url.Host + ":443"
	default:
		return url.Host + ":80"
	}
}

// This returns the default config variables.
// header order, chrome like headers and protocols.
func GetDefaultConfig() Config {
	return Config{
		HeaderOrder: []string{
			":authority",
			":method",
			":path",
			":scheme",
			"accept",
			"accept-encoding",
			"accept-language",
			"cache-control",
			"content-length",
			"content-type",
			"cookie",
			"origin",
			"referer",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"sec-ch-ua-platform-version",
			"upgrade-insecure-requests",
			"user-agent",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
		},
		Headers: map[string]string{
			"cache-control":              "max-age=0",
			"upgrade-insecure-requests":  "1",
			"user-agent":                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
			"accept":                     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"sec-fetch-site":             "none",
			"sec-fetch-mode":             "navigate",
			"sec-fetch-user":             "?1",
			"sec-fetch-dest":             "document",
			"sec-ch-ua":                  "\\\" Not;A Brand\\\";v=\\\"99\\\", \\\"Google Chrome\\\";v=\\\"101\\\", \\\"Chromium\\\";v=\\\"101\\",
			"sec-ch-ua-mobile":           "?0",
			"sec-ch-ua-platform":         "\\\"Windows\\",
			"sec-ch-ua-platform-version": "14.0.0",
			"accept-language":            "en-US,en;q=0.9",
		},
		Protocols: []string{"h2", "h1", "http/1.1"},
	}
}
