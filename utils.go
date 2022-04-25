package h2

import (
	"bytes"
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

// Takes a normal JA3 string and parses it into ciphersuites, tokens, curves and pointFormats
func (Data *Client) ParseJA3String() (targetPointFormats []byte, suites []uint16, targetCurves []tls.CurveID) {
	if Data.Config.Ja3 != "" {
		tokens := strings.Split(Data.Config.Ja3, ",")
		ciphers := strings.Split(tokens[1], "-")
		curves := strings.Split(tokens[3], "-")
		pointFormats := strings.Split(tokens[4], "-")

		if len(curves) == 1 && curves[0] == "" {
			curves = []string{}
		}

		if len(pointFormats) == 1 && pointFormats[0] == "" {
			pointFormats = []string{}
		}

		// parse curves
		targetCurves = append(targetCurves, tls.CurveID(tls.GREASE_PLACEHOLDER)) //append grease for Chrome browsers
		for _, c := range curves {
			cid, _ := strconv.ParseUint(c, 10, 16)
			targetCurves = append(targetCurves, tls.CurveID(cid))
		}

		for _, p := range pointFormats {
			pid, _ := strconv.ParseUint(p, 10, 8)
			targetPointFormats = append(targetPointFormats, byte(pid))
		}

		for _, c := range ciphers {
			cid, _ := strconv.ParseUint(c, 10, 16)
			suites = append(suites, uint16(cid))
		}
	}

	return
}

// Makes a default Spec that contains CipherSuites, TLSver max/min. GenerateSpec adds extensions to this spec.
func (Data *Client) DefaultSpec(config ReqConfig) *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: config.Ciphersuites,
		TLSVersMax:   tls.VersionTLS13,
		TLSVersMin:   tls.VersionTLS10,
	}
}

// This checks for JA3 strings, if so it gens the pointers, ciphers, etc. then applys them to the DefaultSpec through the extension
// variable.
func (Data *Client) GenerateSpec(config ReqConfig) *tls.ClientHelloSpec {
	targetPointFormats, suites, targetCurves := Data.ParseJA3String()
	spec := Data.DefaultSpec(config)

	check := make(map[uint16]int)
	for _, val := range append(config.Ciphersuites, suites...) {
		check[val] = 1
	}

	for letter := range check {
		spec.CipherSuites = append(spec.CipherSuites, letter)
	}

	spec.Extensions = []tls.TLSExtension{
		&tls.SNIExtension{ServerName: Data.Client.url.Host},
		&tls.SupportedCurvesExtension{Curves: targetCurves},
		&tls.SupportedPointsExtension{SupportedPoints: targetPointFormats},
		&tls.SessionTicketExtension{},
		&tls.ALPNExtension{AlpnProtocols: Data.Config.Protocols},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256, // SignatureScheme identifies a signature algorithm supported by TLS. See RFC 8446, Section 4.2.3.
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA256,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA512,
			tls.ECDSAWithSHA1,
			tls.PKCS1WithSHA1}},
		&tls.KeyShareExtension{KeyShares: []tls.KeyShare{}},
		&tls.PSKKeyExchangeModesExtension{
			Modes: []uint8{0}}, // pskModeDHE
		&tls.SupportedVersionsExtension{
			Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10}}}

	return spec
}

// Generate conn performs a conn to the url you supply.
// Makes all the config options and sets JA3 if given a value.
// TODO: Add proxy support.
func (Data *Client) GenerateConn(config ReqConfig) (err error) {
	var conn net.Conn
	if config.Proxy != nil {
		req, err := proxy.SOCKS5("tcp", fmt.Sprintf("%v:%v", config.Proxy.IP, config.Proxy.Port), &proxy.Auth{
			User:     config.Proxy.User,
			Password: config.Proxy.Password,
		}, proxy.Direct)
		if err != nil {
			return err
		}

		conn, err = req.Dial("tcp", CheckAddr(Data.Client.url))
		if err != nil {
			return err
		}
	} else {
		conn, err = net.Dial("tcp", CheckAddr(Data.Client.url))
		if err != nil {
			return err
		}
	}

	if tlsConn := tls.UClient(conn, &tls.Config{
		ServerName:               Data.Client.url.Host,
		NextProtos:               Data.Config.Protocols,
		InsecureSkipVerify:       config.InsecureSkipVerify,
		Renegotiation:            config.Renegotiation,
		CipherSuites:             config.Ciphersuites,
		Certificates:             config.Certificates,
		ClientAuth:               config.ClientAuth,
		PreferServerCipherSuites: config.PreferServerCipherSuites,
		CurvePreferences:         config.CurvePreferences,
		RootCAs:                  config.RootCAs,
		ClientCAs:                config.ClientCAs,
	}, tls.HelloChrome_Auto); tlsConn.ApplyPreset(Data.GenerateSpec(config)) != nil {
		return errors.New("error while applying spec")
	} else {
		if config.SaveCookies {
			if Data.Cookies == nil || len(Data.Cookies) == 0 {
				Data.Cookies = make(map[string][]hpack.HeaderField)
			}
		}

		fmt.Fprintf(tlsConn, http2.ClientPreface)
		tlsConn.Handshake()
		tlsConn.ApplyConfig()

		Data.Client.Conn = http2.NewFramer(tlsConn, tlsConn)
		Data.Client.Conn.SetReuseFrames()
		Data.Client.Conn.AllowIllegalReads = true
		Data.Client.Conn.AllowIllegalWrites = true

		Data.WriteSettings()
		Data.Windows_Update()
		Data.Send_Prio_Frames()
	}
	return nil
}

// gets a selected cookie based on the cookie_name variable
//			e.g. "__vf_bm" > "__vf_bm=awdawd223reqfqh32rqrf32qr"
func (Data *Client) GetCookie(cookie_name, url string) string {
	for _, val := range Data.Cookies[url] {
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
func (Data *Client) TransformCookies(url string) string {
	var cookies []string
	for _, val := range Data.Cookies[url] {
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
func (Data *Website) DataSend(body []byte) {
	Data.Conn.WriteData(1, true, body)
}

// Sends priority frames, this ensures the right data is sent in the correct order.
func (Data *Client) Send_Prio_Frames() {
	Data.Client.Conn.WritePriority(3, http2.PriorityParam{
		StreamDep: 201,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(5, http2.PriorityParam{
		StreamDep: 101,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(7, http2.PriorityParam{
		StreamDep: 1,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(9, http2.PriorityParam{
		StreamDep: 7,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(11, http2.PriorityParam{
		StreamDep: 1,
		Weight:    3,
		Exclusive: false,
	})
}

// Loops over the Config headers and applies them to the Client []string variable.
// Method for example "GET".
func (Data *Client) GetHeaders(method string) (headers []string) {
	for _, name := range Data.Config.HeaderOrder {
		switch name {
		case ":authority":
			headers = append(headers, name+": "+Data.Client.url.Host)
		case ":method":
			headers = append(headers, name+": "+method)
		case ":path":
			headers = append(headers, name+": "+Data.CheckQuery().Client.url.Path)
		case ":scheme":
			headers = append(headers, name+": "+Data.Client.url.Scheme)
		default:
			if val, exists := Data.Config.Headers[name]; exists {
				headers = append(headers, name+": "+val)
			}
		}
	}

	for name, val := range Data.Config.Headers {
		if !strings.Contains(strings.Join(Data.Config.HeaderOrder, ","), name) {
			headers = append(headers, name+": "+val)
		}
	}

	return
}

// Writes the headers to the http2 framer.
// this function also encodes the headers into a []byte
// Endstream is also called in this function, only use true values when performing GET requests.
func (Data *Client) SendHeaders(headers []string, endStream bool) {
	Data.Client.Conn.WriteHeaders(
		http2.HeadersFrameParam{
			StreamID:      Data.Client.MultiPlex,
			BlockFragment: Data.FormHeaderBytes(headers),
			EndHeaders:    true,
			EndStream:     endStream,
		},
	)
}

// Writes the window update frame to the http2 framer.
func (Data *Client) Windows_Update() {
	Data.Client.Conn.WriteWindowUpdate(0, 15663105)
}

// Write settings writes the default chrome settings to the framer
func (Data *Client) WriteSettings() {
	Data.Client.Conn.WriteSettings(
		http2.Setting{
			ID: http2.SettingHeaderTableSize, Val: 65536,
		},
		http2.Setting{
			ID: http2.SettingMaxConcurrentStreams, Val: 1000,
		},
		http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: 6291456,
		},
		http2.Setting{
			ID: http2.SettingMaxHeaderListSize, Val: 262144,
		},
		http2.Setting{
			ID: http2.SettingEnablePush, Val: 1,
		},
	)
}

// Find data is called after the prior settings/window/prio frames are performed, it goes through the
// framer and returns its data, any errors and also headers / status codes.
func (Datas *Client) FindData() (Config Response, err error) {
	for key, header := range Datas.Config.Headers {
		Config.Debug.Headers = append(Config.Debug.Headers, key+":"+header)
	}

	for {
		f, err := Datas.Client.Conn.ReadFrame()
		if err != nil {
			return Config, err
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			Config.Debug.SentFrames = append(Config.Debug.SentFrames, Frames{
				Length:   f.Length,
				StreamID: f.StreamID,
				Setting:  f.String(),
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
				if Data.Name == ":status" {
					Config.Status = Data.Value
				} else if Data.Name == "set-cookie" {
					if Datas.Client.Config.SaveCookies {
						Datas.Cookies[Datas.Client.url.String()] = append(Datas.Cookies[Datas.Client.url.Host], Data)
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
func (Data *Client) GrabUrl(addr string) *Client {
	Data.Client.url, _ = url.Parse(addr)
	if Data.Client.url.Path == "" {
		Data.Client.url.Path = "/"
	}
	return Data
}

// Checks if there are params in your url and adds it to your path.
//				e.g. "/api/name?code=12343&scope=1234"
func (Data *Client) CheckQuery() *Client {
	if Data.Client.url.Query().Encode() != "" {
		Data.Client.url.Path += "?" + Data.Client.url.Query().Encode()
	}
	return Data
}

// Form header bytes takes the []string of headers and turns it into []byte data
// this is so it can be compatiable for the http2 headers.
func (Data *Client) FormHeaderBytes(headers []string) []byte {
	var val []string
	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)
	if Data.Config.CapitalizeHeaders {
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
			"upgrade-insecure-requests",
			"user-agent",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
		},
		Headers: map[string]string{
			"cache-control":             "max-age=0",
			"upgrade-insecure-requests": "1",
			"user-agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
			"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"sec-fetch-site":            "none",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-user":            "?1",
			"sec-fetch-dest":            "document",
			"sec-ch-ua":                 "\\\" Not;A Brand\\\";v=\\\"99\\\", \\\"Google Chrome\\\";v=\\\"98\\\", \\\"Chromium\\\";v=\\\"98\\",
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        "\\\"Windows\\",
			"accept-language":           "en-US,en;q=0.9",
		},
		Protocols: []string{"h2", "h1", "http/1.1"},
		Ja3:       `771,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-59-49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49177-167-109-137-49202-49198-49194-49190-49167-49157-157-61-132-49170-49160-19-49175-49165-49155-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49176-166-108-155-70-49201-49197-49193-49189-49166-49156-156-60-150-65-49169-49159-49174-49164-49154-18-17-255,11-10-35-13-15,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2`,
	}
}
