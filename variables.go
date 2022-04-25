package h2

import (
	"crypto/x509"
	"net/url"

	tls "github.com/Carcraftz/utls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	MethodGet     = "GET"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodOptions = "OPTIONS"
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
)

type Client struct {
	Config  Config
	Cookies map[string][]hpack.HeaderField // Used to store the data of websites cookies
	Client  Website
}

type Debug struct {
	Headers     []string `json:"sentheaders"`
	HeadersRecv []string `json:"recvheaders"`
	SentFrames  []Frames `json:"send"`
	RecvFrames  []Frames `json:"recv"`
}

type Frames struct {
	StreamID uint32 `json:"streamid"`
	Setting  string `json:"name"`
	Length   uint32 `json:"len"`
}

type Website struct {
	url             *url.URL
	Conn            *http2.Framer
	MultiPlex       uint32
	Config          ReqConfig
	HasDoneFirstReq bool
}

type Config struct {
	HeaderOrder, Protocols []string
	Headers                map[string]string
	CapitalizeHeaders      bool
	Ja3                    string
}

type Response struct {
	Data    []byte
	Status  string
	Headers []hpack.HeaderField
	Debug   Debug `json:"debug"`
}

type ReqConfig struct {
	Ciphersuites             []uint16
	Certificates             []tls.Certificate
	CurvePreferences         []tls.CurveID
	Renegotiation            tls.RenegotiationSupport
	ClientAuth               tls.ClientAuthType
	InsecureSkipVerify       bool
	Proxy                    *ProxyAuth
	SaveCookies              bool
	PreferServerCipherSuites bool
	RootCAs, ClientCAs       *x509.CertPool
}

type ProxyAuth struct {
	IP, Port, User, Password string
}
