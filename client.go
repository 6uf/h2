package h2

import (
	"net/url"

	"golang.org/x/net/http2"
)

type Conn struct {
	url             *url.URL
	Conn            *http2.Framer
	MultiPlex       uint32
	Config          ReqConfig
	HasDoneFirstReq bool
}

// i suggest using webshare proxies if your using this library on a vps, since it will allow requests to go through
// if you dont use a proxy on a vps, you wont be able to send any requests due to some bot providers detecting
// datacenter ips.

// Connects to the url you supply, and stores it inside the Client struct.
func (Data *Client) Connect(addr string, config ReqConfig) error {
	if err := Data.GrabUrl(addr).GenerateConn(config); err != nil {
		return err
	}

	Data.Client.MultiPlex = 1
	Data.Client.Config = config

	return nil
}

// Does a request, since http2 doesnt like to resent new headers. after the first request it will reconnect to the server
// and make a new http2 framer variable to use.
func (Data *Client) Do(method, json string, cookies *[]string) (Config Response, err error) {
	if !Data.Client.HasDoneFirstReq {
		Data.Client.HasDoneFirstReq = true
	} else {
		if err = Data.GenerateConn(Data.Client.Config); err != nil {
			return
		}
	}

	if cookies != nil {
		Data.Config.Headers["cookie"] += TurnCookieHeader(*cookies)
	}

	Headers := Data.GetHeaders(method)
	Data.SendHeaders(Headers, method == "GET")

	if method != "GET" {
		Data.Client.DataSend([]byte(json))
	}

	return Data.FindData(Headers)
}

// Changes the proxy IP. PORT etc so the next request(s) uses it.
func (Data *Client) ChangeProxy(Proxy *ProxyAuth) {
	Data.Client.Config.Proxy = Proxy
}

// Changes the url path, so you can send to different locations under one variable.
func (Data *Client) ChangeURLPath(path string) {
	Data.Client.url.Path = path
}

// adds a header to the client struct
func (Data *Client) AddHeader(name, value string) {
	Data.Config.Headers[name] = value
}

// deletes headers from a client struct
func (Data *Client) DeleteHeader(headernames ...string) {
	for _, val := range headernames {
		delete(Data.Config.Headers, val)
	}
}
