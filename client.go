package h2

import (
	"net/url"

	"golang.org/x/net/http2"
)

type Conn struct {
	Url      *url.URL
	Conn     *http2.Framer
	Config   ReqConfig
	Client   *Client
	FirstUse bool
}

// i suggest using webshare proxies if your using this library on a vps, since it will allow requests to go through
// if you dont use a proxy on a vps, you wont be able to send any requests due to some bot providers detecting
// datacenter ips.

// Connects to the url you supply, and stores it inside the Client struct.
func (Data *Client) Connect(addr string, config ReqConfig) (Connection Conn, err error) {
	Connection.Url = GrabUrl(addr)
	Connection.Client = Data
	Connection.Config = config

	if err := Connection.GenerateConn(config); err != nil {
		return Conn{}, err
	}

	return Connection, nil
}

// Does a request, since http2 doesnt like to resent new headers. after the first request it will reconnect to the server
// and make a new http2 framer variable to use.
func (Data *Conn) Do(method, json string, cookies *[]string) (Config Response, err error) {
	/*if !Data.FirstUse {
		Data.FirstUse = true
	} else {
		if err = Data.GenerateConn(Data.Config); err != nil {
			return
		}
	}*/

	if cookies != nil {
		Data.Client.Config.Headers["cookie"] += TurnCookieHeader(*cookies)
	}

	Headers := Data.GetHeaders(method)
	Data.SendHeaders(Headers, method == "GET")

	if method != "GET" {
		Data.DataSend([]byte(json))
	}

	return Data.FindData(Headers)
}

func (Data *Conn) ChangeProxy(proxy *ProxyAuth) {
	Data.Config.Proxy = proxy
}

// Changes the url path, so you can send to different locations under one variable.
func (Data *Conn) ChangeURLPath(path string) {
	Data.Url.Path = path
}

// adds a header to the client struct
func (Data *Conn) AddHeader(name, value string) {
	Data.Client.Config.Headers[name] = value
}

// deletes headers from a client struct
func (Data *Conn) DeleteHeader(headernames ...string) {
	for _, val := range headernames {
		delete(Data.Client.Config.Headers, val)
	}
}
