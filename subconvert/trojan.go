/*
 * 项目名称：sing-box_bw
 * 文件名：trojan.go
 * 日期：2025/08/02 21:24
 * 作者：Ben
 */

package subconvert

import (
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func explodeTrojan(trojan string, node *Proxy) {
	var server, port, psk, addition, group, remark, host, path, network string
	var tfo, scv bool

	trojan = trojan[9:]
	pos := strings.LastIndex(trojan, "#")

	if pos != -1 {
		remark = urlDecode(trojan[pos+1:])
		trojan = trojan[:pos]
	}

	pos = strings.Index(trojan, "?")
	if pos != -1 {
		addition = trojan[pos+1:]
		trojan = trojan[:pos]
	}

	if regGetMatch(trojan, `(.*?)@(.*):(.*)`, &psk, &server, &port) == -1 {
		return
	}
	if port == "0" {
		return
	}

	host = getUrlArg(addition, "sni")
	if host == "" {
		host = getUrlArg(addition, "peer")
	}

	tfo = getUrlArg(addition, "tfo") == "1"
	scv = getUrlArg(addition, "allowInsecure") == "1"
	group = urlDecode(getUrlArg(addition, "group"))

	if getUrlArg(addition, "ws") == "1" {
		path = getUrlArg(addition, "wspath")
		network = "ws"
	} else if getUrlArg(addition, "type") == "ws" {
		path = getUrlArg(addition, "path")
		if len(path) >= 3 && path[:3] == "%2F" {
			path = urlDecode(path)
		}
		network = "ws"
	}

	if remark == "" {
		remark = server + ":" + port
	}
	if group == "" {
		group = TROJAN_DEFAULT_GROUP
	}

	trojanConstruct(node, group, remark, server, port, psk, network, host, path, true, nil, &tfo, &scv, nil, "")
}

func ToTrojan(proxy Proxy, pc *ProxyConfig) (ob option.Outbound) {
	oo := option.TrojanOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     proxy.Hostname,
			ServerPort: proxy.Port,
		},
		Password: proxy.Password,
	}
	if tr := v2rayTransport(proxy); tr.Type != "" {
		oo.Transport = &tr
	}
	if proxy.TLSSecure {
		oo.TLS = &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: *proxy.AllowInsecure,
		}
		if proxy.ServerName != "" {
			oo.TLS.ServerName = proxy.ServerName
		} else if proxy.Host != "" {
			oo.TLS.ServerName = proxy.Host
		}
	}
	oo.RoutingMark = option.FwMark(pc.RoutingMark)
	ob.Type = constant.TypeTrojan
	ob.Tag = proxy.Remark
	ob.Title = pc.Title
	ob.Options = oo
	return
}
