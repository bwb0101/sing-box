/*
 * 项目名称：sing-box_bw
 * 文件名：trojan.go
 * 日期：2025/08/02 21:24
 * 作者：Ben
 */

package subconvert

import (
	"strings"
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
