/*
 * 项目名称：sing-box_bw
 * 文件名：socks.go
 * 日期：2025/08/02 21:20
 * 作者：Ben
 */

package subconvert

import (
	"strings"
)

func explodeSocks(link string, node *Proxy) {
	var group, remarks, server, port, username, password string

	if strings.HasPrefix(link, "socks://") { // v2rayn socks link
		if strings.Contains(link, "#") {
			pos := strings.Index(link, "#")
			remarks = urlDecode(link[pos+1:])
			link = link[:pos]
		}

		decodedLink := urlSafeBase64Decode(link[8:])
		if strings.Contains(decodedLink, "@") {
			userinfo := strings.Split(decodedLink, "@")
			if len(userinfo) < 2 {
				return
			}
			decodedLink = userinfo[1]
			userinfo = strings.Split(userinfo[0], ":")
			if len(userinfo) < 2 {
				return
			}
			username = userinfo[0]
			password = userinfo[1]
		}

		arguments := strings.Split(decodedLink, ":")
		if len(arguments) < 2 {
			return
		}
		server = arguments[0]
		port = arguments[1]
	} else if strings.Contains(link, "https://t.me/socks") || strings.Contains(link, "tg://socks") { // telegram style socks link
		server = getUrlArg(link, "server")
		port = getUrlArg(link, "port")
		username = urlDecode(getUrlArg(link, "user"))
		password = urlDecode(getUrlArg(link, "pass"))
		remarks = urlDecode(getUrlArg(link, "remarks"))
		group = urlDecode(getUrlArg(link, "group"))
	}

	if group == "" {
		group = SOCKS_DEFAULT_GROUP
	}
	if remarks == "" {
		remarks = server + ":" + port
	}
	if port == "0" {
		return
	}

	socksConstruct(node, group, remarks, server, port, username, password, nil, nil, nil, "")
}
