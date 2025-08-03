/*
 * 项目名称：sing-box_bw
 * 文件名：ssr.go
 * 日期：2025/08/02 14:41
 * 作者：Ben
 */

package subconvert

import (
	"encoding/json"
	"strings"

	"github.com/sagernet/sing-box/option"
)

func explodeSSRConf(content string, nodes *[]Proxy) {
	var jsonData map[string]any
	index := len(*nodes)

	if err := json.Unmarshal([]byte(content), &jsonData); err != nil {
		return
	}

	// 处理单个libev配置
	if _, hasLocalPort := jsonData["local_port"]; hasLocalPort {
		if _, hasLocalAddress := jsonData["local_address"]; hasLocalAddress {
			var node Proxy
			server, _ := jsonData["server"].(string)
			port, _ := jsonData["server_port"].(string)
			remarks := server + ":" + port
			method, _ := jsonData["method"].(string)
			obfs, _ := jsonData["obfs"].(string)
			protocol, _ := jsonData["protocol"].(string)

			// 检查是否是普通Shadowsocks配置
			isPlainSS := false
			for _, cipher := range ssCiphers {
				if cipher == method {
					isPlainSS = (obfs == "" || obfs == "plain") && (protocol == "" || protocol == "origin")
					break
				}
			}

			if isPlainSS {
				plugin, _ := jsonData["plugin"].(string)
				pluginOpts, _ := jsonData["plugin_opts"].(string)
				ssConstruct(&node, SS_DEFAULT_GROUP, remarks, server, port, "", method, plugin, pluginOpts, nil, nil, nil, nil, "")
			} else {
				protoparam, _ := jsonData["protocol_param"].(string)
				obfsparam, _ := jsonData["obfs_param"].(string)
				ssrConstruct(&node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, obfs, "", obfsparam, protoparam, nil, nil, nil, "")
			}
			*nodes = append(*nodes, node)
			return
		}
	}

	// 处理配置数组
	configs, ok := jsonData["configs"].([]any)
	if !ok {
		return
	}

	for _, item := range configs {
		config, ok := item.(map[string]any)
		if !ok {
			continue
		}

		var node Proxy
		group, _ := config["group"].(string)
		if group == "" {
			group = SSR_DEFAULT_GROUP
		}
		remarks, _ := config["remarks"].(string)
		server, _ := config["server"].(string)
		port, _ := config["server_port"].(string)
		if port == "0" {
			continue
		}
		if remarks == "" {
			remarks = server + ":" + port
		}
		password, _ := config["password"].(string)
		method, _ := config["method"].(string)
		protocol, _ := config["protocol"].(string)
		protoparam, _ := config["protocolparam"].(string)
		obfs, _ := config["obfs"].(string)
		obfsparam, _ := config["obfsparam"].(string)
		ssrConstruct(&node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam, nil, nil, nil, "")
		node.Id = uint32(index)
		*nodes = append(*nodes, node)
		index++
	}
}

func explodeSSR(ssr string, node *Proxy) {
	var strobfs string
	var remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam string

	ssr = strings.ReplaceAll(ssr[6:], "\r", "")
	ssr = urlSafeBase64Decode(ssr)
	if strings.Contains(ssr, "/?") {
		pos := strings.Index(ssr, "/?")
		strobfs = ssr[pos+2:]
		ssr = ssr[:pos]
		group = urlSafeBase64Decode(getUrlArg(strobfs, "group"))
		remarks = urlSafeBase64Decode(getUrlArg(strobfs, "remarks"))
		obfsparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "obfsparam")), "\\s", "", true, true)
		protoparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "protoparam")), "\\s", "", true, true)
	}

	if regGetMatch(ssr, `(\\S+):(\\d+?):(\\S+?):(\\S+?):(\\S+?):(\\S+)`, &server, &port, &protocol, &method, &obfs, &password) == -1 {
		return
	}
	password = urlSafeBase64Decode(password)
	if port == "0" {
		return
	}

	if group == "" {
		group = SSR_DEFAULT_GROUP
	}
	if remarks == "" {
		remarks = server + ":" + port
	}

	found := false
	for _, cipher := range ssCiphers {
		if cipher == method {
			found = true
			break
		}
	}

	if found && (obfs == "" || obfs == "plain") && (protocol == "" || protocol == "origin") {
		ssConstruct(node, group, remarks, server, port, password, method, "", "", nil, nil, nil, nil, "")
	} else {
		ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam, nil, nil, nil, "")
	}
}

func ToSSR(proxy Proxy, title string, routingMark int) (ob option.Outbound) {
	// oo := option.ShadowsocksROutboundOptions{
	// 	ServerOptions: option.ServerOptions{
	// 		Server:     proxy.Hostname,
	// 		ServerPort: proxy.Port,
	// 	},
	// 	Method:   proxy.EncryptMethod,
	// 	Password: proxy.Password,
	// }
	// oo.RoutingMark = option.FwMark(routingMark)
	// ob.Type = constant.TypeShadowsocks
	// ob.Tag = title + "_" + proxy.Remark
	return
}
