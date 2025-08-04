/*
 * 项目名称：sing-box_bw
 * 文件名：ss.go
 * 日期：2025/08/02 14:19
 * 作者：Ben
 */

package subconvert

import (
	"encoding/json"
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func explodeSSConf(content string, nodes *[]Proxy) {
	var jsonData map[string]any
	err := json.Unmarshal([]byte(content), &jsonData)
	if err != nil {
		return
	}

	section := "configs"
	if _, hasVersion := jsonData["version"]; hasVersion {
		if _, hasServers := jsonData["servers"]; hasServers {
			section = "servers"
		}
	}

	if _, exists := jsonData[section]; !exists {
		return
	}

	group, _ := jsonData["remarks"].(string)
	if group == "" {
		group = SS_DEFAULT_GROUP
	}

	index := len(*nodes)

	// 确保 section 是数组类型
	configs, ok := jsonData[section].([]any)
	if !ok {
		return
	}

	for _, item := range configs {
		config, ok := item.(map[string]any)
		if !ok {
			continue
		}

		node := Proxy{}
		ps, _ := config["remarks"].(string)
		port, _ := config["server_port"].(string)
		if port == "0" {
			continue
		}
		if ps == "" {
			ps = ":" + port
		}
		password, _ := config["password"].(string)
		method, _ := config["method"].(string)
		server, _ := config["server"].(string)
		plugin, _ := config["plugin"].(string)
		pluginopts, _ := config["plugin_opts"].(string)

		node.Id = uint32(index)
		ssConstruct(&node, group, ps, server, port, password, method, plugin, pluginopts, nil, nil, nil, nil, "")
		*nodes = append(*nodes, node)
		index++
	}
}

func explodeShadowrocket(rocket string, node *Proxy) {
	var add, port, id, aid, net, path, host, tls, cipher, remarks string
	net = "tcp"
	obfs := "" // for other style of link
	rocket = rocket[8:]

	pos := strings.Index(rocket, "?")
	addition := rocket[pos+1:]
	rocket = rocket[:pos]

	if regGetMatch(urlSafeBase64Decode(rocket), "(.*?):(.*)@(.*):(.*)", &cipher, &id, &add, &port) == -1 {
		return
	}
	if port == "0" {
		return
	}

	remarks = urlDecode(getUrlArg(addition, "remarks"))
	obfs = getUrlArg(addition, "obfs")
	if obfs != "" {
		if obfs == "websocket" {
			net = "ws"
			host = getUrlArg(addition, "obfsParam")
			path = getUrlArg(addition, "path")
		}
	} else {
		net = getUrlArg(addition, "network")
		host = getUrlArg(addition, "wsHost")
		path = getUrlArg(addition, "wspath")
	}
	if getUrlArg(addition, "tls") == "1" {
		tls = "tls"
	}
	aid = getUrlArg(addition, "aid")

	if aid == "" {
		aid = "0"
	}

	if remarks == "" {
		remarks = add + ":" + port
	}
	vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, "", id, aid, net, cipher, path, host, "", tls, "", nil, nil, nil, nil, "")
}

func explodeSS(ss string, node *Proxy) {
	var ps, password, method, server, port, plugins, plugin, pluginopts, addition, group, secret string
	group = SS_DEFAULT_GROUP

	ss = strings.ReplaceAll(ss[5:], "/?", "?")
	if sspos := strings.Index(ss, "#"); sspos != -1 {
		ps = urlDecode(ss[sspos+1:])
		ss = ss[:sspos]
	}

	if strings.Contains(ss, "?") {
		addition = ss[strings.Index(ss, "?")+1:]
		plugins = urlDecode(getUrlArg(addition, "plugin"))
		pluginpos := strings.Index(plugins, ";")
		if pluginpos != -1 {
			plugin = plugins[:pluginpos]
			pluginopts = plugins[pluginpos+1:]
		} else {
			plugin = plugins
		}
		group = getUrlArg(addition, "group")
		if group != "" {
			group = urlSafeBase64Decode(group)
		}
		ss = ss[:strings.Index(ss, "?")]
	}

	if strings.Contains(ss, "@") {
		if regGetMatch(ss, "(\\S+?)@(\\S+):(\\d+)", &secret, &server, &port) == -1 {
			return
		}
		if regGetMatch(urlSafeBase64Decode(secret), "(\\S+?):(\\S+)", &method, &password) == -1 {
			return
		}
	} else {
		if regGetMatch(urlSafeBase64Decode(secret), "(\\S+?):(\\S+)@(\\S+):(\\d+)", &method, &password) == -1 {
			return
		}
	}

	if port == "0" {
		return
	}

	if ps == "" {
		ps = server + ":" + port
	}
	ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts, nil, nil, nil, nil, "")
}

func ToSS(proxy Proxy, pc *ProxyConfig) (ob option.Outbound) {
	oo := &option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     proxy.Hostname,
			ServerPort: proxy.Port,
		},
		Method:   proxy.EncryptMethod,
		Password: proxy.Password,
	}
	if proxy.Plugin != "" && proxy.PluginOption != "" {
		if proxy.Plugin == "simple-obfs" {
			proxy.Plugin = "obfs-local"
		}
		oo.Plugin = proxy.Plugin
		oo.PluginOptions = proxy.PluginOption
	}
	oo.RoutingMark = option.FwMark(pc.RoutingMark)
	ob.Type = constant.TypeShadowsocks
	ob.Tag = proxy.Remark
	ob.Title = pc.Title
	ob.Options = oo
	return
}
