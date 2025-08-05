/*
 * 项目名称：sing-box_bw
 * 文件名：vmess.go
 * 日期：2025/08/02 14:57
 * 作者：Ben
 */

package subconvert

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func explodeVmessConf(content string, nodes *[]Proxy) {
	var jsonMap map[string]any
	var ps, add, port, typeName, id, aid, net, path, host, edge, tls, cipher, sni string
	var udp, tfo, scv *bool
	var configType int
	index := uint32(len(*nodes))
	subdata := make(map[string]string)

	streamset := "streamSettings"
	tcpset := "tcpSettings"
	wsset := "wsSettings"
	regGetMatch(content, "((?i)streamsettings)", &streamset)
	regGetMatch(content, "((?i)tcpsettings)", &tcpset)
	regGetMatch(content, "((?1)wssettings)", &wsset)

	// Parse JSON content
	err := json.Unmarshal([]byte(content), &jsonMap)
	if err != nil {
		return
	}

	// Handle single config in outbounds
	if outbounds, ok := jsonMap["outbounds"].([]any); ok && len(outbounds) > 0 {
		firstOutbound, ok := outbounds[0].(map[string]any)
		if !ok {
			return
		}
		// Check if settings.vnext exists
		settings, ok := firstOutbound["settings"].(map[string]any)
		if !ok {
			return
		}
		vn, ok := settings["vnext"]
		if !ok {
			return
		}
		vnext, ok := vn.([]any)
		if !ok || len(vnext) == 0 {
			return
		}
		vnext0, ok := vnext[0].(map[string]any)
		if !ok {
			return
		}
		add, _ = vnext0["address"].(string)
		port, _ = vnext0["port"].(string)
		if port == "0" {
			return
		}
		if _users, ok := vnext0["users"]; ok {
			if users, ok := _users.([]any); ok && len(users) > 0 {
				if u0, ok := users[0].(map[string]any); ok {
					id, _ = u0["id"].(string)
					aid, _ = u0["alterId"].(string)
					cipher, _ = u0["security"].(string)
				}
			}
		}
		// Handle stream settings
		if streamSettings, ok := firstOutbound[streamset].(map[string]any); ok {
			net, _ = streamSettings["network"].(string)
			tls, _ = streamSettings["security"].(string)

			if net == "ws" {
				var wsSettings, ok = streamSettings[wsset].(map[string]any)
				if !ok {
					wsSettings = make(map[string]any)
				}
				path, _ = wsSettings["path"].(string)
				if headers, ok := wsSettings["headers"].(map[string]any); ok {
					host, _ = headers["Host"].(string)
					edge, _ = headers["Edge"].(string)
				}
			}

			var tcpSettings, ok = streamSettings[tcpset].(map[string]any)
			if !ok {
				tcpSettings = make(map[string]any)
			}
			if header, ok := tcpSettings["header"].(map[string]any); ok {
				typeName, _ = header["type"].(string)
				if typeName == "http" {
					if request, ok := header["request"].(map[string]any); ok {
						if r, ok := request[path]; ok {
							if parr, ok := r.([]any); ok && len(parr) > 0 {
								if path0, ok := parr[0].(string); ok {
									path = path0
								}
							}
						}
						if headers, ok := request["headers"].(map[string]any); ok {
							host, _ = headers["Host"].(string)
							edge, _ = headers["Edge"].(string)
						}
					}
				}
			}
		}
		node := Proxy{}
		vmessConstruct(&node, V2RAY_DEFAULT_GROUP, add+":"+port, add, port, typeName, id, aid, net, cipher, path, host, edge, tls, "", udp, tfo, scv, nil, "")
		*nodes = append(*nodes, node)
		return
	}

	if si, ok := jsonMap["subItem"]; ok {
		if subItems, ok := si.([]any); ok {
			for _, item := range subItems {
				if itemMap, ok := item.(map[string]any); ok {
					if idVal, ok := itemMap["id"].(string); ok {
						if remarks, ok := itemMap["remarks"].(string); ok {
							subdata[idVal] = remarks
						}
					}
				}
			}
		}
	}
	if vm, ok := jsonMap["vmess"]; ok {
		if vmessArr, ok := vm.([]any); ok {
			for _, item := range vmessArr {
				vmessMap, ok := item.(map[string]any)
				if !ok {
					continue
				}

				// Skip if required fields are missing
				if isNull(vmessMap, "address") || isNull(vmessMap, "port") || isNull(vmessMap, "id") {
					continue
				}

				// Common info
				ps, _ = vmessMap["remarks"].(string)
				add, _ = vmessMap["address"].(string)
				port, _ = vmessMap["port"].(string)
				if port == "0" {
					continue
				}
				// subid, _ = vmessMap["subid"].(string)
				// if subid != "" {
				// 	if val, ok := subdata[subid]; ok {
				// 		group = val
				// 	}
				// }
				if ps == "" {
					ps = add + ":" + port
				}

				scv = getMapBoolStr(vmessMap, "allowInsecure")
				if configTypeVal, ok := vmessMap["configType"]; ok {
					if configTypeFloat, ok := configTypeVal.(float64); ok {
						configType = int(configTypeFloat)
					}
				}

				switch configType {
				case 1: // vmess config
					typeName, _ = vmessMap["headerType"].(string)
					id, _ = vmessMap["id"].(string)
					aid, _ = vmessMap["alterId"].(string)
					net, _ = vmessMap["network"].(string)
					path, _ = vmessMap["path"].(string)
					host, _ = vmessMap["requestHost"].(string)
					tls, _ = vmessMap["streamSecurity"].(string)
					cipher, _ = vmessMap["security"].(string)
					sni, _ = vmessMap["sni"].(string)
					node := Proxy{}
					vmessConstruct(&node, V2RAY_DEFAULT_GROUP, ps, add, port, typeName, id, aid, net, cipher, path, host, "", tls, sni, udp, tfo, scv, nil, "")
					node.Id = index
					*nodes = append(*nodes, node)
				case 3: // ss config
					id, _ = vmessMap["id"].(string)
					cipher, _ = vmessMap["security"].(string)
					node := Proxy{}
					ssConstruct(&node, SS_DEFAULT_GROUP, ps, add, port, id, cipher, "", "", udp, tfo, scv, nil, "")
					node.Id = index
					*nodes = append(*nodes, node)
				case 4: // socks config
					node := Proxy{}
					socksConstruct(&node, SOCKS_DEFAULT_GROUP, ps, add, port, "", "", udp, tfo, scv, "")
					node.Id = index
					*nodes = append(*nodes, node)
				default:
					continue
				}
				index++
			}
		}
	}
}

func explodeVmess(vmess string, node *Proxy) {
	var version, ps, add, port, typeName, id, aid, net, path, host, tls, sni string
	var vArray []string

	if regMatch(vmess, `vmess://([A-Za-z0-9-_]+)\?(.*)`) { // shadowrocket style link
		explodeShadowrocket(vmess, node)
		return
	} else if regMatch(vmess, `vmess://(.*?)@(.*)`) {
		explodeStdVMess(vmess, node)
		return
	} else if regMatch(vmess, `vmess1://(.*?)\?(.*)`) { // kitsunebi style link
		explodeKitsunebi(vmess, node)
		return
	}

	vmess = urlSafeBase64Decode(regReplace(vmess, `(vmess|vmess1)://`, "", true, true))
	if regMatch(vmess, `(.*?) = (.*)`) {
		explodeQuan(vmess, node)
		return
	}

	var jsondata map[string]any
	if err := json.Unmarshal([]byte(vmess), &jsondata); err != nil {
		return
	}
	version = "1" // link without version will treat as version 1
	getMember(jsondata, "v", &version)
	getMember(jsondata, "ps", &ps)
	getMember(jsondata, "add", &add)
	getMember(jsondata, "port", &port)
	if port == "0" {
		return
	}
	getMember(jsondata, "type", &typeName)
	getMember(jsondata, "id", &id)
	getMember(jsondata, "aid", &aid)
	getMember(jsondata, "net", &net)
	getMember(jsondata, "tls", &tls)
	getMember(jsondata, "host", &host)
	getMember(jsondata, "sni", &sni)
	switch version {
	case "1":
		if host != "" {
			vArray = strings.Split(host, ";")
			if len(vArray) == 2 {
				host = vArray[0]
				path = vArray[1]
			}
		}
	case "2":
		if v, ok := jsondata["path"]; ok {
			path = fmt.Sprintf("%v", v)
		}
	}

	add = strings.TrimSpace(add)

	vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, typeName, id, aid, net, "auto", path, host, "", tls, sni, nil, nil, nil, nil, "")
}

func explodeStdVMess(vmess string, node *Proxy) {
	var add, port, typeName, id, aid, net, path, host, tls, remarks, addition string

	vmess = vmess[8:]
	pos := strings.LastIndex(vmess, "#")
	if pos != -1 {
		remarks = urlDecode(vmess[pos+1:])
		vmess = vmess[:pos]
	}

	stdvmessMatcher := `^([a-z]+)(?:\+([a-z]+))?:([\da-f]{4}(?:[\da-f]{4}-){4}[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?\?(.*))?$`
	if regGetMatch(vmess, stdvmessMatcher, &net, &tls, &id, &aid, &add, &port, &addition) == -1 {
		return
	}

	switch net {
	case "tcp", "kcp":
		typeName = getUrlArg(addition, "type")
	case "http", "ws":
		host = getUrlArg(addition, "host")
		path = getUrlArg(addition, "path")
	case "quic":
		typeName = getUrlArg(addition, "security")
		host = getUrlArg(addition, "type")
		path = getUrlArg(addition, "key")
	default:
		return
	}

	if remarks == "" {
		remarks = add + ":" + port
	}

	vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, typeName, id, aid, net, "auto", path, host, "", tls, "", nil, nil, nil, nil, "")
}

func explodeKitsunebi(kit string, node *Proxy) {
	var add, port, typeName, id, aid, net, path, host, tls, cipher, remarks string
	var addition string
	var pos int

	aid = "0"
	net = "tcp"
	cipher = "auto"

	kit = kit[9:]

	pos = strings.Index(kit, "#")
	if pos != -1 {
		remarks = kit[pos+1:]
		kit = kit[:pos]
	}

	pos = strings.Index(kit, "?")
	if pos != -1 {
		addition = kit[pos+1:]
		kit = kit[:pos]
	}

	if regGetMatch(kit, `(.*?)@(.*):(.*)`, &id, &add, &port) == -1 {
		return
	}

	pos = strings.Index(port, "/")
	if pos != -1 {
		path = port[pos:]
		port = port[:pos]
	}

	if port == "0" {
		return
	}

	net = getUrlArg(addition, "network")
	if getUrlArg(addition, "tls") == "true" {
		tls = "tls"
	} else {
		tls = ""
	}
	host = getUrlArg(addition, "ws.host")

	if remarks == "" {
		remarks = add + ":" + port
	}

	vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, typeName, id, aid, net, cipher, path, host, "", tls, "", nil, nil, nil, nil, "")
}

func explodeQuan(quan string, node *Proxy) {
	var strTemp, itemName, itemVal string
	group := V2RAY_DEFAULT_GROUP
	var ps, add, port, cipher, typeName, id string
	aid := "0"
	net := "tcp"
	var path, host, edge, tls string
	var configs, vArray, headers []string

	strTemp = regReplace(quan, `(.*?) = (.*)`, "$1,$2", true, true)
	configs = strings.Split(strTemp, ",")

	if len(configs) > 1 && configs[1] == "vmess" {
		if len(configs) < 6 {
			return
		}
		ps = strings.TrimSpace(configs[0])
		add = strings.TrimSpace(configs[2])
		port = strings.TrimSpace(configs[3])
		if port == "0" {
			return
		}
		cipher = strings.TrimSpace(configs[4])
		id = strings.TrimSpace(replaceAllDistinct(configs[5], `"`, ""))

		// read link
		for i := 6; i < len(configs); i++ {
			vArray = strings.Split(configs[i], "=")
			if len(vArray) < 2 {
				continue
			}
			itemName = strings.TrimSpace(vArray[0])
			itemVal = strings.TrimSpace(vArray[1])
			switch itemName {
			case "group":
				group = itemVal
			case "over-tls":
				if itemVal == "true" {
					tls = "tls"
				} else {
					tls = ""
				}
			case "tls-host":
				host = itemVal
			case "obfs-path":
				path = regReplace(itemVal, `"`, "", true, true)
			case "obfs-header":
				headerStr := replaceAllDistinct(replaceAllDistinct(itemVal, `"`, ""), `[Rr][Nn]`, "|")
				headers = strings.Split(headerStr, "|")
				for _, x := range headers {
					if regMatch(x, `(?i)Host: `) {
						host = x[6:]
					} else if regMatch(x, `(?i)Edge: `) {
						edge = x[6:]
					}
				}
			case "obfs":
				if itemVal == "ws" {
					net = "ws"
				}
			default:
				continue
			}
		}
		if path == "" {
			path = "/"
		}

		vmessConstruct(node, group, ps, add, port, typeName, id, aid, net, cipher, path, host, edge, tls, "", nil, nil, nil, nil, "")
	}
}

func ToVMESS(proxy Proxy, pc *ProxyConfig) (ob option.Outbound) {
	oo := &option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     proxy.Hostname,
			ServerPort: proxy.Port,
		},
		UUID:     proxy.UUID,
		Security: proxy.EncryptMethod,
		AlterId:  int(proxy.AlterId),
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
	ob.Type = constant.TypeVMess
	ob.Tag = proxy.Remark
	ob.Title = pc.Title
	ob.Options = oo
	return
}
