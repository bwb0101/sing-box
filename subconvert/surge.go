/*
 * 项目名称：sing-box_bw
 * 文件名：surge.go
 * 日期：2025/08/02 16:46
 * 作者：Ben
 */

package subconvert

import (
	"regexp"
	"strings"

	"gopkg.in/ini.v1"
)

func explodeSurge(surge string, nodes *[]Proxy) bool {
	proxies := make(map[string]string)
	index := uint32(len(*nodes))

	if strings.Contains(surge, "[Proxy]") {
		re := regexp.MustCompile(`^[\S\s]*?\[`)
		surge = re.ReplaceAllString(surge, "[")
	}

	// 解析 INI 格式的配置
	iniFile, err := ini.LoadSources(ini.LoadOptions{
		AllowShadows:            true,
		SkipUnrecognizableLines: false,
	}, []byte(surge))
	if err != nil {
		return false
	}

	// 检查是否存在 [Proxy] 部分
	proxySection, err := iniFile.GetSection("Proxy")
	if err != nil {
		return false
	}

	// 遍历 [Proxy] 部分中的所有键值对
	for _, key := range proxySection.Keys() {
		proxies[key.Name()] = key.Value()
	}

	proxyRegex := regexp.MustCompile(`(.*?)\s*=\s*(.*)`)

	for _, configStr := range proxies {
		matches := proxyRegex.FindStringSubmatch(configStr)
		if len(matches) < 3 {
			continue
		}
		remarks := strings.TrimSpace(matches[1])
		config := strings.TrimSpace(matches[2])
		configs := strings.Split(config, ",")

		if len(configs) < 3 {
			continue
		}

		var (
			server, port, method, username, password                       string
			plugin, pluginopts, pluginopts_mode, pluginopts_host           string
			id, net, tls, host, edge, path                                 string
			protocol, protoparam                                           string
			section, ip, ipv6, private_key, mtu, test_url, peer, keepalive string
			dns_servers                                                    []string
			version, aead                                                  = "1", "1"
			itemName, itemVal                                              string
			vArray, headers, header                                        []string
			udp, tfo, scv, tls13                                           bool
			node                                                           Proxy
		)

		switch strings.TrimSpace(configs[0]) {
		case "direct", "reject", "reject-tinygif":
			continue
		case "custom": // surge 2 style custom proxy
			if len(configs) < 5 {
				continue
			}
			server = strings.TrimSpace(configs[1])
			port = strings.TrimSpace(configs[2])
			if port == "0" {
				continue
			}
			method = strings.TrimSpace(configs[3])
			password = strings.TrimSpace(configs[4])

			for i := 6; i < len(configs); i++ {
				vArray = strings.Split(configs[i], "=")
				if len(vArray) < 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "obfs":
					plugin = "simple-obfs"
					pluginopts_mode = itemVal
				case "obfs-host":
					pluginopts_host = itemVal
				case "udp-relay":
					udp = itemVal == "true"
				case "tfo":
					tfo = itemVal == "true"
				default:
					continue
				}
			}
			if plugin != "" {
				pluginopts = "obfs=" + pluginopts_mode
				if pluginopts_host != "" {
					pluginopts += ";obfs-host=" + pluginopts_host
				}
			}
			ssConstruct(&node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, &udp, &tfo, &scv, nil, "")
		case "ss": // surge 3 style ss proxy
			server = strings.TrimSpace(configs[1])
			port = strings.TrimSpace(configs[2])
			if port == "0" {
				continue
			}

			for i := 3; i < len(configs); i++ {
				vArray = strings.Split(configs[i], "=")
				if len(vArray) < 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "encrypt-method":
					method = itemVal
				case "password":
					password = itemVal
				case "obfs":
					plugin = "simple-obfs"
					pluginopts_mode = itemVal
				case "obfs-host":
					pluginopts_host = itemVal
				case "udp-relay":
					udp = itemVal == "true"
				case "tfo":
					tfo = itemVal == "true"
				default:
					continue
				}
			}
			if plugin != "" {
				pluginopts = "obfs=" + pluginopts_mode
				if pluginopts_host != "" {
					pluginopts += ";obfs-host=" + pluginopts_host
				}
			}
			ssConstruct(&node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, &udp, &tfo, &scv, nil, "")
		case "socks5": // surge 3 style socks5 proxy
			server = strings.TrimSpace(configs[1])
			port = strings.TrimSpace(configs[2])
			if port == "0" {
				continue
			}
			if len(configs) >= 5 {
				username = strings.TrimSpace(configs[3])
				password = strings.TrimSpace(configs[4])
			}
			for i := 5; i < len(configs); i++ {
				vArray = strings.Split(configs[i], "=")
				if len(vArray) < 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "udp-relay":
					udp = itemVal == "true"
				case "tfo":
					tfo = itemVal == "true"
				case "skip-cert-verify":
					scv = itemVal == "true"
				default:
					continue
				}
			}
			socksConstruct(&node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, &udp, &tfo, &scv, "")
		case "vmess": // surge 4 style vmess proxy
			server = strings.TrimSpace(configs[1])
			port = strings.TrimSpace(configs[2])
			if port == "0" {
				continue
			}
			net = "tcp"
			method = "auto"

			for i := 3; i < len(configs); i++ {
				vArray = strings.Split(configs[i], "=")
				if len(vArray) != 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "username":
					id = itemVal
				case "ws":
					if itemVal == "true" {
						net = "ws"
					} else {
						net = "tcp"
					}
				case "tls":
					if itemVal == "true" {
						tls = "tls"
					} else {
						tls = ""
					}
				case "ws-path":
					path = itemVal
				case "obfs-host":
					host = itemVal
				case "ws-headers":
					headers = strings.Split(itemVal, "|")
					for _, y := range headers {
						header = strings.Split(strings.TrimSpace(y), ":")
						if len(header) != 2 {
							continue
						} else if strings.Contains(strings.ToLower(header[0]), "host") {
							host = strings.Trim(header[1], "\"")
						} else if strings.Contains(strings.ToLower(header[0]), "edge") {
							edge = strings.Trim(header[1], "\"")
						}
					}
				case "udp-relay":
					udp = itemVal == "true"
				case "tfo":
					tfo = itemVal == "true"
				case "skip-cert-verify":
					scv = itemVal == "true"
				case "tls13":
					tls13 = itemVal == "true"
				case "vmess-aead":
					if itemVal == "true" {
						aead = "0"
					} else {
						aead = "1"
					}
				default:
					continue
				}
			}
			vmessConstruct(&node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, edge, tls, "", &udp, &tfo, &scv, &tls13, "")
		case "http": // http proxy
			server = strings.TrimSpace(configs[1])
			port = strings.TrimSpace(configs[2])
			if port == "0" {
				continue
			}
			for i := 3; i < len(configs); i++ {
				vArray = strings.Split(configs[i], "=")
				if len(vArray) < 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "username":
					username = itemVal
				case "password":
					password = itemVal
				case "skip-cert-verify":
					scv = itemVal == "true"
				default:
					continue
				}
			}
			httpConstruct(&node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, false, &tfo, &scv, nil, "")
		case "trojan": // surge 4 style trojan proxy
			server = strings.TrimSpace(configs[1])
			port = strings.TrimSpace(configs[2])
			if port == "0" {
				continue
			}

			for i := 3; i < len(configs); i++ {
				vArray = strings.Split(configs[i], "=")
				if len(vArray) != 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "password":
					password = itemVal
				case "sni":
					host = itemVal
				case "udp-relay":
					udp = itemVal == "true"
				case "tfo":
					tfo = itemVal == "true"
				case "skip-cert-verify":
					scv = itemVal == "true"
				default:
					continue
				}
			}
			trojanConstruct(&node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", true, &udp, &tfo, &scv, nil, "")
		case "snell":
			server = strings.TrimSpace(configs[1])
			port = strings.TrimSpace(configs[2])
			if port == "0" {
				continue
			}

			for i := 3; i < len(configs); i++ {
				vArray = strings.Split(configs[i], "=")
				if len(vArray) != 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "psk":
					password = itemVal
				case "obfs":
					plugin = itemVal
				case "obfs-host":
					host = itemVal
				case "udp-relay":
					udp = itemVal == "true"
				case "tfo":
					tfo = itemVal == "true"
				case "skip-cert-verify":
					scv = itemVal == "true"
				case "version":
					version = itemVal
				default:
					continue
				}
			}
			snellConstruct(&node, SNELL_DEFAULT_GROUP, remarks, server, port, password, plugin, host, uint16(toInt(version, 0)), &udp, &tfo, &scv, "")
		case "wireguard":
			for i := 1; i < len(configs); i++ {
				vArray = strings.Split(strings.TrimSpace(configs[i]), "=")
				if len(vArray) != 2 {
					continue
				}
				itemName = strings.TrimSpace(vArray[0])
				itemVal = strings.TrimSpace(vArray[1])
				switch itemName {
				case "section-name":
					section = itemVal
				case "test-url":
					test_url = itemVal
				}
			}
			if section == "" {
				continue
			}
			wgSection, err := iniFile.GetSection("WireGuard " + section)
			if err != nil {
				continue
			}
			for _, key := range wgSection.Keys() {
				itemName = strings.TrimSpace(key.Name())
				itemVal = strings.TrimSpace(key.Value())
				switch itemName {
				case "self-ip":
					ip = itemVal
				case "self-ip-v6":
					ipv6 = itemVal
				case "private-key":
					private_key = itemVal
				case "dns-server":
					vArray = strings.Split(itemVal, ",")
					for _, y := range vArray {
						dns_servers = append(dns_servers, strings.TrimSpace(y))
					}
				case "mtu":
					mtu = itemVal
				case "peer":
					peer = itemVal
				case "keepalive":
					keepalive = itemVal
				}
			}
			wireguardConstruct(&node, WG_DEFAULT_GROUP, remarks, "", "0", ip, ipv6, private_key, "", "", dns_servers, mtu, keepalive, test_url, "", &udp, "")
			parsePeers(&node, peer)
		default:
			switch remarks {
			case "shadowsocks": // quantumult x style ss/ssr link
				parts := strings.Split(configs[0], ":")
				if len(parts) < 2 {
					continue
				}
				server = strings.TrimSpace(parts[0])
				port = strings.TrimSpace(parts[1])
				if port == "0" {
					continue
				}

				for i := 1; i < len(configs); i++ {
					vArray = strings.Split(strings.TrimSpace(configs[i]), "=")
					if len(vArray) != 2 {
						continue
					}
					itemName = strings.TrimSpace(vArray[0])
					itemVal = strings.TrimSpace(vArray[1])
					switch itemName {
					case "method":
						method = itemVal
					case "password":
						password = itemVal
					case "tag":
						remarks = itemVal
					case "ssr-protocol":
						protocol = itemVal
					case "ssr-protocol-param":
						protoparam = itemVal
					case "obfs":
						switch itemVal {
						case "http", "tls":
							plugin = "simple-obfs"
							pluginopts_mode = itemVal
						case "wss":
							tls = "tls"
							fallthrough
						case "ws":
							pluginopts_mode = "websocket"
							plugin = "v2ray-plugin"
						default:
							pluginopts_mode = itemVal
						}
					case "obfs-host":
						pluginopts_host = itemVal
					case "obfs-uri":
						path = itemVal
					case "udp-relay":
						udp = itemVal == "true"
					case "fast-open":
						tfo = itemVal == "true"
					case "tls13":
						tls13 = itemVal == "true"
					default:
						continue
					}
				}
				if remarks == "" {
					remarks = server + ":" + port
				}
				switch plugin {
				case "simple-obfs":
					pluginopts = "obfs=" + pluginopts_mode
					if pluginopts_host != "" {
						pluginopts += ";obfs-host=" + pluginopts_host
					}
				case "v2ray-plugin":
					if pluginopts_host == "" && !isIPv4(server) && !isIPv6(server) {
						pluginopts_host = server
					}
					pluginopts = "mode=" + pluginopts_mode
					if pluginopts_host != "" {
						pluginopts += ";host=" + pluginopts_host
					}
					if path != "" {
						pluginopts += ";path=" + path
					}
					pluginopts += ";" + tls
				}

				if protocol != "" {
					ssrConstruct(&node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, pluginopts_mode, password, pluginopts_host, protoparam, &udp, &tfo, &scv, "")
				} else {
					ssConstruct(&node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, &udp, &tfo, &scv, &tls13, "")
				}
			case "vmess": // quantumult x style vmess link
				parts := strings.Split(configs[0], ":")
				if len(parts) < 2 {
					continue
				}
				server = strings.TrimSpace(parts[0])
				port = strings.TrimSpace(parts[1])
				if port == "0" {
					continue
				}
				net = "tcp"

				for i := 1; i < len(configs); i++ {
					vArray = strings.Split(strings.TrimSpace(configs[i]), "=")
					if len(vArray) != 2 {
						continue
					}
					itemName = strings.TrimSpace(vArray[0])
					itemVal = strings.TrimSpace(vArray[1])
					switch itemName {
					case "method":
						method = itemVal
					case "password":
						id = itemVal
					case "tag":
						remarks = itemVal
					case "obfs":
						switch itemVal {
						case "ws":
							net = "ws"
						case "over-tls":
							tls = "tls"
						case "wss":
							net = "ws"
							tls = "tls"
						}
					case "obfs-host":
						host = itemVal
					case "obfs-uri":
						path = itemVal
					case "over-tls":
						if itemVal == "true" {
							tls = "tls"
						} else {
							tls = ""
						}
					case "udp-relay":
						udp = itemVal == "true"
					case "fast-open":
						tfo = itemVal == "true"
					case "tls13":
						tls13 = itemVal == "true"
					case "aead":
						if itemVal == "true" {
							aead = "0"
						} else {
							aead = "1"
						}
					default:
						continue
					}
				}
				if remarks == "" {
					remarks = server + ":" + port
				}
				vmessConstruct(&node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, "", tls, "", &udp, &tfo, &scv, &tls13, "")
			case "trojan": // quantumult x style trojan link
				parts := strings.Split(configs[0], ":")
				if len(parts) < 2 {
					continue
				}
				server = strings.TrimSpace(parts[0])
				port = strings.TrimSpace(parts[1])
				if port == "0" {
					continue
				}

				for i := 1; i < len(configs); i++ {
					vArray = strings.Split(strings.TrimSpace(configs[i]), "=")
					if len(vArray) != 2 {
						continue
					}
					itemName = strings.TrimSpace(vArray[0])
					itemVal = strings.TrimSpace(vArray[1])
					switch itemName {
					case "password":
						password = itemVal
					case "tag":
						remarks = itemVal
					case "over-tls":
						tls = itemVal
					case "tls-host":
						host = itemVal
					case "udp-relay":
						udp = itemVal == "true"
					case "fast-open":
						tfo = itemVal == "true"
					case "tls-verification":
						scv = itemVal != "false"
					case "tls13":
						tls13 = itemVal == "true"
					default:
						continue
					}
				}
				if remarks == "" {
					remarks = server + ":" + port
				}
				trojanConstruct(&node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", tls == "true", &udp, &tfo, &scv, &tls13, "")
			case "http": // quantumult x style http links
				parts := strings.Split(configs[0], ":")
				if len(parts) < 2 {
					continue
				}
				server = strings.TrimSpace(parts[0])
				port = strings.TrimSpace(parts[1])
				if port == "0" {
					continue
				}

				for i := 1; i < len(configs); i++ {
					vArray = strings.Split(strings.TrimSpace(configs[i]), "=")
					if len(vArray) != 2 {
						continue
					}
					itemName = strings.TrimSpace(vArray[0])
					itemVal = strings.TrimSpace(vArray[1])
					switch itemName {
					case "username":
						username = itemVal
					case "password":
						password = itemVal
					case "tag":
						remarks = itemVal
					case "over-tls":
						tls = itemVal
					case "tls-verification":
						scv = itemVal != "false"
					case "tls13":
						tls13 = itemVal == "true"
					case "fast-open":
						tfo = itemVal == "true"
					default:
						continue
					}
				}
				if remarks == "" {
					remarks = server + ":" + port
				}
				if username == "none" {
					username = ""
				}
				if password == "none" {
					password = ""
				}
				httpConstruct(&node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, tls == "true", &tfo, &scv, &tls13, "")
			default:
				continue
			}
		}
		node.Id = index
		*nodes = append(*nodes, node)
		index++
	}
	return index > 0
}
