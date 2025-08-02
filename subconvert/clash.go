/*
 * 项目名称：sing-box_bw
 * 文件名：clash.go
 * 日期：2025/08/02 18:25
 * 作者：Ben
 */

package subconvert

import (
	"strconv"
	"strings"
)

func explodeClash(yamlnode map[string]any, nodes *[]Proxy) {
	var (
		proxytype, ps, server, port, cipher, group, password, underlyingProxy string // common
		id, aid, net, path, host, edge, tls, sni                              string // vmess
		plugin, pluginopts, pluginoptsMode, pluginoptsHost, pluginoptsMux     string // ss
		protocol, protoparam, obfs, obfsparam                                 string // ssr
		user                                                                  string // socks
		ip, ipv6, privateKey, publicKey, mtu                                  string // wireguard
		ports, obfsProtocol, up, upSpeed, down, downSpeed, auth, authStr      string // hysteria
		fingerprint, ca, caStr, recvWindowConn, recvWindow                    string
		hopInterval, alpn                                                     string
		obfsPassword, cwnd                                                    string // hysteria2
		uuid, heartbeatInterval, requestTimeout                               string // TUIC
		disableSni, reduceRtt                                                 *bool
		udpRelayMode, congestionController                                    string
		maxUdpRelayPacketSize, maxOpenStreams                                 string
		idleSessionCheckInterval, idleSessionTimeout, minIdleSession          string
		flow, xtls, shortId                                                   string
		dnsServer                                                             []string
		disableMtuDiscovery, fastOpen, udp, tfo, scv                          *bool
	)

	aid = "0"
	net = "tcp"

	index := uint32(len(*nodes))
	section := "Proxy"
	if _, ok := yamlnode["proxies"]; ok {
		section = "proxies"
	}

	proxies, ok := yamlnode[section].([]any)
	if !ok {
		return
	}

	for _, item := range proxies {
		singleproxy, ok := item.(map[string]any)
		if !ok {
			continue
		}

		var node Proxy
		// Extract common fields
		getMember(singleproxy, "type", &proxytype)
		getMember(singleproxy, "name", &ps)
		getMember(singleproxy, "server", &server)
		getMember(singleproxy, "port", &port)
		getMember(singleproxy, "underlying-proxy", &underlyingProxy)
		if port == "" || port == "0" {
			continue
		}
		udp = getMapBoolStr(singleproxy, "udp")
		tfo = getMapBoolStr(singleproxy, "fast-open")
		scv = getMapBoolStr(singleproxy, "skip-cert-verify")

		switch proxytype {
		case "vmess":
			group = V2RAY_DEFAULT_GROUP

			getMember(singleproxy, "uuid", &id)
			getMember(singleproxy, "alterId", &aid)
			getMember(singleproxy, "cipher", &cipher)
			getMember(singleproxy, "network", &net)
			getMember(singleproxy, "servername", &sni)

			switch net {
			case "http":
				if opts, ok := singleproxy["http-opts"].(map[string]any); ok {
					if paths, ok := opts["path"].([]any); ok && len(paths) > 0 {
						path, _ = paths[0].(string)
					}
					if headers, ok := opts["headers"].(map[string]any); ok {
						if hosts, ok := headers["Host"].([]any); ok && len(hosts) > 0 {
							host, _ = hosts[0].(string)
						}
					}
				}
				edge = ""
			case "ws":
				if wsOpts, ok := singleproxy["ws-opts"].(map[string]any); ok {
					if getMember(wsOpts, "path", &path); path == "" {
						path = "/"
					}
					if headers, ok := wsOpts["headers"].(map[string]any); ok {
						getMember(headers, "Host", &host)
						getMember(headers, "Edge", &edge)
					}
				} else {
					if getMember(singleproxy, "ws-path", &path); path == "" {
						path = "/"
					}
					if headers, ok := singleproxy["ws-headers"].(map[string]any); ok {
						getMember(headers, "Host", &host)
						getMember(headers, "Edge", &edge)
					}
				}
			case "h2":
				if h2Opts, ok := singleproxy["h2-opts"].(map[string]any); ok {
					getMember(h2Opts, "path", &path)
					if hosts, ok := h2Opts["host"].([]any); ok && len(hosts) > 0 {
						host, _ = hosts[0].(string)
					}
				}
				edge = ""
			case "grpc":
				getMember(singleproxy, "servername", &host)
				if grpcOpts, ok := singleproxy["grpc-opts"].(map[string]any); ok {
					getMember(grpcOpts, "grpc-service-name", &path)
				}
				edge = ""
			}

			if val, ok := singleproxy["tls"]; ok {
				if tlsBool, ok := val.(bool); ok && tlsBool {
					tls = "tls"
				} else if tlsStr, ok := val.(string); ok && tlsStr == "true" {
					tls = "tls"
				}
			}

			vmessConstruct(&node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, udp, tfo, scv, nil, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "vless":
			group = VLESS_DEFAULT_GROUP

			getMember(singleproxy, "uuid", &uuid)
			getMember(singleproxy, "servername", &sni)
			if alpnVal, ok := singleproxy["alpn"]; ok {
				if alpnArr, ok := alpnVal.([]any); ok && len(alpnArr) > 0 {
					alpn, _ = alpnArr[0].(string)
				} else if alpnStr, ok := alpnVal.(string); ok {
					alpn = alpnStr
				}
			}
			getMember(singleproxy, "fingerprint", &fingerprint)
			getMember(singleproxy, "flow", &flow)
			if realityOpts, ok := singleproxy["reality-opts"].(map[string]any); ok {
				getMember(realityOpts, "public-key", &publicKey)
				getMember(realityOpts, "short-id", &shortId)
			}

			vlessConstruct(&node, group, ps, server, port, uuid, sni, alpn, fingerprint, flow, xtls, publicKey, shortId, tfo, scv, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "ss":
			group = SS_DEFAULT_GROUP

			getMember(singleproxy, "cipher", &cipher)
			getMember(singleproxy, "password", &password)
			if pluginVal, ok := singleproxy["plugin"]; ok {
				pluginStr, _ := pluginVal.(string)
				switch pluginStr {
				case "obfs":
					plugin = "obfs-local"
					if pluginOpts, ok := singleproxy["plugin-opts"].(map[string]any); ok {
						getMember(pluginOpts, "mode", &pluginoptsMode)
						getMember(pluginOpts, "host", &pluginoptsHost)
					}
				case "v2ray-plugin":
					plugin = "v2ray-plugin"
					if pluginOpts, ok := singleproxy["plugin-opts"].(map[string]any); ok {
						getMember(pluginOpts, "mode", &pluginoptsMode)
						getMember(pluginOpts, "host", &pluginoptsHost)
						getMember(pluginOpts, "tls", &tls)
						getMember(pluginOpts, "path", &path)
						if val, ok := pluginOpts["mux"]; ok {
							if muxBool, ok := val.(bool); ok && muxBool {
								pluginoptsMux = "mux=4;"
							}
						}
					}
				}
			} else if obfsVal, ok := singleproxy["obfs"]; ok {
				plugin = "obfs-local"
				pluginoptsMode, _ = obfsVal.(string)
				getMember(singleproxy, "obfs-host", &pluginoptsHost)
			} else {
				plugin = ""
			}

			switch plugin {
			case "simple-obfs", "obfs-local":
				pluginopts = "obfs=" + pluginoptsMode
				if pluginoptsHost != "" {
					pluginopts += ";obfs-host=" + pluginoptsHost
				}
			case "v2ray-plugin":
				pluginopts = "mode=" + pluginoptsMode + ";" + tls + pluginoptsMux
				if pluginoptsHost != "" {
					pluginopts += "host=" + pluginoptsHost + ";"
				}
				if path != "" {
					pluginopts += "path=" + path + ";"
				}
				if pluginoptsMux != "" {
					pluginopts += "mux=" + pluginoptsMux + ";"
				}
			}

			// support for go-shadowsocks2
			if cipher == "AEAD_CHACHA20_POLY1305" {
				cipher = "chacha20-ietf-poly1305"
			} else if strings.Contains(cipher, "AEAD") {
				cipher = strings.ReplaceAll(cipher, "AEAD_", "")
				cipher = strings.ReplaceAll(cipher, "_", "-")
				cipher = strings.ToLower(cipher)
			}

			ssConstruct(&node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv, nil, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "socks5":
			group = SOCKS_DEFAULT_GROUP
			getMember(singleproxy, "username", &user)
			getMember(singleproxy, "password", &password)

			socksConstruct(&node, group, ps, server, port, user, password, nil, nil, nil, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "ssr":
			group = SSR_DEFAULT_GROUP
			if getMember(singleproxy, "cipher", &cipher); cipher == "dummy" {
				cipher = "none"
			}
			getMember(singleproxy, "password", &password)
			getMember(singleproxy, "protocol", &protocol)
			getMember(singleproxy, "obfs", &obfs)
			if getMember(singleproxy, "protocol-param", &protoparam); protoparam != "" {
				getMember(singleproxy, "protocolparam", &protoparam)
			}
			if getMember(singleproxy, "obfs-param", &obfsparam); obfsparam != "" {
				getMember(singleproxy, "obfsparam", &obfsparam)
			}

			ssrConstruct(&node, group, ps, server, port, protocol, cipher, obfs, password, obfsparam, protoparam, udp, tfo, scv, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "http":
			group = HTTP_DEFAULT_GROUP
			getMember(singleproxy, "username", &user)
			getMember(singleproxy, "password", &password)
			getMember(singleproxy, "tls", &tls)

			httpConstruct(&node, group, ps, server, port, user, password, tls == "true", tfo, scv, nil, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "trojan":
			group = TROJAN_DEFAULT_GROUP
			getMember(singleproxy, "password", &password)
			getMember(singleproxy, "sni", &host)
			getMember(singleproxy, "network", &net)

			switch net {
			case "grpc":
				if grpcOpts, ok := singleproxy["grpc-opts"].(map[string]any); ok {
					getMember(grpcOpts, "grpc-service-name", &path)
				}
			case "ws":
				if wsOpts, ok := singleproxy["ws-opts"].(map[string]any); ok {
					getMember(wsOpts, "path", &path)
				}
			default:
				net = "tcp"
				path = ""
			}

			trojanConstruct(&node, group, ps, server, port, password, net, host, path, true, udp, tfo, scv, nil, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "snell":
			group = SNELL_DEFAULT_GROUP
			getMember(singleproxy, "psk", &password)
			getMember(singleproxy, "version", &aid)

			if obfsOpts, ok := singleproxy["obfs-opts"].(map[string]any); ok {
				getMember(obfsOpts, "mode", &obfs)
				getMember(obfsOpts, "host", &host)
			}

			aidInt, _ := strconv.Atoi(aid)
			snellConstruct(&node, group, ps, server, port, password, obfs, host, uint16(aidInt), udp, tfo, scv, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "wireguard":
			group = WG_DEFAULT_GROUP
			getMember(singleproxy, "public-key", &publicKey)
			getMember(singleproxy, "private-key", &privateKey)
			if val, ok := singleproxy["dns"]; ok {
				if dnsArr, ok := val.([]any); ok {
					for _, d := range dnsArr {
						if dnsStr, ok := d.(string); ok {
							dnsServer = append(dnsServer, dnsStr)
						}
					}
				}
			}
			getMember(singleproxy, "mtu", &mtu)
			getMember(singleproxy, "preshared-key", &password)
			getMember(singleproxy, "ip", &ip)
			getMember(singleproxy, "ipv6", &ipv6)

			wireguardConstruct(&node, group, ps, server, port, ip, ipv6, privateKey, publicKey, password, dnsServer, mtu, "0", "", "", udp, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "hysteria":
			group = HYSTERIA_DEFAULT_GROUP

			getMember(singleproxy, "ports", &ports)
			getMember(singleproxy, "protocol", &protocol)
			getMember(singleproxy, "obfs-protocol", &obfsProtocol)
			getMember(singleproxy, "up", &up)
			getMember(singleproxy, "up-speed", &upSpeed)
			getMember(singleproxy, "down", &down)
			getMember(singleproxy, "down-speed", &downSpeed)
			getMember(singleproxy, "auth", &auth)
			getMember(singleproxy, "auth-str", &authStr)
			if authStr == "" {
				getMember(singleproxy, "auth_str", &authStr)
			}
			getMember(singleproxy, "obfs", &obfs)
			getMember(singleproxy, "sni", &sni)
			getMember(singleproxy, "fingerprint", &fingerprint)
			if alpnVal, ok := singleproxy["alpn"]; ok {
				if alpnArr, ok := alpnVal.([]any); ok && len(alpnArr) > 0 {
					alpn, _ = alpnArr[0].(string)
				} else if alpnStr, ok := alpnVal.(string); ok {
					alpn = alpnStr
				}
			}
			getMember(singleproxy, "ca", &ca)
			getMember(singleproxy, "ca-str", &caStr)
			getMember(singleproxy, "recv-window-conn", &recvWindowConn)
			getMember(singleproxy, "recv-window", &recvWindow)
			disableMtuDiscovery = getMapBoolStr(singleproxy, "disable-mtu-discovery")
			if disableMtuDiscovery == nil {
				disableMtuDiscovery = getMapBoolStr(singleproxy, "disable_mtu_discovery")
			}
			getMember(singleproxy, "hop-interval", &hopInterval)

			hysteriaConstruct(&node, group, ps, server, port, ports, protocol, obfsProtocol, up, upSpeed, down, downSpeed, auth, authStr, obfs, sni, fingerprint, ca, caStr, recvWindowConn, recvWindow, disableMtuDiscovery, hopInterval, alpn, tfo,
				scv,
				underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "hysteria2":
			group = HYSTERIA2_DEFAULT_GROUP
			getMember(singleproxy, "ports", &ports)
			getMember(singleproxy, "up", &up)
			getMember(singleproxy, "down", &down)
			getMember(singleproxy, "password", &password)
			if password == "" {
				getMember(singleproxy, "auth", &password)
			}
			getMember(singleproxy, "obfs", &obfs)
			getMember(singleproxy, "obfs-password", &obfsPassword)
			getMember(singleproxy, "sni", &sni)
			getMember(singleproxy, "fingerprint", &fingerprint)
			if alpnVal, ok := singleproxy["alpn"]; ok {
				if alpnArr, ok := alpnVal.([]any); ok && len(alpnArr) > 0 {
					alpn, _ = alpnArr[0].(string)
				} else if alpnStr, ok := alpnVal.(string); ok {
					alpn = alpnStr
				}
			}
			getMember(singleproxy, "ca", &ca)
			getMember(singleproxy, "ca-str", &caStr)
			getMember(singleproxy, "cwnd", &cwnd)
			getMember(singleproxy, "hop-interval", &hopInterval)

			hysteria2Construct(&node, group, ps, server, port, ports, up, down, password, obfs, obfsPassword, sni, fingerprint, alpn, ca, caStr, cwnd, hopInterval, tfo, scv, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "tuic":
			group = TUIC_DEFAULT_GROUP
			getMember(singleproxy, "uuid", &uuid)
			getMember(singleproxy, "ip", &ip)
			getMember(singleproxy, "password", &password)
			getMember(singleproxy, "heartbeat-interval", &heartbeatInterval)
			if alpnVal, ok := singleproxy["alpn"]; ok {
				if alpnArr, ok := alpnVal.([]any); ok && len(alpnArr) > 0 {
					alpn, _ = alpnArr[0].(string)
				} else if alpnStr, ok := alpnVal.(string); ok {
					alpn = alpnStr
				}
			}
			disableSni = getMapBoolStr(singleproxy, "disable-sni")
			reduceRtt = getMapBoolStr(singleproxy, "reduce-rtt")
			getMember(singleproxy, "request-timeout", &requestTimeout)
			getMember(singleproxy, "udp-relay-mode", &udpRelayMode)
			getMember(singleproxy, "congestion-controller", &congestionController)
			getMember(singleproxy, "max-udp-relay-packet-size", &maxUdpRelayPacketSize)
			getMember(singleproxy, "max-open-streams", &maxOpenStreams)
			fastOpen = getMapBoolStr(singleproxy, "fast-open")

			tuicConstruct(&node, group, ps, server, port, uuid, password, ip, heartbeatInterval, alpn, disableSni, reduceRtt, requestTimeout, udpRelayMode, congestionController, maxUdpRelayPacketSize, maxOpenStreams, sni, fastOpen, tfo, scv,
				underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		case "anytls":
			group = ANYTLS_DEFAULT_GROUP
			getMember(singleproxy, "password", &password)
			getMember(singleproxy, "sni", &sni)
			if alpnVal, ok := singleproxy["alpn"]; ok {
				if alpnArr, ok := alpnVal.([]any); ok && len(alpnArr) > 0 {
					alpn, _ = alpnArr[0].(string)
				} else if alpnStr, ok := alpnVal.(string); ok {
					alpn = alpnStr
				}
			}
			getMember(singleproxy, "fingerprint", &fingerprint)

			anytlsConstruct(&node, group, ps, server, port, password, sni, alpn, fingerprint, idleSessionCheckInterval, idleSessionTimeout, minIdleSession, tfo, scv, underlyingProxy)
			node.Id = index
			*nodes = append(*nodes, node)
			index++
		default:
			continue
		}
	}
}
