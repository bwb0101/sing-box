/*
 * 项目名称：sing-box_bw
 * 文件名：subparser.go
 * 日期：2025/08/02 14:07
 * 作者：Ben
 */

package subconvert

import (
	"encoding/base64"
	"log"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfType 枚举定义
type ConfType int

const (
	Unknow ConfType = iota
	SS
	SSR
	V2Ray
	SSConf
	SSTap
	Netch
	SOCKS
	HTTP_
	SUB
	Local
)

var (
	ssCiphers = []string{"rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "bf-cfb",
		"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "salsa20", "chacha20", "chacha20-ietf", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305", "2022-blake3-chacha8-poly1305"}
	ssrCiphers = []string{"none", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb",
		"idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"}
)

func commonConstruct(node *Proxy, proxyType ProxyType, group, remarks, server, port string, udp, tfo, scv, tls13 *bool, underlyingProxy string) {
	node.Type = proxyType
	node.Group = group
	node.Remark = remarks
	node.Hostname = server
	node.UnderlyingProxy = underlyingProxy
	v, _ := strconv.ParseUint(port, 10, 32)
	node.Port = uint16(v)
	node.UDP = udp
	node.TCPFastOpen = tfo
	node.AllowInsecure = scv
	node.TLS13 = tls13
}

func ssrConstruct(node *Proxy, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam string, udp, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, ShadowsocksR, group, remarks, server, port, udp, tfo, scv, nil, underlyingProxy)
	node.Password = password
	node.EncryptMethod = method
	node.Protocol = protocol
	node.ProtocolParam = protoparam
	node.OBFS = obfs
	node.OBFSParam = obfsparam
}

func ssConstruct(node *Proxy, group, remarks, server, port, password, method, plugin, pluginopts string, udp, tfo, scv, tls13 *bool, underlyingProxy string) {
	commonConstruct(node, Shadowsocks, group, remarks, server, port, udp, tfo, scv, tls13, underlyingProxy)
	node.Password = password
	node.EncryptMethod = method
	node.Plugin = plugin
	node.PluginOption = pluginopts
}

func vmessConstruct(node *Proxy, group, remarks, add, port, typeName, id, aid, net, cipher, path, host, edge, tls, sni string, udp, tfo, scv, tls13 *bool, underlyingProxy string) {
	commonConstruct(node, VMess, group, remarks, add, port, udp, tfo, scv, tls13, underlyingProxy)
	if id == "" {
		node.UserId = "00000000-0000-0000-0000-000000000000"
	} else {
		node.UserId = id
	}
	v, _ := strconv.Atoi(aid)
	node.AlterId = uint16(v)
	node.EncryptMethod = cipher
	if net == "" {
		node.TransferProtocol = "tcp"
	} else {
		node.TransferProtocol = net
	}
	node.Edge = edge
	node.ServerName = sni

	if net == "quic" {
		node.QUICSecure = host
		node.QUICSecret = path
	} else {
		if host == "" && !isIPv4(add) && !isIPv6(add) {
			node.Host = add
		} else {
			node.Host = strings.TrimSpace(host)
		}
		if path == "" {
			node.Path = "/"
		} else {
			node.Path = strings.TrimSpace(path)
		}
	}
	node.FakeType = typeName
	node.TLSSecure = tls == "tls"
}

func vlessConstruct(node *Proxy, group, remarks, server, port, uuid, sni, alpn, fingerprint, flow, xtls, public_key, short_id string, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, VLESS, group, remarks, server, port, nil, tfo, scv, nil, underlyingProxy)
	node.UUID = uuid
	node.SNI = sni
	if alpn != "" {
		node.Alpn = []string{alpn}
	}
	node.Fingerprint = fingerprint
	node.Flow = flow
	node.XTLS = toInt(xtls, 0)
	node.PublicKey = public_key
	node.ShortID = short_id
}

func socksConstruct(node *Proxy, group, remarks, server, port, username, password string, udp, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, SOCKS5, group, remarks, server, port, udp, tfo, scv, nil, underlyingProxy)
	node.Username = username
	node.Password = password
}

func httpConstruct(node *Proxy, group, remarks, server, port, username, password string, tls bool, tfo, scv, tls13 *bool, underlyingProxy string) {
	proxyType := HTTP
	if tls {
		proxyType = HTTPS
	}
	commonConstruct(node, proxyType, group, remarks, server, port, nil, tfo, scv, tls13, underlyingProxy)
	node.Username = username
	node.Password = password
	node.TLSSecure = tls
}

func trojanConstruct(node *Proxy, group, remarks, server, port, password, network, host, path string, tlssecure bool, udp, tfo, scv, tls13 *bool, underlyingProxy string) {
	commonConstruct(node, Trojan, group, remarks, server, port, udp, tfo, scv, tls13, underlyingProxy)
	node.Password = password
	node.Host = host
	node.TLSSecure = tlssecure
	if network == "" {
		node.TransferProtocol = "tcp"
	} else {
		node.TransferProtocol = network
	}
	node.Path = path
}

func snellConstruct(node *Proxy, group, remarks, server, port, password, obfs, host string, version uint16, udp, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, Snell, group, remarks, server, port, udp, tfo, scv, nil, underlyingProxy)
	node.Password = password
	node.OBFS = obfs
	node.Host = host
	node.SnellVersion = version
}

func wireguardConstruct(node *Proxy, group, remarks, server, port, selfIp, selfIpv6, privKey, pubKey, psk string, dns []string, mtu, keepalive, testUrl, clientId string, udp *bool, underlyingProxy string) {
	commonConstruct(node, WireGuard, group, remarks, server, port, udp, nil, nil, nil, underlyingProxy)
	node.SelfIP = selfIp
	node.SelfIPv6 = selfIpv6
	node.PrivateKey = privKey
	node.PublicKey = pubKey
	node.PreSharedKey = psk
	node.DnsServers = dns
	if v, err := strconv.Atoi(mtu); err == nil {
		node.Mtu = uint16(v)
	}
	if v, err := strconv.Atoi(keepalive); err == nil {
		node.KeepAlive = uint16(v)
	}
	node.TestUrl = testUrl
	node.ClientId = clientId
}

func hysteriaConstruct(node *Proxy, group, remarks, server, port, ports, protocol, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, obfs, sni, fingerprint, ca, ca_str, recv_window_conn, recv_window string, disable_mtu_discovery *bool,
	hop_interval, alpn string, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, Hysteria, group, remarks, server, port, nil, tfo, scv, nil, underlyingProxy)
	node.Ports = ports
	node.Protocol = protocol
	node.OBFSParam = obfs_protocol
	if up != "" {
		if len(up) > 4 && up[len(up)-3:] == "bps" {
			node.Up = up
		} else if toInt(up, 0) != 0 {
			node.UpSpeed = toInt(up, 0)
			node.Up = up + " Mbps"
		}
	}
	if up_speed != "" {
		node.UpSpeed = toInt(up_speed, 0)
	}
	if down != "" {
		if len(down) > 4 && down[len(down)-3:] == "bps" {
			node.Down = down
		} else if toInt(down, 0) != 0 {
			node.DownSpeed = toInt(down, 0)
			node.Down = down + " Mbps"
		}
	}
	if down_speed != "" {
		node.DownSpeed = toInt(down_speed, 0)
	}
	node.AuthStr = auth_str
	if auth != "" {
		if dstr, err := base64.StdEncoding.DecodeString("SGVsbG8sIFdvcmxkIQ=="); err != nil {
			log.Fatalln(err)
		} else {
			node.AuthStr = string(dstr)
		}
	}
	node.OBFS = obfs
	node.SNI = sni
	node.Fingerprint = fingerprint
	node.Ca = ca
	node.CaStr = ca_str
	node.RecvWindowConn = toInt(recv_window_conn, 0)
	node.RecvWindow = toInt(recv_window, 0)
	node.DisableMtuDiscovery = disable_mtu_discovery
	node.HopInterval = toInt(hop_interval, 0)
	if alpn != "" {
		node.Alpn = []string{alpn}
	}
}

func hysteria2Construct(node *Proxy, group, remarks, server, port, ports, up, down, password, obfs, obfs_password, sni, fingerprint, alpn, ca, ca_str, cwnd, hop_interval string, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, Hysteria2, group, remarks, server, port, nil, tfo, scv, nil, underlyingProxy)
	node.UpSpeed = toInt(up, 0)
	node.DownSpeed = toInt(down, 0)
	node.Ports = ports
	node.Password = password
	node.OBFS = obfs
	node.OBFSParam = obfs_password
	node.SNI = sni
	node.Fingerprint = fingerprint
	if alpn != "" {
		node.Alpn = []string{alpn}
	}
	node.Ca = ca
	node.CaStr = ca_str
	node.CWND = toInt(cwnd, 0)
	node.HopInterval = toInt(hop_interval, 0)
}

func tuicConstruct(node *Proxy, group, remarks, server, port, uuid, password, ip, heartbeat_interval, alpn string, disable_sni, reduce_rtt *bool, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams,
	sni string, fast_open, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, TUIC, group, remarks, server, port, nil, tfo, scv, nil, underlyingProxy)
	node.Password = password
	node.UUID = uuid
	node.IP = ip
	node.HeartbeatInterval = heartbeat_interval
	if alpn != "" {
		node.Alpn = []string{alpn}
	}
	node.DisableSNI = disable_sni
	node.ReduceRTT = reduce_rtt
	node.RequestTimeout = toInt(request_timeout, 0)
	node.UdpRelayMode = udp_relay_mode
	node.CongestionController = congestion_controller
	node.MaxUdpRelayPacketSize = toInt(max_udp_relay_packet_size, 0)
	node.MaxOpenStreams = toInt(max_open_streams, 0)
	node.SNI = sni
	node.FastOpen = fast_open
}

func anytlsConstruct(node *Proxy, group, remarks, server, port, password, sni, alpn, fingerprint, idleSessionCheckInterval, idleSessionTimeout, minIdleSession string, tfo, scv *bool, underlyingProxy string) {
	commonConstruct(node, AnyTLS, group, remarks, server, port, nil, tfo, scv, nil, underlyingProxy)
	node.Password = password
	node.SNI = sni
	if alpn != "" {
		node.Alpn = []string{alpn}
	}
	node.Fingerprint = fingerprint
	node.IdleSessionCheckInterval = toInt(idleSessionCheckInterval, 0)
	node.IdleSessionTimeout = toInt(idleSessionTimeout, 0)
	node.MinIdleSession = toInt(minIdleSession, 0)
}

func ExplodeConfContent(content string, nodes *[]Proxy) bool {
	filetype := Unknow

	if strings.Contains(content, "\"version\"") {
		filetype = SS
	} else if strings.Contains(content, "\"serverSubscribes\"") {
		filetype = SSR
	} else if strings.Contains(content, "\"uiItem\"") || strings.Contains(content, "vnext") {
		filetype = V2Ray
	} else if strings.Contains(content, "\"proxy_apps\"") {
		filetype = SSConf
	} else if strings.Contains(content, "\"idInUse\"") {
		filetype = SSTap
	} else if strings.Contains(content, "\"local_address\"") && strings.Contains(content, "\"local_port\"") {
		filetype = SSR // use ssr config parser
	} else if strings.Contains(content, "\"ModeFileNameType\"") {
		filetype = Netch
	}

	switch filetype {
	case SS:
		explodeSSConf(content, nodes)
	case SSR:
		explodeSSRConf(content, nodes)
	case V2Ray:
		explodeVmessConf(content, nodes)
	case SSConf:
		// explodeSSAndroid(content, nodes)
	case SSTap:
		// explodeSSTap(content, nodes)
	case Netch:
		// explodeNetchConf(content, nodes)
	default:
		// try to parse as a local subscription
		explodeSub(content, nodes)
	}
	return len(*nodes) > 0
}

func explodeSub(sub string, nodes *[]Proxy) {
	var strLink string
	processed := false

	// 尝试解析为 SSD 配置
	if strings.HasPrefix(sub, "ssd://") {
		explodeSSD(sub, nodes)
		processed = true
	}

	// 尝试解析为 clash 配置
	if !processed && regFind(sub, `"?Proxy|proxies"?:`) {
		// 提取 Proxy/Proxies 部分
		// 注意：原始代码中的正则表达式可能存在语法问题，这里做了简化处理
		regGetMatch(sub, `(?m)^(?:Proxy|proxies):\s(?:(?:^\ +?.*$|^\ *?-.*$)\s?)+`, &sub)

		var yamlnode map[string]any
		err := yaml.Unmarshal([]byte(sub), &yamlnode)
		if err != nil {
			log.Fatalln(err)
		}
		if yamlnode != nil && (yamlnode["Proxy"] != nil || yamlnode["proxies"] != nil) {
			explodeClash(yamlnode, nodes)
			processed = true
		}
	}

	// 尝试解析为 surge 配置
	if !processed && explodeSurge(sub, nodes) {
		processed = true
	}

	// 尝试解析为普通订阅
	if !processed {
		sub = urlSafeBase64Decode(sub)
		if regFind(sub, `(vmess|shadowsocks|http|trojan)\s*?=`) {
			if explodeSurge(sub, nodes) {
				return
			}
		}

		// 确定分隔符
		delimiter := "\n"
		if strings.Count(sub, "\n") < 1 {
			if strings.Count(sub, "\r") < 1 {
				delimiter = " " // 没有换行符，使用空格作为分隔符
			} else {
				delimiter = "\r"
			}
		}

		// 按分隔符分割并处理每个链接
		lines := strings.Split(sub, delimiter)
		for _, strLink = range lines {
			// 移除行尾的回车符
			if strings.HasSuffix(strLink, "\r") {
				strLink = strLink[:len(strLink)-1]
			}
			var node Proxy
			explode(strLink, &node)
			if strLink != "" && node.Type != Unknown {
				*nodes = append(*nodes, node)
			}
		}
	}
}

func explode(link string, node *Proxy) {
	if strings.HasPrefix(link, "ssr://") {
		explodeSSR(link, node)
	} else if strings.HasPrefix(link, "vmess://") || strings.HasPrefix(link, "vmess1://") {
		explodeVmess(link, node)
	} else if strings.HasPrefix(link, "ss://") {
		explodeSS(link, node)
	} else if strings.HasPrefix(link, "socks://") || strings.HasPrefix(link, "https://t.me/socks") || strings.HasPrefix(link, "tg://socks") {
		explodeSocks(link, node)
	} else if strings.HasPrefix(link, "https://t.me/http") || strings.HasPrefix(link, "tg://http") { // telegram style http link
		// explodeHTTP(link, node)
	} else if strings.HasPrefix(link, "Netch://") {
		// explodeNetch(link, node)
	} else if strings.HasPrefix(link, "trojan://") {
		explodeTrojan(link, node)
	} else if strings.Contains(link, "hysteria2://") || strings.Contains(link, "hy2://") {
		// explodeHysteria2(link, node)
	} else if strings.Contains(link, "tuic://") {
		// explodeTUIC(link, node)
	} else if strings.Contains(link, "anytls://") {
		// explodeAnyTLS(link, node)
	} else if strings.Contains(link, "vless://") {
		explodeVLESS(link, node)
	} else if isLink(link) {
		// explodeHTTPSub(link, node)
	}
}
