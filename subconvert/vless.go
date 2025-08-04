/*
 * 项目名称：sing-box_bw
 * 文件名：vless.go
 * 日期：2025/08/02 21:29
 * 作者：Ben
 */

package subconvert

import (
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func explodeVLESS(vless string, node *Proxy) {
	vless = regReplace(vless, `(vless)://`, "vless://", true, true)
	// replace /? with ?
	vless = regReplace(vless, `/\?`, "?", true, false)
	explodeStdVLESS(vless, node)
}

func explodeStdVLESS(vless string, node *Proxy) {
	var add, port, uuid, sni, alpn, fingerprint, remarks, addition, flow, xtls, public_key, short_id string
	var tfo, scv bool
	var decoded, userinfo, hostinfo string
	var userParts []string

	vless = vless[8:]
	var pos int

	if pos = strings.LastIndex(vless, "#"); pos != -1 {
		remarks = urlDecode(vless[pos+1:])
		vless = vless[:pos]
	}

	if pos = strings.LastIndex(vless, "?"); pos != -1 {
		addition = vless[pos+1:]
		vless = vless[:pos]
	}

	if pos = strings.Index(vless, "@"); pos != -1 {
		// 直接从URL中提取UUID
		uuid = vless[:pos]
		hostinfo = vless[pos+1:]
		if regGetMatch(hostinfo, `^(.*?):(\d+)$`, &add, &port) == -1 {
			return
		}
	} else {
		decoded = urlSafeBase64Decode(vless)
		uuid = getUrlArg(addition, "uuid")

		if uuid == "" && strings.Contains(decoded, "@") && strings.Contains(decoded, ":") {
			userinfo = decoded[:strings.Index(decoded, "@")]
			hostinfo = decoded[strings.Index(decoded, "@")+1:]

			if strings.Contains(userinfo, ":") {
				userParts = strings.Split(userinfo, ":")
				if len(userParts) >= 2 {
					uuid = userParts[1]
				}
			} else {
				uuid = userinfo
			}

			if regGetMatch(hostinfo, `^(.*?):(\d+)$`, &add, &port) == -1 {
				return
			}
		} else if regGetMatch(vless, `^(.*?):(\d+)$`, &add, &port) == -1 {
			return
		}
	}

	if uuid == "" {
		return
	}

	if addition != "" {
		sni = getUrlArg(addition, "sni")
		if sni == "" {
			sni = getUrlArg(addition, "peer")
		}
		alpn = getUrlArg(addition, "alpn")
		fingerprint = getUrlArg(addition, "hpkp")
		flow = getUrlArg(addition, "flow")
		xtls = getUrlArg(addition, "xtls")
		public_key = getUrlArg(addition, "pbk")
		short_id = getUrlArg(addition, "sid")
		if tfoArg := getUrlArg(addition, "tfo"); tfoArg != "" {
			tfo, _ = strconv.ParseBool(tfoArg)
		}
		if scvArg := getUrlArg(addition, "insecure"); scvArg != "" {
			scv, _ = strconv.ParseBool(scvArg)
		}

		if remarks == "" {
			remarks = urlDecode(getUrlArg(addition, "remark"))
			if remarks == "" {
				remarks = urlDecode(getUrlArg(addition, "remarks"))
			}
		}
	}

	if remarks == "" {
		remarks = add + ":" + port
	}

	vlessConstruct(node, VLESS_DEFAULT_GROUP, remarks, add, port, uuid, sni, alpn, fingerprint, flow, xtls, public_key, short_id, &tfo, &scv, "")
}

func ToVLESS(proxy Proxy, pc *ProxyConfig) (ob option.Outbound) {
	pe := "xudp"
	oo := &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     proxy.Hostname,
			ServerPort: proxy.Port,
		},
		UUID:           proxy.UUID,
		PacketEncoding: &pe,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: proxy.ServerName,
				UTLS:       &option.OutboundUTLSOptions{},
				Reality:    &option.OutboundRealityOptions{},
			},
		},
	}
	oo.RoutingMark = option.FwMark(pc.RoutingMark)
	if proxy.XTLS == 2 {
		oo.Flow = "xtls-rprx-vision"
	} else {
		oo.Flow = proxy.Flow
	}
	if proxy.PublicKey != "" && proxy.ShortID != "" {
		var fp = []string{"chrome", "firefox", "safari", "ios", "edge", "qq"}
		oo.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: proxy.ServerName,
				ALPN:       proxy.Alpn,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: fp[rand.IntN(len(fp))],
				},
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					ShortID:   proxy.ShortID,
					PublicKey: proxy.PublicKey,
				},
			},
		}
	}
	ob.Type = constant.TypeVLESS
	ob.Tag = proxy.Remark
	ob.Title = pc.Title
	ob.Options = oo
	return
}
