/*
 * 项目名称：sing-box_bw
 * 文件名：v2ray.go
 * 日期：2025/08/03 02:21
 * 作者：Ben
 */

package subconvert

import (
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func v2rayTransport(proxy Proxy) (ot option.V2RayTransportOptions) {
	switch proxy.TransferProtocol {
	case "http":
		if proxy.Host != "" {
			ot.HTTPOptions.Host = []string{proxy.Hostname}
		}
		fallthrough
	case "ws":
		ot.Type = proxy.TransferProtocol
		if proxy.Path == "" {
			ot.WebsocketOptions.Path = "/"
		} else {
			ot.WebsocketOptions.Path = proxy.Path
		}
		headers := make(badoption.HTTPHeader)
		if proxy.Host != "" {
			headers["Host"] = []string{proxy.Host}
		}
		if proxy.Edge != "" {
			headers["Edge"] = []string{proxy.Edge}
		}
		ot.WebsocketOptions.Headers = headers
	case "grpc":
		ot.Type = constant.V2RayTransportTypeGRPC
		if proxy.Path != "" {
			ot.GRPCOptions.ServiceName = proxy.Path
		}
	default:
		// Do nothing
	}
	return
}
