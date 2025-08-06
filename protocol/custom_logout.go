/*
 * 项目名称：sing-box_bw
 * 文件名：custom_logout.go
 * 日期：2025/08/06 22:29
 * 作者：Ben
 */

package protocol

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func CustomOutboundLogOut(l log.ContextLogger, ctx context.Context, inbound *adapter.InboundContext, outboundType, logContent string, checkUrlTest bool) {
	if checkUrlTest && !(inbound.Destination.Fqdn == "" && inbound.Domain != "") { // urltest
		return
	}
	if ll, ok := l.(log.LogTag); ok {
		if selector := adapter.ContextFromSelector(ctx); selector != nil {
			if selector.Tag != "" {
				ll.LogWithTag(ctx, log.LevelInfo, "outbound/"+outboundType+"["+selector.Tag+"]", logContent+" -> "+inbound.Domain+"("+inbound.Destination.String()+")")
			}
			return
		}
	}
	l.InfoContext(ctx, logContent+" -> "+inbound.Domain+"("+inbound.Destination.String()+")")
}
