/*
 * 项目名称：sing-box_bw
 * 文件名：clash.go
 * 日期：2025/08/06 21:45
 * 作者：Ben
 */

package adapter

import (
	"context"
)

type SelectorGroupContext struct {
	Tag string
}

type selectorContextKey struct{}

func WithContextSelector(ctx context.Context, selectorContext *SelectorGroupContext) context.Context {
	return context.WithValue(ctx, (*selectorContextKey)(nil), selectorContext)
}

func ContextFromSelector(ctx context.Context) *SelectorGroupContext {
	metadata := ctx.Value((*selectorContextKey)(nil))
	if metadata == nil {
		return nil
	}
	return metadata.(*SelectorGroupContext)
}
