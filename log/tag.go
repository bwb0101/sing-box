/*
 * 项目名称：sing-box_bw
 * 文件名：tag.go
 * 日期：2025/08/06 22:22
 * 作者：Ben
 */

package log

import (
	"context"
	"os"
	"time"

	F "github.com/sagernet/sing/common/format"
)

type (
	LogTag interface {
		LogWithTag(ctx context.Context, level Level, myTag string, args ...any)
	}
)

func (l *observableLogger) LogWithTag(ctx context.Context, level Level, myTag string, args ...any) {
	level = OverrideLevelFromContext(level, ctx)
	if level > l.level {
		return
	}
	nowTime := time.Now()
	if l.needObservable {
		message, messageSimple := l.formatter.FormatWithSimple(ctx, level, myTag, F.ToString(args...), nowTime)
		if level == LevelPanic {
			panic(message)
		}
		_, _ = l.writer.Write([]byte(message))
		if level == LevelFatal {
			os.Exit(1)
		}
		l.subscriber.Emit(Entry{level, messageSimple})
	} else {
		message := l.formatter.Format(ctx, level, myTag, F.ToString(args...), nowTime)
		if level == LevelPanic {
			panic(message)
		}
		_, _ = l.writer.Write([]byte(message))
		if level == LevelFatal {
			os.Exit(1)
		}
	}
	if l.platformWriter != nil {
		l.platformWriter.WriteMessage(level, l.platformFormatter.Format(ctx, level, myTag, F.ToString(args...), nowTime))
	}
}
