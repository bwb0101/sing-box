/*
 * 项目名称：sing-box_bw
 * 文件名：utils.go
 * 日期：2025/08/02 20:40
 * 作者：Ben
 */

package subconvert

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func getMember(j map[string]any, key string, value *string) {
	if s, ok := j[key]; ok {
		if r, ok := s.(string); ok {
			*value = r
		}
	}
}

func replaceAllDistinct(str, oldValue, newValue string) string {
	return strings.ReplaceAll(str, oldValue, newValue)
}

func regGetMatch(src, match string, targets ...*string) int {
	// 调用 regGetAllMatch 获取所有匹配组
	result := regGetAllMatch(src, match, false)

	// 检查是否有匹配结果
	if len(result) == 0 {
		return -1 // 没有找到匹配
	}

	// 填充目标变量
	for i, target := range targets {
		if target != nil && i < len(result) {
			*target = result[i]
		}
		// 如果已经处理完所有结果就退出
		if i >= len(result)-1 {
			break
		}
	}

	return 0 // 成功
}

func regGetAllMatch(src, match string, groupOnly bool) []string {
	// Compile the regex pattern
	re, err := regexp.Compile(match)
	if err != nil {
		return []string{}
	}

	// Find all matches
	matches := re.FindAllStringSubmatch(src, -1)

	// If no matches found, return empty slice
	if len(matches) == 0 {
		return []string{}
	}

	// Build result array based on the groupOnly flag
	var result []string
	begin := 0
	if groupOnly {
		begin = 1
	}

	// Extract groups from all matches
	for _, groups := range matches {
		for i := begin; i < len(groups); i++ {
			result = append(result, groups[i])
		}
	}

	return result
}

func regReplace(src, match, rep string, global, multiline bool) string {
	// 处理多行模式
	pattern := match
	if multiline && !strings.HasPrefix(match, "(?") {
		pattern = "(?m)" + match
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return src
	}

	if global {
		return re.ReplaceAllString(src, rep)
	} else {
		// 您的正确方法
		loc := re.FindStringIndex(src)
		if loc != nil {
			return src[:loc[0]] + rep + src[loc[1]:]
		}
		return src
	}
}

func regMatch(src, match string) bool {
	pattern := "(?m)" + match
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(src)
}

func isIPv4(address string) bool {
	matched, _ := regexp.MatchString(`^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$`, address)
	return matched
}

func isIPv6(address string) bool {
	regLists := []string{
		`^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`,
		`^((?:[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::((?:([0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4})?)$`,
		`^(::(?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5})|((?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5}::)$`,
	}
	for _, pattern := range regLists {
		matched, err := regexp.MatchString(pattern, address)
		if err != nil {
			// 如果正则表达式编译失败，继续尝试下一个模式
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// urlSafeBase64Decode 等效于C++的 urlSafeBase64Decode
func urlSafeBase64Decode(encodedString string) string {
	// 将URL安全字符转换回标准Base64字符
	encodedString = strings.ReplaceAll(encodedString, "-", "+")
	encodedString = strings.ReplaceAll(encodedString, "_", "/")

	// 添加必要的填充
	switch len(encodedString) % 4 {
	case 2:
		encodedString += "=="
	case 3:
		encodedString += "="
	}

	decoded, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func regFind(src, match string) bool {
	re, err := regexp.Compile(match)
	if err != nil {
		return false
	}
	return re.MatchString(src)
}

func toInt(str string, defValue uint32) uint32 {
	if str == "" {
		return defValue
	}
	n, err := strconv.Atoi(str)
	if err != nil {
		return defValue
	}
	return uint32(n)
}

func parsePeers(node *Proxy, data string) {
	peers := regGetAllMatch(data, `\((.*?)\)`, true)
	if len(peers) == 0 {
		return
	}
	peer := peers[0]
	peerdata := regGetAllMatch(peer, `([a-z-]+) ?= ?([^" ),]+|".*?"),? ?`, true)
	if len(peerdata)%2 != 0 {
		return
	}
	for i := 0; i < len(peerdata); i += 2 {
		key := peerdata[i]
		val := peerdata[i+1]
		switch key {
		case "public-key":
			node.PublicKey = val
		case "endpoint":
			lastColon := strings.LastIndex(val, ":")
			if lastColon != -1 {
				node.Hostname = val[:lastColon]
				portStr := val[lastColon+1:]
				if port, err := strconv.Atoi(portStr); err == nil {
					node.Port = uint16(port)
				}
			}
		case "client-id":
			node.ClientId = val
		case "allowed-ips":
			node.AllowedIPs = strings.Trim(val, `"`)
		default:
			// Ignore unknown keys
		}
	}
}

func getUrlArg(urlStr, request string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	// 解析查询参数
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ""
	}

	// 获取参数值
	return params.Get(request)
}

func urlDecode(encoded string) string {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return ""
	}
	return decoded
}

func isNull(m map[string]any, key string) bool {
	val, ok := m[key]
	return !ok || val == nil
}

func getMapBoolStr(m map[string]any, key string) *bool {
	var b bool
	if val, ok := m[key]; ok {
		if bb, ok := val.(bool); ok {
			b = bb
		} else {
			b, _ = strconv.ParseBool(val.(string))
		}
	}
	return &b
}

func isLink(url string) bool {
	return strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "data:")
}
