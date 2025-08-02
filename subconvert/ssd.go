/*
 * 项目名称：sing-box_bw
 * 文件名：ssd.go
 * 日期：2025/08/02 16:47
 * 作者：Ben
 */

package subconvert

import (
	"encoding/json"
)

func explodeSSD(link string, nodes *[]Proxy) {
	var jsondata map[string]any
	var listType int
	var listCount int
	var nodeMap map[int]string

	group := ""
	port := ""
	method := ""
	password := ""
	server := ""
	remarks := ""
	plugin := ""
	pluginopts := ""

	link = urlSafeBase64Decode(link[6:])
	if err := json.Unmarshal([]byte(link), &jsondata); err != nil {
		return
	}

	if _, exists := jsondata["servers"]; !exists {
		return
	}

	if airport, exists := jsondata["airport"]; exists {
		if airportStr, ok := airport.(string); ok {
			group = airportStr
		}
	}

	switch servers := jsondata["servers"].(type) {
	case []any:
		listType = 0
		listCount = len(servers)
	case map[string]any:
		listType = 1
		listCount = len(servers)
		nodeMap = make(map[int]string)
		index := 0
		for key := range servers {
			nodeMap[index] = key
			index++
		}
	default:
		return
	}

	index := uint32(len(*nodes))

	for i := 0; i < listCount; i++ {
		// Get default info
		getMember(jsondata, "port", &port)
		getMember(jsondata, "encryption", &method)
		getMember(jsondata, "password", &password)
		getMember(jsondata, "plugin", &plugin)
		getMember(jsondata, "plugin_options", &pluginopts)

		var singlenode map[string]any

		switch listType {
		case 0:
			if servers, ok := jsondata["servers"].([]any); ok && i < len(servers) {
				if node, ok := servers[i].(map[string]any); ok {
					singlenode = node
				}
			}
		case 1:
			if key, exists := nodeMap[i]; exists {
				if servers, ok := jsondata["servers"].(map[string]any); ok {
					if node, exists := servers[key]; exists {
						if nodeMap, ok := node.(map[string]any); ok {
							singlenode = nodeMap
						}
					}
				}
			}
		default:
			continue
		}

		if singlenode == nil {
			continue
		}

		server = singlenode["server"].(string)
		getMember(singlenode, "remarks", &remarks)
		getMember(singlenode, "port", &port)
		getMember(singlenode, "encryption", &method)
		getMember(singlenode, "password", &password)
		getMember(singlenode, "plugin", &plugin)
		getMember(singlenode, "plugin_options", &pluginopts)

		if port == "0" {
			continue
		}

		var node Proxy
		ssConstruct(&node, group, remarks, server, port, password, method, plugin, pluginopts, nil, nil, nil, nil, "")
		node.Id = index
		*nodes = append(*nodes, node)
		index++
	}
}
