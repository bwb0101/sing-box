/*
 * 项目名称：sing-box_bw
 * 文件名：config.go
 * 日期：2025/08/03 15:10
 * 作者：Ben
 */

package subconvert

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badoption"
	"gopkg.in/ini.v1"
)

type (
	ProxyUrl struct {
		SubUrl     string
		RuleSetUrl string
	}

	ProxyConfig struct {
		Sub     string
		Proxy   *ProxyOption
		RuleSet *RulesetOption
		//
		Title       string
		RoutingMark int
		Filters     []string
	}

	ProxyOption struct {
		Rules  []string
		Proxys []ProxyGroupOption
		Nodes  []ProxyGroupOption
	}

	ProxyGroupOption struct {
		Name      string
		Type      string // select / urltest
		Url       string
		Interval  int
		Timeout   int
		Tolerance int
		Proxies   []string
	}

	RulesetOption struct {
		SpeedDomain string
		Set         struct {
			Type           string
			UpdateInterval badoption.Duration
			Urls           []struct {
				Tag string
				Url string
			}
		}
	}
)

func UrlParse(urls *ProxyUrl) (pc *ProxyConfig, err error) {
	pc = &ProxyConfig{}
	url := urls.SubUrl
	if url != "" {
		if pos := strings.Index(url, "?"); pos != -1 {
			url = url[:pos]
		}
		if resp, err := http.Get(url); err == nil {
			if bs, err := io.ReadAll(resp.Body); err != nil {
				return nil, err
			} else {
				pc.Sub = string(bs)
				pc.Title = getUrlArg(urls.SubUrl, "title")
				pc.RoutingMark, _ = strconv.Atoi(getUrlArg(urls.SubUrl, "routing_mark"))
				pc.Filters = strings.Split(getUrlArg(urls.SubUrl, "filter"), ",")
				//
				if url = getUrlArg(urls.SubUrl, "rule"); url != "" {
					if resp, err := http.Get(url); err == nil {
						if bs, err := io.ReadAll(resp.Body); err != nil {
							return nil, err
						} else {
							if iniFile, err := ini.LoadSources(ini.LoadOptions{
								AllowShadows:            true,
								SkipUnrecognizableLines: false,
							}, bs); err != nil {
								return nil, err
							} else {
								sr, _ := iniFile.GetSection("rules")
								sp, _ := iniFile.GetSection("proxys")
								sn, _ := iniFile.GetSection("nodes")
								if sr != nil && sp != nil && sn != nil {
									pc.Proxy = &ProxyOption{
										Rules: sr.Key("rule").ValueWithShadows(),
									}
									for _, proxy := range sp.Key("proxy").ValueWithShadows() {
										arr := strings.Split(proxy, "`")
										px := ProxyGroupOption{
											Name: arr[0],
											Type: arr[1],
										}
										switch px.Type {
										case "select":
											px.Type = constant.TypeSelector
											px.Proxies = arr[2:]
										case "url-test":
											px.Type = constant.TypeURLTest
											px.Proxies = arr[2:3]
											px.Url = arr[3]
											times := strings.Split(arr[4], ",")
											px.Interval, _ = strconv.Atoi(times[0])
											px.Tolerance, _ = strconv.Atoi(times[2])
										}
										pc.Proxy.Proxys = append(pc.Proxy.Proxys, px)
									}
									for _, proxy := range sn.Key("node").ValueWithShadows() {
										arr := strings.Split(proxy, "`")
										px := ProxyGroupOption{
											Name: arr[0],
											Type: arr[1],
										}
										switch px.Type {
										case "select":
											px.Type = constant.TypeSelector
											px.Proxies = arr[2:]
										}
										pc.Proxy.Nodes = append(pc.Proxy.Nodes, px)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if url = urls.RuleSetUrl; url != "" {
		if resp, err := http.Get(url); err == nil {
			if bs, err := io.ReadAll(resp.Body); err != nil {
				return nil, err
			} else {
				var opt RulesetOption
				if err = json.Unmarshal(bs, &opt); err != nil {
					return nil, err
				}
				pc.RuleSet = &opt
			}
		}
	}
	return
}
