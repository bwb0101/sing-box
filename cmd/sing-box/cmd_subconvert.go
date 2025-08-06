package main

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/subconvert"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/spf13/cobra"
)

var (
	subUrl     string
	rulesetUrl string
)

var commandSubconvert = &cobra.Command{
	Use:  "subconvert",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		decodedSubUrl, err := url.QueryUnescape(subUrl)
		if err != nil {
			log.Fatal("Failed to decode subUrl: ", err)
		}
		subUrl = decodedSubUrl
		//
		decodedSubUrl, err = url.QueryUnescape(rulesetUrl)
		if err != nil {
			log.Fatal("Failed to decode rulesetUrl: ", err)
		}
		rulesetUrl = decodedSubUrl
		err = _subconvert()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandSubconvert.Flags().StringVarP(&subUrl, "sub", "", "", "订阅地址")
	commandSubconvert.Flags().StringVarP(&rulesetUrl, "rset", "", "", "规则集地址")
	mainCommand.AddCommand(commandSubconvert)
}

func _subconvert() error {
	if _, err := os.Stat(configPaths[0]); err != nil && os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(configPaths[0]), 0644)
		file, _ := os.Create(configPaths[0])
		def := option.Options{
			Route: &option.RouteOptions{},
		}
		b, _ := json.Marshal(def)
		_, _ = file.Write(b)
		file.Close()
	}
	cfg, err := readConfig()
	if err != nil {
		return err
	}
	proxyCfg, err := subconvert.UrlParse(&subconvert.ProxyUrl{
		SubUrl:     subUrl,
		RuleSetUrl: rulesetUrl,
	})
	if err != nil {
		return err
	}
	cfgOpt := cfg[0].options
	subs(&cfgOpt, proxyCfg)
	convert_ruleset(&cfgOpt, proxyCfg)
	if err = convert_rules(&cfgOpt, proxyCfg); err != nil {
		return err
	}
	//
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(cfgOpt)
	if err != nil {
		return E.Cause(err, "encode config")
	}
	err = os.WriteFile(configPaths[0], buffer.Bytes(), 0o644)
	if err != nil {
		return err
	}
	return nil
}

func subs(cfgOpt *option.Options, pc *subconvert.ProxyConfig) {
	if pc.Sub != "" {
		var proxy []subconvert.Proxy
		subconvert.ExplodeConfContent(pc.Sub, &proxy)
		if len(pc.Filters) > 0 {
			for i := 0; i < len(proxy); i++ {
				s := proxy[i]
				for _, f := range pc.Filters {
					if strings.Contains(s.Remark, f) {
						proxy = append(proxy[:i], proxy[i+1:]...)
						i--
						break
					}
				}
			}
		}
		var hasInit bool
		var outboundProxys = map[string]int{}
		var outboundTitles = map[string][]int{}
		for i, outbound := range cfgOpt.Outbounds {
			if outbound.Type == constant.TypeDirect {
				hasInit = true
			}
			if subconvert.OutboundTypes[outbound.Type] {
				outboundTitles[outbound.Title] = append(outboundTitles[outbound.Title], i)
				outboundProxys[outbound.Tag] = i
			}
		}
		if !hasInit {
			cfgOpt.Outbounds = append(cfgOpt.Outbounds, option.Outbound{
				Type: constant.TypeDirect,
				Tag:  strings.ToUpper(constant.TypeDirect),
				Options: option.DialerOptions{
					RoutingMark: option.FwMark(pc.RoutingMark),
				},
			})
			cfgOpt.Outbounds = append(cfgOpt.Outbounds, option.Outbound{
				Type: constant.TypeBlock,
				Tag:  "REJECT",
			})
		}
		ins := 2 // 上面两个
		for _, p := range proxy {
			var ob option.Outbound
			// var dialer *option.DialerOptions
			switch p.Type {
			case subconvert.Shadowsocks:
				ob = subconvert.ToSS(p, pc)
				// dialer = &ob.Options.(*option.ShadowsocksOutboundOptions).DialerOptions
			case subconvert.VMess:
				ob = subconvert.ToVMESS(p, pc)
				// dialer = &ob.Options.(*option.VMessOutboundOptions).DialerOptions
			case subconvert.VLESS:
				ob = subconvert.ToVLESS(p, pc)
				// dialer = &ob.Options.(*option.VLESSOutboundOptions).DialerOptions
			case subconvert.Trojan:
				ob = subconvert.ToTrojan(p, pc)
				// dialer = &ob.Options.(*option.TrojanOutboundOptions).DialerOptions
			default:
				continue
			}
			// do := dialer.TakeDialerOptions()
			// do.DomainResolver = &option.DomainResolveOptions{
			// 	Server: "dns_default",
			// }
			// dialer.ReplaceDialerOptions(do)
			if idx, ok := outboundProxys[ob.Tag]; ok {
				cfgOpt.Outbounds[idx] = ob
				list := outboundTitles[ob.Title]
				for i, ix := range list {
					if ix == idx {
						outboundTitles[ob.Title] = append(list[:i], list[i+1:]...)
						break
					}
				}
			} else {
				cfgOpt.Outbounds = append(cfgOpt.Outbounds, ob)
			}
		}
		if len(outboundTitles[pc.Title]) > 0 {
			idxs := outboundTitles[pc.Title]
			sort.Sort(sort.Reverse(sort.IntSlice(idxs)))
			for _, idx := range idxs {
				cfgOpt.Outbounds = append(cfgOpt.Outbounds[:idx], cfgOpt.Outbounds[idx+1:]...)
			}
			clear(outboundProxys) // 重新刷新
			for i, outbound := range cfgOpt.Outbounds {
				if subconvert.OutboundTypes[outbound.Type] {
					outboundProxys[outbound.Tag] = i
				}
			}
		}
		//
		if pc.Proxy != nil {
			ins += len(proxy)
			mv := 0
			for i, groupOption := range pc.Proxy.Proxys {
				ob := proxy_parse(proxy, groupOption)
				if op, ok := outboundProxys[ob.Tag]; ok {
					cfgOpt.Outbounds[op+mv] = ob
				} else {
					if i+ins >= len(cfgOpt.Outbounds) {
						cfgOpt.Outbounds = append(cfgOpt.Outbounds, ob)
					} else {
						cfgOpt.Outbounds = append(cfgOpt.Outbounds[:i+ins+1], cfgOpt.Outbounds[i+ins:]...)
						cfgOpt.Outbounds[i+ins] = ob
						mv++
					}
				}
			}
			for _, nodeOption := range pc.Proxy.Nodes {
				ob := proxy_parse(proxy, nodeOption)
				if op, ok := outboundProxys[ob.Tag]; ok {
					cfgOpt.Outbounds[op+mv] = ob
				} else {
					cfgOpt.Outbounds = append(cfgOpt.Outbounds, ob)
				}
			}
		}
	}
}

func convert_ruleset(cfgOpt *option.Options, pc *subconvert.ProxyConfig) {
	if pc.RuleSet != nil {
		route := cfgOpt.Route
		var rsmap = map[string]int{}
		for i, set := range route.RuleSet {
			rsmap[set.Tag] = i
		}
		for _, _url := range pc.RuleSet.Set.Urls {
			rs := option.RuleSet{
				Tag:  _url.Tag,
				Type: pc.RuleSet.Set.Type,
				RemoteOptions: option.RemoteRuleSet{
					URL:            pc.RuleSet.SpeedDomain + _url.Url,
					UpdateInterval: pc.RuleSet.Set.UpdateInterval,
				},
			}
			if op, ok := rsmap[_url.Tag]; ok {
				route.RuleSet[op] = rs
			} else {
				route.RuleSet = append(route.RuleSet, rs)
			}
		}
	}
}

func convert_rules(cfgOpt *option.Options, pc *subconvert.ProxyConfig) error {
	if pc.Proxy != nil && len(pc.Proxy.Rules) > 0 {
		route := cfgOpt.Route
		route.DefaultDomainResolver = &option.DomainResolveOptions{
			Server: "dns_default",
		}
		route.Rules = def_rules()
		var rsmap = map[string]bool{}
		for _, set := range route.RuleSet {
			rsmap[set.Tag] = true
		}
		var nodemap = map[string][]string{}
		for _, nd := range pc.Proxy.Rules {
			rarr := strings.Split(nd, ",")
			if lr, local := convert_rules_custom(cfgOpt, rarr[1]); local {
				rsmap[rarr[1]] = true
				rarr[1] = lr
			}
			nodemap[rarr[0]] = append(nodemap[rarr[0]], rarr[1])
		}
		for _, rn := range pc.Proxy.Rules {
			rarr := strings.Split(rn, ",")
			if rarr[1] == "FINAL" {
				route.AutoDetectInterface = true
				route.Final = rarr[0]
			} else {
				if rsmap[rarr[1]] {
					route.Rules = append(route.Rules, option.Rule{
						Type: constant.RuleTypeDefault,
						DefaultOptions: option.DefaultRule{
							RawDefaultRule: option.RawDefaultRule{
								RuleSet: nodemap[rarr[0]],
							},
							RuleAction: option.RuleAction{
								Action: constant.RuleActionTypeRoute,
								RouteOptions: option.RouteActionOptions{
									Outbound: rarr[0],
								},
							},
						},
					})
				}
			}
		}
	}
	return nil
}

func convert_rules_custom(cfgOpt *option.Options, tag string) (string, bool) {
	if tag[0] == '/' {
		_tag := filepath.Base(tag[1:])
		_tag = _tag[:strings.LastIndex(_tag, ".")]
		//
		route := cfgOpt.Route
		var rsmap = map[string]int{}
		if len(route.RuleSet) > 0 {
			for i, set := range route.RuleSet {
				rsmap[set.Tag] = i
			}
		}
		rs := option.RuleSet{
			Tag:  _tag,
			Type: constant.RuleSetTypeLocal,
			LocalOptions: option.LocalRuleSet{
				Path: tag[1:],
			},
		}
		if op, ok := rsmap[_tag]; ok {
			route.RuleSet[op] = rs
		} else {
			route.RuleSet = append(route.RuleSet, rs)
		}
		return _tag, true
	}
	return tag, false
}

func def_rules() (rules []option.Rule) {
	rules = append(rules, option.Rule{
		Type: constant.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Inbound: []string{"dns-in"},
			},
			RuleAction: option.RuleAction{
				Action: "hijack-dns",
			},
		},
	})
	rules = append(rules, option.Rule{
		Type: constant.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				ClashMode: "Global",
			},
			RuleAction: option.RuleAction{
				Action: constant.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: "GLOBAL",
				},
			},
		},
	})
	rules = append(rules, option.Rule{
		Type: constant.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				ClashMode: "Direct",
			},
			RuleAction: option.RuleAction{
				Action: constant.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: "DIRECT",
				},
			},
		},
	})
	return
}

func proxy_parse(proxy []subconvert.Proxy, group subconvert.ProxyGroupOption) (ob option.Outbound) {
	ob.Tag = group.Name
	ob.Type = group.Type
	switch group.Type {
	case constant.TypeSelector:
		out := option.SelectorOutboundOptions{InterruptExistConnections: true}
		for _, px := range group.Proxies {
			if px[:2] == "[]" {
				out.Outbounds = append(out.Outbounds, px[2:])
			} else if len(proxy) > 0 {
				for _, s := range proxy {
					if subconvert.Pcre2RegFind(s.Remark, px) {
						out.Outbounds = append(out.Outbounds, s.Remark)
					}
				}
			}
			if len(out.Outbounds) == 0 {
				out.Outbounds = append(out.Outbounds, strings.ToUpper(constant.TypeDirect))
			}
		}
		ob.Options = out
	case constant.TypeURLTest:
		out := option.URLTestOutboundOptions{}
		for _, s := range proxy {
			if subconvert.Pcre2RegFind(s.Remark, group.Proxies[0]) {
				out.Outbounds = append(out.Outbounds, s.Remark)
			}
		}
		out.Interval = badoption.Duration(time.Duration(group.Interval) * time.Second)
		out.Tolerance = uint16(group.Tolerance)
		out.URL = group.Url
		ob.Options = out
	}
	return
}
