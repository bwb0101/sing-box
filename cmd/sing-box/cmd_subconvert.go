package main

import (
	json2 "encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
)

var (
	subUrl     string
	rulesUrl   string
	rulesetUrl string
)

var commandSubconvert = &cobra.Command{
	Use: "subconvert",
	Run: func(cmd *cobra.Command, args []string) {
		err := _subconvert()
		if err != nil {
			log.Fatal(err)
		}
	},
}

type (
	rulesetOption struct {
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

func init() {
	mainCommand.PersistentFlags().StringVarP(&subUrl, "sub", "", "", "订阅地址")
	mainCommand.PersistentFlags().StringVarP(&rulesUrl, "rule", "", "", "规则地址")
	mainCommand.PersistentFlags().StringVarP(&rulesetUrl, "rset", "", "", "规则集地址")
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
	cfgOpt := cfg[0].options
	if err = convert_ruleset(&cfgOpt); err != nil {
		return err
	}
	if err = convert_rules(&cfgOpt); err != nil {
		return err
	}
	b, err := json2.MarshalIndent(cfgOpt, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(configPaths[0], os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(b)
	return err
}

func convert_ruleset(cfgOpt *option.Options) error {
	if rulesetUrl != "" {
		if resp, err := http.Get(rulesetUrl); err != nil {
			return err
		} else {
			if bs, err := io.ReadAll(resp.Body); err != nil {
				return err
			} else {
				var opt rulesetOption
				if err = json.Unmarshal(bs, &opt); err != nil {
					return err
				}
				route := cfgOpt.Route
				if route.RuleSet != nil {
					route.RuleSet = route.RuleSet[:0]
				}
				for _, url := range opt.Set.Urls {
					route.RuleSet = append(route.RuleSet, option.RuleSet{
						Tag:  url.Tag,
						Type: opt.Set.Type,
						RemoteOptions: option.RemoteRuleSet{
							URL:            opt.SpeedDomain + url.Url,
							UpdateInterval: opt.Set.UpdateInterval,
						},
					})
				}
			}
		}
	}
	return nil
}

func convert_rules(cfgOpt *option.Options) error {
	if rulesUrl != "" {
		if resp, err := http.Get(rulesUrl); err != nil {
			return err
		} else {
			if bs, err := io.ReadAll(resp.Body); err != nil {
				return err
			} else {
				if iniFile, err := ini.LoadSources(ini.LoadOptions{
					AllowShadows:            true,
					SkipUnrecognizableLines: false,
				}, bs); err != nil {
					return err
				} else {
					route := cfgOpt.Route
					var rules []option.Rule
					for _, rule := range route.Rules {
						if rule.DefaultOptions.RuleAction.RouteOptions.Outbound == "hijack-dns" {
							rules = append(rules, rule)
						} else if rule.DefaultOptions.RawDefaultRule.ClashMode != "" {
							rules = append(rules, rule)
						}
					}
					if len(rules) == 0 {
						route.Rules = def_rules()
					}
					section, err := iniFile.GetSection("rules")
					if err != nil {
						return err
					}
					var rsmap = map[string]bool{}
					for _, set := range route.RuleSet {
						rsmap[set.Tag] = true
					}
					var rmap = map[string]bool{}
					for _, rule := range route.Rules {
						rmap[rule.DefaultOptions.RouteOptions.Outbound] = true
					}
					var nodemap = map[string][]string{}
					ruleNodes := section.Key("rules").ValueWithShadows()
					for _, nd := range ruleNodes {
						rarr := strings.Split(nd, ",")
						nodemap[rarr[0]] = append(nodemap[rarr[0]], rarr[1])
					}
					for _, rn := range section.Key("rules").ValueWithShadows() {
						rarr := strings.Split(rn, ",")
						if rarr[1] == "FINAL" {
							route.AutoDetectInterface = true
							route.Final = rarr[0]
						} else {
							if rsmap[rarr[1]] && !rmap[rarr[0]] {
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
			}
		}
	}
	return nil
}

func def_rules() (rules []option.Rule) {
	rules = append(rules, option.Rule{
		Type: constant.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Protocol: []string{"dns"},
			},
			RuleAction: option.RuleAction{
				Action: constant.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: "hijack-dns",
				},
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
