/*
 * 项目名称：sing-box_bw
 * 文件名：proxy.go
 * 日期：2025/08/02 14:04
 * 作者：Ben
 */

package subconvert

const (
	SS_DEFAULT_GROUP        = "SSProvider"
	SSR_DEFAULT_GROUP       = "SSRProvider"
	V2RAY_DEFAULT_GROUP     = "V2RayProvider"
	VLESS_DEFAULT_GROUP     = "VLESSProvider"
	SOCKS_DEFAULT_GROUP     = "SocksProvider"
	HTTP_DEFAULT_GROUP      = "HTTPProvider"
	TROJAN_DEFAULT_GROUP    = "TrojanProvider"
	SNELL_DEFAULT_GROUP     = "SnellProvider"
	WG_DEFAULT_GROUP        = "WireGuardProvider"
	HYSTERIA_DEFAULT_GROUP  = "HysteriaProvider"
	HYSTERIA2_DEFAULT_GROUP = "Hysteria2Provider"
	TUIC_DEFAULT_GROUP      = "TUICProvider"
	ANYTLS_DEFAULT_GROUP    = "AnyTLSProvider"
)

type ProxyType int

const (
	Unknown ProxyType = iota
	Shadowsocks
	ShadowsocksR
	VMess
	VLESS
	Trojan
	Snell
	HTTP
	HTTPS
	SOCKS5
	WireGuard
	Hysteria
	Hysteria2
	TUIC
	AnyTLS
)

func getProxyTypeName(t ProxyType) string {
	switch t {
	case Shadowsocks:
		return "SS"
	case ShadowsocksR:
		return "SSR"
	case VMess:
		return "VMess"
	case VLESS:
		return "VLESS"
	case Trojan:
		return "Trojan"
	case Snell:
		return "Snell"
	case HTTP:
		return "HTTP"
	case HTTPS:
		return "HTTPS"
	case SOCKS5:
		return "SOCKS5"
	case WireGuard:
		return "WireGuard"
	case Hysteria:
		return "Hysteria"
	case Hysteria2:
		return "Hysteria2"
	case TUIC:
		return "TUIC"
	case AnyTLS:
		return "AnyTLS"
	default:
		return "Unknown"
	}
}

type Proxy struct {
	Type     ProxyType
	Id       uint32
	GroupId  uint32
	Group    string
	Remark   string
	Hostname string
	Port     uint16

	Username         string
	Password         string
	EncryptMethod    string
	Plugin           string
	PluginOption     string
	Protocol         string
	ProtocolParam    string
	OBFS             string
	OBFSParam        string
	UserId           string
	AlterId          uint16
	TransferProtocol string
	FakeType         string
	TLSSecure        bool

	Host string
	Path string
	Edge string

	QUICSecure string
	QUICSecret string

	UDP           *bool // tribool
	TCPFastOpen   *bool // tribool
	AllowInsecure *bool // tribool
	TLS13         *bool // tribool

	UnderlyingProxy string

	SnellVersion uint16
	ServerName   string

	SelfIP       string
	SelfIPv6     string
	PublicKey    string
	PrivateKey   string
	PreSharedKey string
	DnsServers   []string
	Mtu          uint16
	AllowedIPs   string // 默认值: "0.0.0.0/0, ::/0"
	KeepAlive    uint16
	TestUrl      string
	ClientId     string

	Ports               string
	Up                  string
	UpSpeed             uint32
	Down                string
	DownSpeed           uint32
	AuthStr             string
	SNI                 string
	Fingerprint         string
	Ca                  string
	CaStr               string
	RecvWindowConn      uint32
	RecvWindow          uint32
	DisableMtuDiscovery *bool // tribool
	HopInterval         uint32
	Alpn                []string

	CWND uint32

	UUID                  string
	IP                    string
	HeartbeatInterval     string
	DisableSNI            *bool // tribool
	ReduceRTT             *bool // tribool
	RequestTimeout        uint32
	UdpRelayMode          string
	CongestionController  string
	MaxUdpRelayPacketSize uint32
	FastOpen              *bool // tribool
	MaxOpenStreams        uint32

	IdleSessionCheckInterval uint32
	IdleSessionTimeout       uint32
	MinIdleSession           uint32

	Flow           string
	XTLS           uint32
	PacketEncoding string
	ShortID        string
}
