package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

var DefaultClientProfile = Chrome_150

var MappedTLSClients = map[string]ClientProfile{
	"chrome_103":             Chrome_103,
	"chrome_104":             Chrome_104,
	"chrome_105":             Chrome_105,
	"chrome_106":             Chrome_106,
	"chrome_107":             Chrome_107,
	"chrome_108":             Chrome_108,
	"chrome_109":             Chrome_109,
	"chrome_110":             Chrome_110,
	"chrome_111":             Chrome_111,
	"chrome_112":             Chrome_112,
	"chrome_116_PSK":         Chrome_116_PSK,
	"chrome_116_PSK_PQ":      Chrome_116_PSK_PQ,
	"chrome_117":             Chrome_117,
	"chrome_120":             Chrome_120,
	"chrome_124":             Chrome_124,
	"chrome_130_PSK":         Chrome_130_PSK,
	"chrome_131":             Chrome_131,
	"chrome_131_PSK":         Chrome_131_PSK,
	"chrome_133":             Chrome_133,
	"chrome_133_PSK":         Chrome_133_PSK,
	"chrome_144":             Chrome_144,
	"chrome_144_PSK":         Chrome_144_PSK,
	"chrome_146":             Chrome_146,
	"chrome_146_PSK":         Chrome_146_PSK,
	"chrome_150":             Chrome_150,
	"chrome_150_PSK":         Chrome_150_PSK,
	"chrome_152":             Chrome_152,
	"chrome_152_PSK":         Chrome_152_PSK,
	"chrome_153":             Chrome_153,
	"chrome_153_PSK":         Chrome_153_PSK,
	"edge_153":               Edge_153,
	"edge_153_PSK":           Edge_153_PSK,
	"brave_146":              Brave_146,
	"brave_146_PSK":          Brave_146_PSK,
	"safari_15_3":            Safari_15_3,
	"safari_15_5":            Safari_15_5,
	"safari_15_6_1":          Safari_15_6_1,
	"safari_16_0":            Safari_16_0,
	"safari_16_1":            Safari_16_1,
	"safari_16_2":            Safari_16_2,
	"safari_16_3":            Safari_16_3,
	"safari_16_4":            Safari_16_4,
	"safari_16_5":            Safari_16_5,
	"safari_16_6":            Safari_16_6,
	"safari_17_0":            Safari_17_0,
	"safari_17_1":            Safari_17_1,
	"safari_17_2":            Safari_17_2,
	"safari_17_3":            Safari_17_3,
	"safari_17_4":            Safari_17_4,
	"safari_17_5":            Safari_17_5,
	"safari_17_6":            Safari_17_6,
	"safari_18_0":            Safari_18_0,
	"safari_18_1":            Safari_18_1,
	"safari_18_2":            Safari_18_2,
	"safari_18_3":            Safari_18_3,
	"safari_18_4":            Safari_18_4,
	"safari_18_5":            Safari_18_5,
	"safari_18_6":            Safari_18_6,
	"safari_26_0":            Safari_26_0,
	"safari_26_1":            Safari_26_1,
	"safari_26_2":            Safari_26_2,
	"safari_26_3":            Safari_26_3,
	"safari_26_4":            Safari_26_4,
	"safari_26_5":            Safari_26_5,
	"safari_26_6":            Safari_26_6,
	"safari_ipad_15_6":       Safari_Ipad_15_6,
	"safari_ios_15_5":        Safari_IOS_15_5,
	"safari_ios_15_6":        Safari_IOS_15_6,
	"safari_ios_16_0":        Safari_IOS_16_0,
	"safari_ios_17_0":        Safari_IOS_17_0,
	"safari_ios_18_0":        Safari_IOS_18_0,
	"safari_ios_18_5":        Safari_IOS_18_5,
	"safari_ios_26_0":        Safari_IOS_26_0,
	"firefox_102":            Firefox_102,
	"firefox_104":            Firefox_104,
	"firefox_105":            Firefox_105,
	"firefox_106":            Firefox_106,
	"firefox_108":            Firefox_108,
	"firefox_110":            Firefox_110,
	"firefox_117":            Firefox_117,
	"firefox_120":            Firefox_120,
	"firefox_123":            Firefox_123,
	"firefox_132":            Firefox_132,
	"firefox_133":            Firefox_133,
	"firefox_135":            Firefox_135,
	"firefox_146_PSK":        Firefox_146_PSK,
	"firefox_147":            Firefox_147,
	"firefox_147_PSK":        Firefox_147_PSK,
	"firefox_148":            Firefox_148,
	"tor_14_0":               Tor_14_0,
	"tor_14_5":               Tor_14_5,
	"opera_89":               Opera_89,
	"opera_90":               Opera_90,
	"opera_91":               Opera_91,
	"opera_92":               Opera_92,
	"opera_93":               Opera_93,
	"opera_94":               Opera_94,
	"opera_95":               Opera_95,
	"opera_96":               Opera_96,
	"opera_97":               Opera_97,
	"opera_98":               Opera_98,
	"opera_99":               Opera_99,
	"opera_100":              Opera_100,
	"opera_101":              Opera_101,
	"opera_102":              Opera_102,
	"opera_103":              Opera_103,
	"opera_104":              Opera_104,
	"opera_105":              Opera_105,
	"opera_106":              Opera_106,
	"opera_107":              Opera_107,
	"opera_108":              Opera_108,
	"opera_109":              Opera_109,
	"opera_110":              Opera_110,
	"opera_111":              Opera_111,
	"opera_112":              Opera_112,
	"opera_113":              Opera_113,
	"opera_114":              Opera_114,
	"opera_115":              Opera_115,
	"opera_116":              Opera_116,
	"opera_117":              Opera_117,
	"opera_118":              Opera_118,
	"opera_119":              Opera_119,
	"opera_120":              Opera_120,
	"opera_121":              Opera_121,
	"opera_122":              Opera_122,
	"opera_123":              Opera_123,
	"opera_124":              Opera_124,
	"opera_125":              Opera_125,
	"opera_126":              Opera_126,
	"opera_127":              Opera_127,
	"opera_128":              Opera_128,
	"opera_129":              Opera_129,
	"opera_130":              Opera_130,
	"opera_131":              Opera_131,
	"opera_132":              Opera_132,
	"opera_133":              Opera_133,
	"opera_134":              Opera_134,
	"opera_135":              Opera_135,
	"opera_136":              Opera_136,
	"zalando_android_mobile": ZalandoAndroidMobile,
	"zalando_ios_mobile":     ZalandoIosMobile,
	"nike_ios_mobile":        NikeIosMobile,
	"nike_android_mobile":    NikeAndroidMobile,
	"cloudscraper":           CloudflareCustom,
	"mms_ios":                MMSIos,
	"mms_ios_1":              MMSIos,
	"mms_ios_2":              MMSIos2,
	"mms_ios_3":              MMSIos3,
	"mesh_ios":               MeshIos,
	"mesh_ios_1":             MeshIos,
	"mesh_ios_2":             MeshIos2,
	"mesh_android":           MeshAndroid,
	"mesh_android_1":         MeshAndroid,
	"mesh_android_2":         MeshAndroid2,
	"confirmed_ios":          ConfirmedIos,
	"confirmed_android":      ConfirmedAndroid,
	"okhttp4_android_7":      Okhttp4Android7,
	"okhttp4_android_8":      Okhttp4Android8,
	"okhttp4_android_9":      Okhttp4Android9,
	"okhttp4_android_10":     Okhttp4Android10,
	"okhttp4_android_11":     Okhttp4Android11,
	"okhttp4_android_12":     Okhttp4Android12,
	"okhttp4_android_13":     Okhttp4Android13,
}

type ClientProfile struct {
	clientHelloId          tls.ClientHelloID
	headerPriority         *http2.PriorityParam
	settings               map[http2.SettingID]uint32
	settingsOrder          []http2.SettingID
	priorities             []http2.Priority
	pseudoHeaderOrder      []string
	connectionFlow         uint32
	streamID               uint32
	allowHTTP              bool
	http3Settings          map[uint64]uint64
	http3SettingsOrder     []uint64
	http3PriorityParam     uint32
	http3PseudoHeaderOrder []string
	http3SendGreaseFrames  bool
}

func NewClientProfile(clientHelloId tls.ClientHelloID, settings map[http2.SettingID]uint32, settingsOrder []http2.SettingID, pseudoHeaderOrder []string, connectionFlow uint32, priorities []http2.Priority, headerPriority *http2.PriorityParam, streamID uint32, allowHTTP bool, http3Settings map[uint64]uint64, http3SettingsOrder []uint64, http3PriorityParam uint32, http3PseudoHeaderOrder []string, http3SendGreaseFrames bool) ClientProfile {
	return ClientProfile{
		clientHelloId:          clientHelloId,
		settings:               settings,
		settingsOrder:          settingsOrder,
		pseudoHeaderOrder:      pseudoHeaderOrder,
		connectionFlow:         connectionFlow,
		priorities:             priorities,
		headerPriority:         headerPriority,
		streamID:               streamID,
		allowHTTP:              allowHTTP,
		http3Settings:          http3Settings,
		http3SettingsOrder:     http3SettingsOrder,
		http3PriorityParam:     http3PriorityParam,
		http3PseudoHeaderOrder: http3PseudoHeaderOrder,
		http3SendGreaseFrames:  http3SendGreaseFrames,
	}
}

func (c ClientProfile) GetClientHelloSpec() (tls.ClientHelloSpec, error) {
	return c.clientHelloId.ToSpec()
}

func (c ClientProfile) GetClientHelloStr() string {
	return c.clientHelloId.Str()
}

func (c ClientProfile) GetSettings() map[http2.SettingID]uint32 {
	return c.settings
}

func (c ClientProfile) GetSettingsOrder() []http2.SettingID {
	return c.settingsOrder
}

func (c ClientProfile) GetConnectionFlow() uint32 {
	return c.connectionFlow
}

func (c ClientProfile) GetPseudoHeaderOrder() []string {
	return c.pseudoHeaderOrder
}

func (c ClientProfile) GetHeaderPriority() *http2.PriorityParam {
	return c.headerPriority
}

func (c ClientProfile) GetClientHelloId() tls.ClientHelloID {
	return c.clientHelloId
}

func (c ClientProfile) GetPriorities() []http2.Priority {
	return c.priorities
}

func (c ClientProfile) GetStreamID() uint32 {
	return c.streamID
}

func (c ClientProfile) GetAllowHTTP() bool {
	return c.allowHTTP
}

func (c ClientProfile) GetHttp3Settings() map[uint64]uint64 {
	return c.http3Settings
}

func (c ClientProfile) GetHttp3SettingsOrder() []uint64 {
	return c.http3SettingsOrder
}

func (c ClientProfile) GetHttp3PriorityParam() uint32 {
	return c.http3PriorityParam
}

func (c ClientProfile) GetHttp3PseudoHeaderOrder() []string {
	return c.http3PseudoHeaderOrder
}

func (c ClientProfile) GetHttp3SendGreaseFrames() bool {
	return c.http3SendGreaseFrames
}
