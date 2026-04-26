// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"stormdns-go/internal/compression"
)

type ServerConfig struct {
	ConfigDir                         string   `toml:"-"`
	ConfigPath                        string   `toml:"-"`
	ProtocolType                      string   `toml:"PROTOCOL_TYPE"`
	UDPHost                           string   `toml:"UDP_HOST"`
	UDPPort                           int      `toml:"UDP_PORT"`
	UDPReaders                        int      `toml:"UDP_READERS"`
	SocketBufferSize                  int      `toml:"SOCKET_BUFFER_SIZE"`
	MaxConcurrentRequests             int      `toml:"MAX_CONCURRENT_REQUESTS"`
	DNSRequestWorkers                 int      `toml:"DNS_REQUEST_WORKERS"`
	DeferredSessionWorkers            int      `toml:"DEFERRED_SESSION_WORKERS"`
	DeferredSessionQueueLimit         int      `toml:"DEFERRED_SESSION_QUEUE_LIMIT"`
	SessionOrphanQueueInitialCap      int      `toml:"SESSION_ORPHAN_QUEUE_INITIAL_CAPACITY"`
	StreamQueueInitialCapacity        int      `toml:"STREAM_QUEUE_INITIAL_CAPACITY"`
	DNSFragmentStoreCapacity          int      `toml:"DNS_FRAGMENT_STORE_CAPACITY"`
	SOCKS5FragmentStoreCapacity       int      `toml:"SOCKS5_FRAGMENT_STORE_CAPACITY"`
	MaxPacketSize                     int      `toml:"MAX_PACKET_SIZE"`
	MaxStreamsPerSession              int      `toml:"MAX_STREAMS_PER_SESSION"`
	MaxDNSResponseBytes               int      `toml:"MAX_DNS_RESPONSE_BYTES"`
	DropLogIntervalSecs               float64  `toml:"DROP_LOG_INTERVAL_SECONDS"`
	InvalidCookieWindowSecs           float64  `toml:"INVALID_COOKIE_WINDOW_SECONDS"`
	InvalidCookieErrorThreshold       int      `toml:"INVALID_COOKIE_ERROR_THRESHOLD"`
	SessionTimeoutSecs                float64  `toml:"SESSION_TIMEOUT_SECONDS"`
	SessionCleanupIntervalSecs        float64  `toml:"SESSION_CLEANUP_INTERVAL_SECONDS"`
	ClosedSessionRetentionSecs        float64  `toml:"CLOSED_SESSION_RETENTION_SECONDS"`
	SessionInitReuseTTLSeconds        float64  `toml:"SESSION_INIT_REUSE_TTL_SECONDS"`
	RecentlyClosedStreamTTLSeconds    float64  `toml:"RECENTLY_CLOSED_STREAM_TTL_SECONDS"`
	RecentlyClosedStreamCap           int      `toml:"RECENTLY_CLOSED_STREAM_CAP"`
	TerminalStreamRetentionSeconds    float64  `toml:"TERMINAL_STREAM_RETENTION_SECONDS"`
	MaxPacketsPerBatch                int      `toml:"MAX_PACKETS_PER_BATCH"`
	PacketBlockControlDuplication     int      `toml:"PACKET_BLOCK_CONTROL_DUPLICATION"`
	DNSUpstreamServers                []string `toml:"DNS_UPSTREAM_SERVERS"`
	DNSUpstreamTimeoutSecs            float64  `toml:"DNS_UPSTREAM_TIMEOUT"`
	DNSInflightWaitTimeoutSecs        float64  `toml:"DNS_INFLIGHT_WAIT_TIMEOUT_SECONDS"`
	SOCKSConnectTimeoutSecs           float64  `toml:"SOCKS_CONNECT_TIMEOUT"`
	DNSFragmentAssemblyTimeoutSecs    float64  `toml:"DNS_FRAGMENT_ASSEMBLY_TIMEOUT"`
	StreamSetupAckTTLSeconds          float64  `toml:"STREAM_SETUP_ACK_TTL_SECONDS"`
	StreamResultPacketTTLSeconds      float64  `toml:"STREAM_RESULT_PACKET_TTL_SECONDS"`
	StreamFailurePacketTTLSeconds     float64  `toml:"STREAM_FAILURE_PACKET_TTL_SECONDS"`
	DNSCacheMaxRecords                int      `toml:"DNS_CACHE_MAX_RECORDS"`
	DNSCacheTTLSeconds                float64  `toml:"DNS_CACHE_TTL_SECONDS"`
	UseExternalSOCKS5                 bool     `toml:"USE_EXTERNAL_SOCKS5"`
	SOCKS5Auth                        bool     `toml:"SOCKS5_AUTH"`
	SOCKS5User                        string   `toml:"SOCKS5_USER"`
	SOCKS5Pass                        string   `toml:"SOCKS5_PASS"`
	ForwardIP                         string   `toml:"FORWARD_IP"`
	ForwardPort                       int      `toml:"FORWARD_PORT"`
	Domain                            []string `toml:"DOMAIN"`
	MinVPNLabelLength                 int      `toml:"MIN_VPN_LABEL_LENGTH"`
	SupportedUploadCompressionTypes   []int    `toml:"SUPPORTED_UPLOAD_COMPRESSION_TYPES"`
	SupportedDownloadCompressionTypes []int    `toml:"SUPPORTED_DOWNLOAD_COMPRESSION_TYPES"`
	DataEncryptionMethod              int      `toml:"DATA_ENCRYPTION_METHOD"`
	EncryptionKeyFile                 string   `toml:"ENCRYPTION_KEY_FILE"`
	LogLevel                          string   `toml:"LOG_LEVEL"`
	ARQWindowSize                     int      `toml:"ARQ_WINDOW_SIZE"`
	ARQInitialRTOSeconds              float64  `toml:"ARQ_INITIAL_RTO_SECONDS"`
	ARQMaxRTOSeconds                  float64  `toml:"ARQ_MAX_RTO_SECONDS"`
	ARQControlInitialRTOSeconds       float64  `toml:"ARQ_CONTROL_INITIAL_RTO_SECONDS"`
	ARQControlMaxRTOSeconds           float64  `toml:"ARQ_CONTROL_MAX_RTO_SECONDS"`
	ARQMaxControlRetries              int      `toml:"ARQ_MAX_CONTROL_RETRIES"`
	ARQInactivityTimeoutSeconds       float64  `toml:"ARQ_INACTIVITY_TIMEOUT_SECONDS"`
	ARQDataPacketTTLSeconds           float64  `toml:"ARQ_DATA_PACKET_TTL_SECONDS"`
	ARQControlPacketTTLSeconds        float64  `toml:"ARQ_CONTROL_PACKET_TTL_SECONDS"`
	ARQMaxDataRetries                 int      `toml:"ARQ_MAX_DATA_RETRIES"`
	ARQDataNackMaxGap                 int      `toml:"ARQ_DATA_NACK_MAX_GAP"`
	ARQDataNackInitialDelaySeconds    float64  `toml:"ARQ_DATA_NACK_INITIAL_DELAY_SECONDS"`
	ARQDataNackRepeatSeconds          float64  `toml:"ARQ_DATA_NACK_REPEAT_SECONDS"`
	ARQTerminalDrainTimeoutSec        float64  `toml:"ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS"`
	ARQTerminalAckWaitTimeoutSec      float64  `toml:"ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS"`
}

type ServerConfigOverrides struct {
	Values map[string]any
}

type ServerConfigFlagBinder struct {
	values      ServerConfig
	setFields   map[string]struct{}
	flagToField map[string]string
}

func defaultServerConfig() ServerConfig {
	workers := min(max(runtime.NumCPU(), 1), 16)

	readers := min(max(runtime.NumCPU()/2, 1), 4)

	return ServerConfig{
		ProtocolType:                      "SOCKS5",
		UDPHost:                           "0.0.0.0",
		UDPPort:                           53,
		UDPReaders:                        readers,
		SocketBufferSize:                  8 * 1024 * 1024,
		MaxConcurrentRequests:             16384,
		DNSRequestWorkers:                 workers,
		DeferredSessionWorkers:            8,
		DeferredSessionQueueLimit:         4096,
		SessionOrphanQueueInitialCap:      64,
		StreamQueueInitialCapacity:        128,
		DNSFragmentStoreCapacity:          256,
		SOCKS5FragmentStoreCapacity:       512,
		MaxPacketSize:                     65535,
		MaxStreamsPerSession:              4096,
		MaxDNSResponseBytes:               32768,
		DropLogIntervalSecs:               2.0,
		InvalidCookieWindowSecs:           2.0,
		InvalidCookieErrorThreshold:       10,
		SessionTimeoutSecs:                300.0,
		SessionCleanupIntervalSecs:        30.0,
		ClosedSessionRetentionSecs:        600.0,
		SessionInitReuseTTLSeconds:        600.0,
		RecentlyClosedStreamTTLSeconds:    600.0,
		RecentlyClosedStreamCap:           2000,
		TerminalStreamRetentionSeconds:    45.0,
		MaxPacketsPerBatch:                8,
		PacketBlockControlDuplication:     1,
		DNSUpstreamServers:                []string{"1.1.1.1:53"},
		DNSUpstreamTimeoutSecs:            4.0,
		DNSInflightWaitTimeoutSecs:        8.0,
		SOCKSConnectTimeoutSecs:           8.0,
		DNSFragmentAssemblyTimeoutSecs:    300.0,
		StreamSetupAckTTLSeconds:          400.0,
		StreamResultPacketTTLSeconds:      300.0,
		StreamFailurePacketTTLSeconds:     120.0,
		DNSCacheMaxRecords:                20000,
		DNSCacheTTLSeconds:                300.0,
		UseExternalSOCKS5:                 false,
		SOCKS5Auth:                        false,
		SOCKS5User:                        "admin",
		SOCKS5Pass:                        "123456",
		ForwardIP:                         "",
		ForwardPort:                       1080,
		Domain:                            nil,
		MinVPNLabelLength:                 3,
		SupportedUploadCompressionTypes:   []int{0, 3},
		SupportedDownloadCompressionTypes: []int{0, 3},
		DataEncryptionMethod:              1,
		EncryptionKeyFile:                 "encrypt_key.txt",
		LogLevel:                          "INFO",
		ARQWindowSize:                     2000,
		ARQInitialRTOSeconds:              1.0,
		ARQMaxRTOSeconds:                  8.0,
		ARQControlInitialRTOSeconds:       1.0,
		ARQControlMaxRTOSeconds:           8.0,
		ARQMaxControlRetries:              80,
		ARQInactivityTimeoutSeconds:       1800.0,
		ARQDataPacketTTLSeconds:           1800.0,
		ARQControlPacketTTLSeconds:        900.0,
		ARQMaxDataRetries:                 800,
		ARQDataNackMaxGap:                 0,
		ARQDataNackInitialDelaySeconds:    0.4,
		ARQDataNackRepeatSeconds:          1.0,
		ARQTerminalDrainTimeoutSec:        90.0,
		ARQTerminalAckWaitTimeoutSec:      60.0,
	}
}

func LoadServerConfig(filename string) (ServerConfig, error) {
	cfg, err := loadServerConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	return finalizeServerConfig(cfg)
}

func loadServerConfigFile(filename string) (ServerConfig, error) {
	cfg := defaultServerConfig()
	path, err := filepath.Abs(filename)
	if err != nil {
		return cfg, err
	}

	if _, err := os.Stat(path); err != nil {
		return cfg, fmt.Errorf("config file not found: %s", path)
	}

	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parse TOML failed for %s: %w", path, err)
	}

	cfg.ConfigPath = path
	cfg.ConfigDir = filepath.Dir(path)
	return cfg, nil
}

func LoadServerConfigWithOverrides(filename string, overrides ServerConfigOverrides) (ServerConfig, error) {
	cfg, err := loadServerConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	if len(overrides.Values) > 0 {
		if err := applyServerConfigOverrideValues(&cfg, overrides.Values); err != nil {
			return cfg, err
		}
	}
	return finalizeServerConfig(cfg)
}

func finalizeServerConfig(cfg ServerConfig) (ServerConfig, error) {
	cfg.ProtocolType = defaultString(strings.ToUpper(strings.TrimSpace(cfg.ProtocolType)), "SOCKS5")

	switch cfg.ProtocolType {
	case "SOCKS5", "TCP":
	default:
		return cfg, fmt.Errorf("invalid PROTOCOL_TYPE: %q", cfg.ProtocolType)
	}

	if cfg.UDPHost == "" {
		cfg.UDPHost = "0.0.0.0"
	}

	if cfg.UDPPort <= 0 || cfg.UDPPort > 65535 {
		return cfg, fmt.Errorf("invalid UDP_PORT: %d", cfg.UDPPort)
	}

	if cfg.UDPReaders <= 0 {
		cfg.UDPReaders = defaultServerConfig().UDPReaders
	}

	if cfg.SocketBufferSize <= 0 {
		cfg.SocketBufferSize = 8 * 1024 * 1024
	}

	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = 4096
	}

	if cfg.DNSRequestWorkers <= 0 {
		cfg.DNSRequestWorkers = defaultServerConfig().DNSRequestWorkers
	}
	if cfg.DeferredSessionWorkers < 0 {
		cfg.DeferredSessionWorkers = 0
	}

	if cfg.DeferredSessionWorkers > 128 {
		cfg.DeferredSessionWorkers = 128
	}

	if cfg.DeferredSessionQueueLimit < 1 {
		cfg.DeferredSessionQueueLimit = 256
	}

	if cfg.DeferredSessionQueueLimit > 14336 {
		cfg.DeferredSessionQueueLimit = 14336
	}

	cfg.SessionOrphanQueueInitialCap = clampInt(defaultIntBelow(cfg.SessionOrphanQueueInitialCap, 1, 64), 4, 4096)
	cfg.StreamQueueInitialCapacity = clampInt(defaultIntBelow(cfg.StreamQueueInitialCapacity, 1, 128), 8, 65536)
	cfg.DNSFragmentStoreCapacity = clampInt(defaultIntBelow(cfg.DNSFragmentStoreCapacity, 1, 256), 16, 16384)
	cfg.SOCKS5FragmentStoreCapacity = clampInt(defaultIntBelow(cfg.SOCKS5FragmentStoreCapacity, 1, 512), 16, 16384)
	if cfg.MaxPacketSize <= 0 {
		cfg.MaxPacketSize = 65535
	}
	cfg.MaxStreamsPerSession = clampInt(defaultIntBelow(cfg.MaxStreamsPerSession, 1, 4096), 16, 65535)
	cfg.MaxDNSResponseBytes = clampInt(defaultIntBelow(cfg.MaxDNSResponseBytes, 1, 32768), 512, 65535)

	if cfg.DropLogIntervalSecs <= 0 {
		cfg.DropLogIntervalSecs = 2.0
	}

	if cfg.InvalidCookieWindowSecs <= 0 {
		cfg.InvalidCookieWindowSecs = 2.0
	}

	if cfg.InvalidCookieErrorThreshold <= 0 {
		cfg.InvalidCookieErrorThreshold = 10
	}

	if cfg.SessionTimeoutSecs <= 0 {
		cfg.SessionTimeoutSecs = 300.0
	}

	if cfg.SessionCleanupIntervalSecs <= 0 {
		cfg.SessionCleanupIntervalSecs = 30.0
	}

	if cfg.ClosedSessionRetentionSecs <= 0 {
		cfg.ClosedSessionRetentionSecs = 600.0
	}
	cfg.SessionInitReuseTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitReuseTTLSeconds, 600.0), 1.0, 86400.0)
	cfg.RecentlyClosedStreamTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.RecentlyClosedStreamTTLSeconds, 600.0), 1.0, 86400.0)
	cfg.RecentlyClosedStreamCap = clampInt(defaultIntBelow(cfg.RecentlyClosedStreamCap, 1, 2000), 1, 1000000)
	cfg.TerminalStreamRetentionSeconds = clampFloat(defaultFloatAtMostZero(cfg.TerminalStreamRetentionSeconds, 45.0), 1.0, 86400.0)

	if cfg.MaxPacketsPerBatch < 1 {
		cfg.MaxPacketsPerBatch = 20
	}

	if cfg.PacketBlockControlDuplication < 1 {
		cfg.PacketBlockControlDuplication = 1
	}

	if cfg.PacketBlockControlDuplication > 4 {
		cfg.PacketBlockControlDuplication = 4
	}

	if len(cfg.DNSUpstreamServers) == 0 {
		cfg.DNSUpstreamServers = []string{"1.1.1.1:53"}
	}

	if cfg.DNSUpstreamTimeoutSecs <= 0 {
		cfg.DNSUpstreamTimeoutSecs = 4.0
	}
	cfg.DNSInflightWaitTimeoutSecs = clampFloat(defaultFloatAtMostZero(cfg.DNSInflightWaitTimeoutSecs, 8.0), 0.1, 120.0)

	if cfg.SOCKSConnectTimeoutSecs <= 0 {
		cfg.SOCKSConnectTimeoutSecs = 8.0
	}

	if cfg.DNSFragmentAssemblyTimeoutSecs <= 0 {
		cfg.DNSFragmentAssemblyTimeoutSecs = 300.0
	}
	cfg.StreamSetupAckTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamSetupAckTTLSeconds, 400.0), 1.0, 86400.0)
	cfg.StreamResultPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamResultPacketTTLSeconds, 300.0), 1.0, 86400.0)
	cfg.StreamFailurePacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamFailurePacketTTLSeconds, 120.0), 1.0, 86400.0)

	if cfg.DNSCacheMaxRecords < 1 {
		cfg.DNSCacheMaxRecords = 2000
	}

	if cfg.DNSCacheTTLSeconds <= 0 {
		cfg.DNSCacheTTLSeconds = 3600.0
	}

	if cfg.ForwardPort < 0 || cfg.ForwardPort > 65535 {
		return cfg, fmt.Errorf("invalid FORWARD_PORT: %d", cfg.ForwardPort)
	}

	if len(cfg.SOCKS5User) > 255 {
		return cfg, fmt.Errorf("SOCKS5_USER cannot exceed 255 bytes")
	}

	if len(cfg.SOCKS5Pass) > 255 {
		return cfg, fmt.Errorf("SOCKS5_PASS cannot exceed 255 bytes")
	}

	if cfg.SOCKS5Auth && (cfg.SOCKS5User == "" || cfg.SOCKS5Pass == "") {
		return cfg, fmt.Errorf("SOCKS5_AUTH requires both SOCKS5_USER and SOCKS5_PASS")
	}

	if cfg.UseExternalSOCKS5 {
		if cfg.ForwardIP == "" {
			return cfg, fmt.Errorf("USE_EXTERNAL_SOCKS5 requires FORWARD_IP")
		}
		if cfg.ForwardPort <= 0 {
			return cfg, fmt.Errorf("USE_EXTERNAL_SOCKS5 requires a valid FORWARD_PORT")
		}
	}

	if cfg.MinVPNLabelLength <= 0 {
		cfg.MinVPNLabelLength = 3
	}

	cfg.SupportedUploadCompressionTypes = normalizeCompressionTypeList(cfg.SupportedUploadCompressionTypes)
	cfg.SupportedDownloadCompressionTypes = normalizeCompressionTypeList(cfg.SupportedDownloadCompressionTypes)

	if cfg.DataEncryptionMethod < 0 || cfg.DataEncryptionMethod > 5 {
		cfg.DataEncryptionMethod = 1
	}

	if cfg.EncryptionKeyFile == "" {
		cfg.EncryptionKeyFile = "encrypt_key.txt"
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	cfg.ARQWindowSize = clampInt(defaultIntBelow(cfg.ARQWindowSize, 1, 2000), 1, 6000)
	cfg.ARQInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInitialRTOSeconds, 1.0), 0.05, 60.0)
	cfg.ARQMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQMaxRTOSeconds, 8.0), cfg.ARQInitialRTOSeconds, 120.0)
	cfg.ARQControlInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlInitialRTOSeconds, 1.0), 0.05, 60.0)
	cfg.ARQControlMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlMaxRTOSeconds, 8.0), cfg.ARQControlInitialRTOSeconds, 120.0)
	cfg.ARQMaxControlRetries = clampInt(defaultIntBelow(cfg.ARQMaxControlRetries, 1, 80), 5, 5000)
	cfg.ARQInactivityTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInactivityTimeoutSeconds, 1800.0), 30.0, 86400.0)
	cfg.ARQDataPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataPacketTTLSeconds, 1800.0), 30.0, 86400.0)
	cfg.ARQControlPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlPacketTTLSeconds, 900.0), 30.0, 86400.0)
	cfg.ARQMaxDataRetries = clampInt(defaultIntBelow(cfg.ARQMaxDataRetries, 1, 800), 60, 100000)
	cfg.ARQDataNackMaxGap = clampInt(defaultIntBelow(cfg.ARQDataNackMaxGap, 0, 0), 0, cfg.ARQWindowSize/4)
	cfg.ARQDataNackInitialDelaySeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackInitialDelaySeconds, 0.0), 0.2, 30.0)
	cfg.ARQDataNackRepeatSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackRepeatSeconds, 2.0), 0.3, 30.0)
	cfg.ARQTerminalDrainTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalDrainTimeoutSec, 90.0), 10.0, 3600.0)
	cfg.ARQTerminalAckWaitTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalAckWaitTimeoutSec, 60.0), 5.0, 3600.0)

	return cfg, nil
}

func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.UDPHost, c.UDPPort)
}

func (c ServerConfig) DropLogInterval() time.Duration {
	return time.Duration(c.DropLogIntervalSecs * float64(time.Second))
}

func (c ServerConfig) InvalidCookieWindow() time.Duration {
	return time.Duration(c.InvalidCookieWindowSecs * float64(time.Second))
}

func (c ServerConfig) SessionTimeout() time.Duration {
	return time.Duration(c.SessionTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SessionCleanupInterval() time.Duration {
	return time.Duration(c.SessionCleanupIntervalSecs * float64(time.Second))
}

func (c ServerConfig) ClosedSessionRetention() time.Duration {
	return time.Duration(c.ClosedSessionRetentionSecs * float64(time.Second))
}

func (c ServerConfig) DNSUpstreamTimeout() time.Duration {
	return time.Duration(c.DNSUpstreamTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) DNSInflightWaitTimeout() time.Duration {
	return time.Duration(c.DNSInflightWaitTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SOCKSConnectTimeout() time.Duration {
	return time.Duration(c.SOCKSConnectTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) DNSFragmentAssemblyTimeout() time.Duration {
	return time.Duration(c.DNSFragmentAssemblyTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SessionInitReuseTTL() time.Duration {
	return time.Duration(c.SessionInitReuseTTLSeconds * float64(time.Second))
}

func (c ServerConfig) RecentlyClosedStreamTTL() time.Duration {
	return time.Duration(c.RecentlyClosedStreamTTLSeconds * float64(time.Second))
}

func (c ServerConfig) TerminalStreamRetention() time.Duration {
	return time.Duration(c.TerminalStreamRetentionSeconds * float64(time.Second))
}

func (c ServerConfig) StreamSetupAckTTL() time.Duration {
	return time.Duration(c.StreamSetupAckTTLSeconds * float64(time.Second))
}

func (c ServerConfig) StreamResultPacketTTL() time.Duration {
	return time.Duration(c.StreamResultPacketTTLSeconds * float64(time.Second))
}

func (c ServerConfig) StreamFailurePacketTTL() time.Duration {
	return time.Duration(c.StreamFailurePacketTTLSeconds * float64(time.Second))
}

func (c ServerConfig) EncryptionKeyPath() string {
	if c.EncryptionKeyFile == "" {
		return filepath.Join(c.ConfigDir, "encrypt_key.txt")
	}
	if filepath.IsAbs(c.EncryptionKeyFile) {
		return c.EncryptionKeyFile
	}
	return filepath.Join(c.ConfigDir, c.EncryptionKeyFile)
}

func normalizeCompressionTypeList(values []int) []int {
	if len(values) == 0 {
		return []int{0}
	}

	seen := [4]bool{}
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value < 0 || value > 3 || seen[value] || !compression.IsTypeAvailable(uint8(value)) {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

func applyServerConfigOverrideValues(cfg *ServerConfig, values map[string]any) error {
	if cfg == nil || len(values) == 0 {
		return nil
	}

	elem := reflect.ValueOf(cfg).Elem()
	typ := elem.Type()
	for fieldName, rawValue := range values {
		field, ok := typ.FieldByName(fieldName)
		if !ok {
			return fmt.Errorf("unknown server config override field: %s", fieldName)
		}
		value := elem.FieldByName(fieldName)
		if !value.CanSet() {
			return fmt.Errorf("server config override field is not settable: %s", field.Name)
		}
		if err := assignServerConfigOverrideValue(value, rawValue, field.Name); err != nil {
			return err
		}
	}
	return nil
}

func assignServerConfigOverrideValue(target reflect.Value, rawValue any, fieldName string) error {
	if !target.IsValid() {
		return fmt.Errorf("invalid server config override target: %s", fieldName)
	}

	switch target.Kind() {
	case reflect.String:
		v, ok := rawValue.(string)
		if !ok {
			return fmt.Errorf("invalid string override for %s", fieldName)
		}
		target.SetString(v)
		return nil
	case reflect.Bool:
		v, ok := rawValue.(bool)
		if !ok {
			return fmt.Errorf("invalid bool override for %s", fieldName)
		}
		target.SetBool(v)
		return nil
	case reflect.Int:
		v, ok := rawValue.(int)
		if !ok {
			return fmt.Errorf("invalid int override for %s", fieldName)
		}
		target.SetInt(int64(v))
		return nil
	case reflect.Float64:
		v, ok := rawValue.(float64)
		if !ok {
			return fmt.Errorf("invalid float override for %s", fieldName)
		}
		target.SetFloat(v)
		return nil
	case reflect.Slice:
		switch target.Type().Elem().Kind() {
		case reflect.String:
			v, ok := rawValue.([]string)
			if !ok {
				return fmt.Errorf("invalid string slice override for %s", fieldName)
			}
			target.Set(reflect.ValueOf(append([]string(nil), v...)))
			return nil
		case reflect.Int:
			v, ok := rawValue.([]int)
			if !ok {
				return fmt.Errorf("invalid int slice override for %s", fieldName)
			}
			target.Set(reflect.ValueOf(append([]int(nil), v...)))
			return nil
		}
	}

	return fmt.Errorf("unsupported server config override type for %s", fieldName)
}

func NewServerConfigFlagBinder(fs *flag.FlagSet) (*ServerConfigFlagBinder, error) {
	if fs == nil {
		return nil, fmt.Errorf("flag set is required")
	}

	binder := &ServerConfigFlagBinder{
		values:      defaultServerConfig(),
		setFields:   make(map[string]struct{}),
		flagToField: make(map[string]string),
	}

	valueElem := reflect.ValueOf(&binder.values).Elem()
	valueType := valueElem.Type()
	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		tomlTag := field.Tag.Get("toml")
		if tomlTag == "" || tomlTag == "-" {
			continue
		}

		flagName := clientConfigFlagName(tomlTag)
		binder.flagToField[flagName] = field.Name
		target := valueElem.Field(i)
		usage := fmt.Sprintf("Override %s from config file", tomlTag)

		switch target.Kind() {
		case reflect.String:
			fs.Var(newServerConfigStringFlag(target.Addr().Interface().(*string), binder, field.Name), flagName, usage)
		case reflect.Bool:
			fs.Var(newServerConfigBoolFlag(target.Addr().Interface().(*bool), binder, field.Name), flagName, usage)
		case reflect.Int:
			fs.Var(newServerConfigIntFlag(target.Addr().Interface().(*int), binder, field.Name), flagName, usage)
		case reflect.Float64:
			fs.Var(newServerConfigFloatFlag(target.Addr().Interface().(*float64), binder, field.Name), flagName, usage)
		case reflect.Slice:
			switch target.Type().Elem().Kind() {
			case reflect.String:
				fs.Var(newServerConfigStringSliceFlag(target.Addr().Interface().(*[]string), binder, field.Name), flagName, usage+" (comma-separated)")
			case reflect.Int:
				fs.Var(newServerConfigIntSliceFlag(target.Addr().Interface().(*[]int), binder, field.Name), flagName, usage+" (comma-separated)")
			}
		}
	}

	return binder, nil
}

func (b *ServerConfigFlagBinder) Overrides() ServerConfigOverrides {
	overrides := ServerConfigOverrides{
		Values: make(map[string]any, len(b.setFields)),
	}
	if b == nil {
		return overrides
	}

	valueElem := reflect.ValueOf(&b.values).Elem()
	for fieldName := range b.setFields {
		field := valueElem.FieldByName(fieldName)
		if !field.IsValid() {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			overrides.Values[fieldName] = field.String()
		case reflect.Bool:
			overrides.Values[fieldName] = field.Bool()
		case reflect.Int:
			overrides.Values[fieldName] = int(field.Int())
		case reflect.Float64:
			overrides.Values[fieldName] = field.Float()
		case reflect.Slice:
			switch field.Type().Elem().Kind() {
			case reflect.String:
				src := field.Interface().([]string)
				overrides.Values[fieldName] = append([]string(nil), src...)
			case reflect.Int:
				src := field.Interface().([]int)
				overrides.Values[fieldName] = append([]int(nil), src...)
			}
		}
	}

	return overrides
}

func (b *ServerConfigFlagBinder) markSet(fieldName string) {
	if b == nil || fieldName == "" {
		return
	}
	b.setFields[fieldName] = struct{}{}
}

type serverConfigStringFlag struct {
	target    *string
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigStringFlag(target *string, binder *ServerConfigFlagBinder, fieldName string) *serverConfigStringFlag {
	return &serverConfigStringFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigStringFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return *f.target
}

func (f *serverConfigStringFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	*f.target = value
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigBoolFlag struct {
	target    *bool
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigBoolFlag(target *bool, binder *ServerConfigFlagBinder, fieldName string) *serverConfigBoolFlag {
	return &serverConfigBoolFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigBoolFlag) String() string {
	if f == nil || f.target == nil {
		return "false"
	}
	return strconv.FormatBool(*f.target)
}

func (f *serverConfigBoolFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

func (f *serverConfigBoolFlag) IsBoolFlag() bool { return true }

type serverConfigIntFlag struct {
	target    *int
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigIntFlag(target *int, binder *ServerConfigFlagBinder, fieldName string) *serverConfigIntFlag {
	return &serverConfigIntFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigIntFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.Itoa(*f.target)
}

func (f *serverConfigIntFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigFloatFlag struct {
	target    *float64
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigFloatFlag(target *float64, binder *ServerConfigFlagBinder, fieldName string) *serverConfigFloatFlag {
	return &serverConfigFloatFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigFloatFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.FormatFloat(*f.target, 'f', -1, 64)
}

func (f *serverConfigFloatFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigStringSliceFlag struct {
	target    *[]string
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigStringSliceFlag(target *[]string, binder *ServerConfigFlagBinder, fieldName string) *serverConfigStringSliceFlag {
	return &serverConfigStringSliceFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigStringSliceFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return strings.Join(*f.target, ",")
}

func (f *serverConfigStringSliceFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		items = append(items, part)
	}
	*f.target = items
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigIntSliceFlag struct {
	target    *[]int
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigIntSliceFlag(target *[]int, binder *ServerConfigFlagBinder, fieldName string) *serverConfigIntSliceFlag {
	return &serverConfigIntSliceFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigIntSliceFlag) String() string {
	if f == nil || f.target == nil || len(*f.target) == 0 {
		return ""
	}
	parts := make([]string, 0, len(*f.target))
	for _, item := range *f.target {
		parts = append(parts, strconv.Itoa(item))
	}
	return strings.Join(parts, ",")
}

func (f *serverConfigIntSliceFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return err
		}
		items = append(items, parsed)
	}
	*f.target = items
	f.binder.markSet(f.fieldName)
	return nil
}
