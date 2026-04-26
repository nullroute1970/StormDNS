package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	runs       = flag.Int("runs", 3, "Number of runs for each direction")
	payloadMiB = flag.Int("bytes", 100*1024*1024, "Payload size in bytes (default 100MiB)")
	forceBuild = flag.Bool("force-build", true, "Force rebuilding binaries")
	benchPort  = flag.Int("bench-port", 19090, "Legacy port (not used much now with dynamic targets)")
	clientPort = flag.Int("client-port", 18080, "Port for the StormDNS client listener")
	serverPort = flag.Int("server-port", 5300, "Port for the StormDNS server UDP listener")

	// Standalone / slipstream-like flags
	optMode         = flag.String("mode", "", "Standalone mode: 'sink', 'source', 'send', 'recv'")
	optAddr         = flag.String("addr", "", "Address for standalone mode (host:port)")
	optChunkSize    = flag.Int("chunk-size", 32*1024, "Chunk size for transfers")
	optPrefaceBytes = flag.Int("preface-bytes", 0, "Bytes to skip before starting timer")
	optLogJson      = flag.Bool("json", false, "Output results in JSON format")
)

const (
	benchDir   = ".bench/local_snapshot_go"
	runtimeDir = benchDir + "/runtime"
	binDir     = benchDir + "/bin"
)

type BenchResult struct {
	Direction string        `json:"direction"`
	Elapsed   time.Duration `json:"elapsed"`
	Bytes     int64         `json:"bytes"`
	MiBps     float64       `json:"mib_s"`
}

type BenchEvent struct {
	Timestamp      float64 `json:"ts"`
	Event          string  `json:"event"`
	Mode           string  `json:"mode,omitempty"`
	Bytes          int64   `json:"bytes,omitempty"`
	Secs           float64 `json:"secs,omitempty"`
	FirstPayloadTs float64 `json:"first_payload_ts,omitempty"`
	LastPayloadTs  float64 `json:"last_payload_ts,omitempty"`
	Peer           string  `json:"peer,omitempty"`
}

func logEvent(event BenchEvent) {
	if *optLogJson {
		data, _ := json.Marshal(event)
		fmt.Println(string(data))
	}
}

func nowAsTs() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	if *optMode != "" {
		runStandalone()
		return
	}

	fmt.Printf("🚀 Starting StormDNS Go-Benchmark (slipstream-style timing)\n")
	fmt.Printf("📂 Working Dir: %s\n", benchDir)
	fmt.Printf("💾 Payload: %.2f MiB | Runs: %d\n\n", float64(*payloadMiB)/(1024*1024), *runs)

	if err := setupDirs(); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}

	if *forceBuild {
		if err := buildBinaries(); err != nil {
			log.Fatalf("Failed to build binaries: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("📡 Benchmarking Exfiltration (Upload)...")
	exfilResults := runBenchmark(ctx, "exfil")

	fmt.Println("\n📡 Benchmarking Download...")
	downloadResults := runBenchmark(ctx, "download")

	printSummary(exfilResults, downloadResults)
}

func runStandalone() {
	ctx := context.Background()
	var err error
	switch *optMode {
	case "sink", "source":
		err = RunServer(ctx, *optMode, *optAddr, int64(*payloadMiB), *optChunkSize, *optPrefaceBytes)
	case "send", "recv":
		err = RunClient(ctx, *optMode, *optAddr, int64(*payloadMiB), *optChunkSize, *optPrefaceBytes)
	default:
		log.Fatalf("Unknown mode: %s", *optMode)
	}
	if err != nil {
		log.Fatalf("Benchmark failed: %v", err)
	}
}

func setupDirs() error {
	// First, try to clear runtime dir if it exists to avoid log pollution
	if _, err := os.Stat(runtimeDir); err == nil {
		_ = os.RemoveAll(runtimeDir)
	}

	for _, d := range []string{benchDir, binDir, runtimeDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}
	return nil
}

func buildBinaries() error {
	bins := map[string]string{
		"server.exe": "./cmd/server",
		"client.exe": "./cmd/client",
	}

	for name, pkg := range bins {
		outPath, _ := filepath.Abs(filepath.Join(binDir, name))
		fmt.Printf("[build] Compiling %s -> %s\n", pkg, outPath)
		cmd := exec.Command("go", "build", "-o", outPath, pkg)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build failed for %s: %v", pkg, err)
		}
	}
	return nil
}

func runBenchmark(ctx context.Context, direction string) []BenchResult {
	var results []BenchResult
	for i := 1; i <= *runs; i++ {
		fmt.Printf("[%s] Run %d/%d ... ", direction, i, *runs)
		res, err := runOnce(ctx, direction, i)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			fmt.Printf("  logs: %s\n", runtimeDir)
			continue
		}
		fmt.Printf("%.3fs (%.2f MiB/s)\n", res.Elapsed.Seconds(), res.MiBps)
		results = append(results, res)
		time.Sleep(1 * time.Second)
	}
	return results
}

func runOnce(ctx context.Context, direction string, runIndex int) (BenchResult, error) {
	// 1. Setup Target Server with dynamic port
	targetReceived := make(chan struct{})
	ln, targetPort, err := startTargetServer(int64(*payloadMiB), direction, targetReceived)
	if err != nil {
		return BenchResult{}, err
	}
	defer ln.Close()

	// 2. Generate Configs
	serverCfg, _ := filepath.Abs(filepath.Join(runtimeDir, "server_config.toml"))
	clientCfg, _ := filepath.Abs(filepath.Join(runtimeDir, "client_config.toml"))
	keyFile, _ := filepath.Abs(filepath.Join(runtimeDir, "encrypt_key.txt"))
	_ = os.Remove(keyFile)

	os.WriteFile(serverCfg, []byte(fmt.Sprintf(`
	PROTOCOL_TYPE = "TCP"
	UDP_HOST = "0.0.0.0"
	UDP_PORT = %d
	DOMAIN = ["a.io"]
	MIN_VPN_LABEL_LENGTH = 1
	DATA_ENCRYPTION_METHOD = 1
	ENCRYPTION_KEY_FILE = "encrypt_key.txt"
	FORWARD_IP = "127.0.0.1"
	FORWARD_PORT = %d
	MAX_PACKETS_PER_BATCH = 5
	ARQ_WINDOW_SIZE = 16384
	ARQ_INITIAL_RTO_SECONDS = 0.25
	ARQ_MAX_RTO_SECONDS = 1.0
	UDP_READERS = 24
	DNS_REQUEST_WORKERS = 24
	DEFERRED_SESSION_WORKERS = 10
	MAX_CONCURRENT_REQUESTS = 52768
	LOG_LEVEL = "INFO"
	SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
	SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
	SOCKET_BUFFER_SIZE = 8388608
	MAX_PACKET_SIZE = 65535
	DEFERRED_SESSION_QUEUE_LIMIT = 4096
	SESSION_ORPHAN_QUEUE_INITIAL_CAPACITY = 128
	STREAM_QUEUE_INITIAL_CAPACITY = 256
	DNS_FRAGMENT_STORE_CAPACITY = 512
	SOCKS5_FRAGMENT_STORE_CAPACITY = 1024
	PACKET_BLOCK_CONTROL_DUPLICATION = 1
	STREAM_SETUP_ACK_TTL_SECONDS = 400.0
	STREAM_RESULT_PACKET_TTL_SECONDS = 300.0
	STREAM_FAILURE_PACKET_TTL_SECONDS = 120.0
	ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.25
	ARQ_CONTROL_MAX_RTO_SECONDS = 1.0
	ARQ_MAX_CONTROL_RETRIES = 300
	ARQ_INACTIVITY_TIMEOUT_SECONDS = 1800.0
	ARQ_DATA_PACKET_TTL_SECONDS = 2400.0
	ARQ_CONTROL_PACKET_TTL_SECONDS = 1200.0
	ARQ_MAX_DATA_RETRIES = 1200
	ARQ_DATA_NACK_MAX_GAP = 128
	ARQ_DATA_NACK_INITIAL_DELAY_SECONDS = 0.35
	ARQ_DATA_NACK_REPEAT_SECONDS = 0.8
	ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS = 120.0
	ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS = 90.0
	`, *serverPort, targetPort)), 0644)

	// 3. Start Server
	absServerBin, _ := filepath.Abs(filepath.Join(binDir, "server.exe"))
	serverCmd := exec.Command(absServerBin, "--config", serverCfg)
	serverCmd.Dir = filepath.Dir(serverCfg)
	serverLog := &safeBuffer{}
	serverCmd.Stdout = serverLog
	serverCmd.Stderr = serverLog
	if err := serverCmd.Start(); err != nil {
		return BenchResult{}, err
	}
	defer serverCmd.Process.Kill()

	if err := waitForFile(keyFile, 15*time.Second); err != nil {
		fmt.Printf("\n[ERROR] Server startup failed. Log:\n%s\n", serverLog.String())
		return BenchResult{}, err
	}
	keyData, _ := os.ReadFile(keyFile)
	encryptionKey := strings.TrimSpace(string(keyData))

	// 4. Start Client
	resolverFile, _ := filepath.Abs(filepath.Join(runtimeDir, "client_resolvers.txt"))
	os.WriteFile(resolverFile, []byte(fmt.Sprintf("127.0.0.1:%d\n", *serverPort)), 0644)

	os.WriteFile(clientCfg, []byte(fmt.Sprintf(`
	PROTOCOL_TYPE = "TCP"
	LISTEN_IP = "127.0.0.1"
	LISTEN_PORT = %d
	DOMAINS = ["a.io"]
	ENCRYPTION_KEY = "%s"
	RESOLVER_BALANCING_STRATEGY = 1
	DATA_ENCRYPTION_METHOD = 1
	UPLOAD_PACKET_DUPLICATION_COUNT = 1
	DOWNLOAD_PACKET_DUPLICATION_COUNT = 1
	UPLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
	DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
	MIN_UPLOAD_MTU = 120
	MIN_DOWNLOAD_MTU = 4000
	MAX_UPLOAD_MTU = 142
	MAX_DOWNLOAD_MTU = 4000
	MTU_TEST_RETRIES_RESOLVERS = 0
	MTU_TEST_TIMEOUT_RESOLVERS = 1.0
	MTU_TEST_PARALLELISM_RESOLVERS = 1
	MTU_TEST_RETRIES_LOGS = 0
	MTU_TEST_TIMEOUT_LOGS = 1.0
	MTU_TEST_PARALLELISM_LOGS = 1
	TUNNEL_READER_WORKERS = 20
	TUNNEL_WRITER_WORKERS = 20
	TUNNEL_PROCESS_WORKERS = 20
	TX_CHANNEL_SIZE = 32768
	RX_CHANNEL_SIZE = 32768
	ARQ_WINDOW_SIZE = 16384
	ARQ_INITIAL_RTO_SECONDS = 0.25
	ARQ_MAX_RTO_SECONDS = 1.0
	DISPATCHER_IDLE_POLL_INTERVAL_SECONDS = 0.002
	LOG_LEVEL = "INFO"
	PING_AGGRESSIVE_INTERVAL_SECONDS = 0.030
	PING_LAZY_INTERVAL_SECONDS = 0.100
	PING_COOLDOWN_INTERVAL_SECONDS = 1.0
	PING_COLD_INTERVAL_SECONDS = 10.0
	PING_WARM_THRESHOLD_SECONDS = 10.0
	PING_COOL_THRESHOLD_SECONDS = 15.0
	PING_COLD_THRESHOLD_SECONDS = 30.0
	ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.25
	ARQ_CONTROL_MAX_RTO_SECONDS = 1.0
	ARQ_INACTIVITY_TIMEOUT_SECONDS = 1800.0
	ARQ_DATA_PACKET_TTL_SECONDS = 2400.0
	ARQ_CONTROL_PACKET_TTL_SECONDS = 1200.0
	ARQ_MAX_DATA_RETRIES = 1200
	ARQ_DATA_NACK_MAX_GAP = 128
	STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD = 50
	STREAM_RESOLVER_FAILOVER_COOLDOWN = 10.0
	RECHECK_INACTIVE_SERVERS_ENABLED = false
	AUTO_DISABLE_TIMEOUT_SERVERS = false
	UPLOAD_COMPRESSION_TYPE = 0
	DOWNLOAD_COMPRESSION_TYPE = 0
	COMPRESSION_MIN_SIZE = 120
	TUNNEL_PACKET_TIMEOUT_SECONDS = 10.0
	RESOLVER_UDP_CONNECTION_POOL_SIZE = 512
	STREAM_QUEUE_INITIAL_CAPACITY = 512
	ORPHAN_QUEUE_INITIAL_CAPACITY = 256
	MAX_PACKETS_PER_BATCH = 1
	ARQ_MAX_CONTROL_RETRIES = 300
	ARQ_DATA_NACK_INITIAL_DELAY_SECONDS = 0.35
	ARQ_DATA_NACK_REPEAT_SECONDS = 0.8
	`, *clientPort, encryptionKey)), 0644)

	absClientBin, _ := filepath.Abs(filepath.Join(binDir, "client.exe"))
	clientCmd := exec.Command(absClientBin, "--config", clientCfg)
	clientLog := &safeBuffer{}
	clientCmd.Stdout = clientLog
	clientCmd.Stderr = clientLog
	defer persistRunLogs(direction, runIndex, serverLog, clientLog)
	if err := clientCmd.Start(); err != nil {
		return BenchResult{}, err
	}
	defer clientCmd.Process.Kill()

	if err := waitForPattern(clientLog, "TCP Proxy server is listening", 30*time.Second); err != nil {
		fmt.Printf("\n[ERROR] Client startup failed. Log:\n%s\n", clientLog.String())
		return BenchResult{}, err
	}

	// 5. Connect and Transfer
	clientMode := "send"
	if direction == "download" {
		clientMode = "recv"
	}
	res, err := RunClientWithResult(ctx, clientMode, fmt.Sprintf("127.0.0.1:%d", *clientPort), int64(*payloadMiB), *optChunkSize, *optPrefaceBytes)
	if err != nil {
		return BenchResult{}, err
	}

	select {
	case <-targetReceived:
	case <-time.After(15 * time.Second):
		return BenchResult{}, fmt.Errorf("target server did not confirm reception")
	}

	return BenchResult{
		Direction: direction,
		Elapsed:   res.Elapsed,
		Bytes:     res.Bytes,
		MiBps:     res.MiBps,
	}, nil
}

func startTargetServer(expectedBytes int64, direction string, targetReceived chan struct{}) (net.Listener, int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		defer close(targetReceived)
		serverMode := "sink"
		if direction == "download" {
			serverMode = "source"
		}
		RunServerWithListener(context.Background(), serverMode, ln, expectedBytes, *optChunkSize, *optPrefaceBytes)
	}()

	return ln, port, nil
}

type safeBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}

func (b *safeBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.String()
}

func persistRunLogs(direction string, runIndex int, serverLog, clientLog *safeBuffer) {
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return
	}
	if serverLog != nil {
		serverPath, _ := filepath.Abs(filepath.Join(runtimeDir, fmt.Sprintf("%s-run-%d-server.log", direction, runIndex)))
		_ = os.WriteFile(serverPath, []byte(serverLog.String()), 0644)
	}
	if clientLog != nil {
		clientPath, _ := filepath.Abs(filepath.Join(runtimeDir, fmt.Sprintf("%s-run-%d-client.log", direction, runIndex)))
		_ = os.WriteFile(clientPath, []byte(clientLog.String()), 0644)
	}
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			info, _ := os.Stat(path)
			if info.Size() > 0 {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for file: %s", path)
}

func waitForPattern(buf *safeBuffer, pattern string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), pattern) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for pattern: %s (in log segment)", pattern)
}

func printSummary(exfil, download []BenchResult) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("📊 StormDNS Benchmark Summary (Avg of %d runs)\n", *runs)
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("%-15s | %-12s | %-15s\n", "Direction", "Avg Time (s)", "Avg Speed (MiB/s)")
	fmt.Println(strings.Repeat("-", 60))

	if len(exfil) > 0 {
		avg := calcAvg(exfil)
		fmt.Printf("Exfil (Up)      | %-12.3f | %-15.3f\n", avg.Elapsed.Seconds(), avg.MiBps)
	}
	if len(download) > 0 {
		avg := calcAvg(download)
		fmt.Printf("Download (Down) | %-12.3f | %-15.3f\n", avg.Elapsed.Seconds(), avg.MiBps)
	}
	fmt.Println(strings.Repeat("=", 60))
}

func calcAvg(results []BenchResult) BenchResult {
	if len(results) == 0 {
		return BenchResult{}
	}
	var totalTime time.Duration
	var totalBytes int64
	for _, r := range results {
		totalTime += r.Elapsed
		totalBytes += r.Bytes
	}
	avgTime := totalTime / time.Duration(len(results))
	avgBytes := totalBytes / int64(len(results))
	return BenchResult{
		Elapsed: avgTime,
		Bytes:   avgBytes,
		MiBps:   (float64(avgBytes) / (1024 * 1024)) / avgTime.Seconds(),
	}
}

// Core Benchmarking Logic

func RunServer(ctx context.Context, mode, addr string, totalBytes int64, chunks, preface int) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	logEvent(BenchEvent{Timestamp: nowAsTs(), Event: "listening", Mode: mode, Peer: addr})
	return RunServerWithListener(ctx, mode, ln, totalBytes, chunks, preface)
}

func RunServerWithListener(ctx context.Context, mode string, ln net.Listener, totalBytes int64, chunks, preface int) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	peer := conn.RemoteAddr().String()
	logEvent(BenchEvent{Timestamp: nowAsTs(), Event: "accept", Peer: peer, Mode: mode})

	res, err := transfer(ctx, mode, conn, totalBytes, chunks, preface)
	if err != nil {
		return err
	}

	logEvent(BenchEvent{
		Timestamp:      nowAsTs(),
		Event:          "done",
		Mode:           mode,
		Bytes:          res.Bytes,
		Secs:           res.Elapsed.Seconds(),
		FirstPayloadTs: float64(res.Elapsed.Nanoseconds()), // Placeholder or actual start TS?
	})
	if *optMode != "" { // Only print summary in standalone mode
		fmt.Printf("server %s: bytes=%d secs=%.3f MiB/s=%.2f\n", mode, res.Bytes, res.Elapsed.Seconds(), res.MiBps)
	}
	return nil
}

func RunClient(ctx context.Context, mode, addr string, totalBytes int64, chunks, preface int) error {
	_, err := RunClientWithResult(ctx, mode, addr, totalBytes, chunks, preface)
	return err
}

func RunClientWithResult(ctx context.Context, mode, addr string, totalBytes int64, chunks, preface int) (BenchResult, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return BenchResult{}, err
	}
	defer conn.Close()
	logEvent(BenchEvent{Timestamp: nowAsTs(), Event: "connect", Peer: addr, Mode: mode})

	res, err := transfer(ctx, mode, conn, totalBytes, chunks, preface)
	if err != nil {
		return BenchResult{}, err
	}

	logEvent(BenchEvent{
		Timestamp: nowAsTs(),
		Event:     "done",
		Mode:      mode,
		Bytes:     res.Bytes,
		Secs:      res.Elapsed.Seconds(),
	})
	if *optMode != "" {
		fmt.Printf("client %s: bytes=%d secs=%.3f MiB/s=%.2f\n", mode, res.Bytes, res.Elapsed.Seconds(), res.MiBps)
	}
	return res, nil
}

func transfer(ctx context.Context, mode string, conn net.Conn, totalBytes int64, chunks, preface int) (BenchResult, error) {
	var start time.Time
	var total int64
	buf := make([]byte, chunks)
	for i := range buf {
		buf[i] = 'a'
	}

	// Handle preface
	if mode == "sink" || mode == "recv" {
		remainingPreface := int64(preface)
		for remainingPreface > 0 {
			toRead := int64(len(buf))
			if toRead > remainingPreface {
				toRead = remainingPreface
			}
			n, err := conn.Read(buf[:toRead])
			if err != nil {
				return BenchResult{}, err
			}
			remainingPreface -= int64(n)
		}
	} else { // source or send
		remainingPreface := int64(preface)
		for remainingPreface > 0 {
			toWrite := int64(len(buf))
			if toWrite > remainingPreface {
				toWrite = remainingPreface
			}
			n, err := conn.Write(buf[:toWrite])
			if err != nil {
				return BenchResult{}, err
			}
			remainingPreface -= int64(n)
		}
	}

	// Actual benchmark
	isSource := (mode == "source" || mode == "send")
	remaining := totalBytes
	lastProgress := totalBytes
	const progressInterval = 5 * 1024 * 1024 // 5 MiB
	for remaining > 0 {
		// Progress update
		if lastProgress-remaining >= progressInterval {
			fmt.Print(".")
			lastProgress = remaining
		}

		conn.SetDeadline(time.Now().Add(45 * time.Second))
		if isSource {
			toWrite := min(int64(len(buf)), remaining)
			if start.IsZero() {
				start = time.Now()
			}
			n, err := conn.Write(buf[:toWrite])
			if err != nil {
				return BenchResult{}, err
			}
			total += int64(n)
			remaining -= int64(n)
		} else {
			if start.IsZero() {
				start = time.Now()
			}
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return BenchResult{}, err
			}
			total += int64(n)
			remaining -= int64(n)
		}
	}

	elapsed := time.Since(start)
	if total == 0 {
		return BenchResult{}, fmt.Errorf("no data transferred")
	}

	// Special case: if exfil (sink mode at target), send ACK
	switch mode {
	case "sink":
		conn.Write([]byte("OK"))
	case "send":
		// Wait for ACK
		ack := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		conn.Read(ack)
	}

	return BenchResult{
		Elapsed: elapsed,
		Bytes:   total,
		MiBps:   (float64(total) / (1024 * 1024)) / elapsed.Seconds(),
	}, nil
}
