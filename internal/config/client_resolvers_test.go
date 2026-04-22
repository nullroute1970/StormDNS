// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientResolversSupportsIPCIDRAndPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
8.8.8.8
1.1.1.1:5353
192.168.10.0/30:5300
[2001:db8::1]:5400
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 5 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 5)
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected default port: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
	if resolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected custom port: got=%d want=%d", resolverMap["1.1.1.1"], 5353)
	}
	if resolverMap["192.168.10.1"] != 5300 || resolverMap["192.168.10.2"] != 5300 {
		t.Fatalf("unexpected cidr expansion map: %+v", resolverMap)
	}
	if resolverMap["2001:db8::1"] != 5400 {
		t.Fatalf("unexpected IPv6 port: got=%d want=%d", resolverMap["2001:db8::1"], 5400)
	}
}

func TestLoadClientResolversRejectsHugeCIDR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(path, []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if _, _, err := LoadClientResolvers(path); err == nil {
		t.Fatal("LoadClientResolvers should still fail when no valid resolvers remain")
	}
}

func TestLoadClientResolversDropsDuplicateIPsEvenWithDifferentPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
8.8.8.8:53
8.8.8.8:5353
8.8.8.8:53
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 1 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 1)
	}
	if resolvers[0].IP != "8.8.8.8" || resolvers[0].Port != 53 {
		t.Fatalf("unexpected resolver entry: %+v", resolvers[0])
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected resolver map port: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
}

func TestLoadClientResolversSkipsInvalidEntriesAndKeepsValidOnes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.txt")

	content := `
bad ip
8.8.8.8
10.0.0.0/8
1.1.1.1:5353
8.8.8.8:9999
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolvers, resolverMap, err := LoadClientResolvers(path)
	if err != nil {
		t.Fatalf("LoadClientResolvers returned error: %v", err)
	}

	if len(resolvers) != 2 {
		t.Fatalf("unexpected resolver count: got=%d want=%d", len(resolvers), 2)
	}
	if resolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected port for 8.8.8.8: got=%d want=%d", resolverMap["8.8.8.8"], 53)
	}
	if resolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected port for 1.1.1.1: got=%d want=%d", resolverMap["1.1.1.1"], 5353)
	}
}
