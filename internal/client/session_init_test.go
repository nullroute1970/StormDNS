package client

import (
	"testing"

	"stormdns-go/internal/config"
)

func TestNextSessionInitAttemptUsesBalancerSnapshotConnection(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b")

	originalDomain := c.connections[0].Domain
	c.connections[0].Domain = "mutated.example.com"

	conn, _, _, err := c.nextSessionInitAttempt()
	if err != nil {
		t.Fatalf("nextSessionInitAttempt returned error: %v", err)
	}

	if conn.Domain != originalDomain {
		t.Fatalf("expected session init to use balancer snapshot domain %q, got %q", originalDomain, conn.Domain)
	}
}
