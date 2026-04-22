// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

// CalculateMaxPackedBlocks calculates the optimal number of control blocks that can be
// packed into a single VPN packet based on the MTU, a safety percentage, and an absolute maximum.
// Each packed control block is 7 bytes: Type(1) + StreamID(2) + SeqNum(2) + FragID(1) + TotalFragments(1).
func CalculateMaxPackedBlocks(mtu int, percent int, absoluteMax int) int {

	mtu = max(mtu, 1)
	percent = max(percent, 30)
	effectiveSize := (mtu * percent) / 100
	count := max(min(max(effectiveSize/PackedControlBlockSize, 1), absoluteMax), 1)
	return count
}
