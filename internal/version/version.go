// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package version

import "strings"

// BuildVersion is set at link-time using -ldflags "-X stormdns-go/internal/version.BuildVersion=..."
var BuildVersion = "dev"

// GetVersion returns the current build version.
func GetVersion() string {
	v := strings.TrimSpace(BuildVersion)
	if v == "" {
		return "dev"
	}
	return v
}
