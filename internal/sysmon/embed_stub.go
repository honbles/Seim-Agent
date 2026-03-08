//go:build windows && !embed_sysmon

package sysmon

// getEmbeddedSysmon returns nil in the default build.
// Build with -tags embed_sysmon and place Sysmon64.exe in embed/
// to bundle the binary directly into the agent.
func getEmbeddedSysmon() []byte { return nil }
