//go:build windows && embed_sysmon

package sysmon

import _ "embed"

//go:embed embed/Sysmon64.exe
var sysmonBinary []byte

// getEmbeddedSysmon returns the bundled Sysmon64.exe bytes.
func getEmbeddedSysmon() []byte { return sysmonBinary }
