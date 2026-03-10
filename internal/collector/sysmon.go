//go:build windows

package collector

// sysmon.go — reads Sysmon events from the Microsoft-Windows-Sysmon/Operational
// event log channel and maps well-known Event IDs to enriched schema.Events.
//
// Sysmon must already be installed and running on the host.
// Ref: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"

	"obsidianwatch/agent/pkg/schema"
)

const sysmonChannel = "Microsoft-Windows-Sysmon/Operational"

const (
	SysmonProcessCreate        = 1
	SysmonNetworkConnect       = 3
	SysmonProcessTerminate     = 5
	SysmonDriverLoad           = 6
	SysmonImageLoad            = 7
	SysmonCreateRemoteThread   = 8
	SysmonRawAccessRead        = 9
	SysmonProcessAccess        = 10
	SysmonFileCreate           = 11
	SysmonRegistryCreate       = 12
	SysmonRegistrySetValue     = 13
	SysmonRegistryRename       = 14
	SysmonFileCreateStreamHash = 15
	SysmonPipeCreated          = 17
	SysmonPipeConnected        = 18
	SysmonDNSQuery             = 22
	SysmonFileDeleteDetected   = 23
)

type sysmonEventMeta struct {
	eventType schema.EventType
	severity  schema.Severity
	name      string
}

var sysmonMeta = map[uint32]sysmonEventMeta{
	SysmonProcessCreate:        {schema.EventTypeProcess, schema.SeverityLow, "ProcessCreate"},
	SysmonNetworkConnect:       {schema.EventTypeNetwork, schema.SeverityLow, "NetworkConnect"},
	SysmonProcessTerminate:     {schema.EventTypeProcess, schema.SeverityInfo, "ProcessTerminate"},
	SysmonDriverLoad:           {schema.EventTypeProcess, schema.SeverityHigh, "DriverLoad"},
	SysmonImageLoad:            {schema.EventTypeProcess, schema.SeverityLow, "ImageLoad"},
	SysmonCreateRemoteThread:   {schema.EventTypeProcess, schema.SeverityHigh, "CreateRemoteThread"},
	SysmonRawAccessRead:        {schema.EventTypeFile, schema.SeverityHigh, "RawAccessRead"},
	SysmonProcessAccess:        {schema.EventTypeProcess, schema.SeverityMedium, "ProcessAccess"},
	SysmonFileCreate:           {schema.EventTypeFile, schema.SeverityLow, "FileCreate"},
	SysmonRegistryCreate:       {schema.EventTypeRegistry, schema.SeverityLow, "RegistryCreate"},
	SysmonRegistrySetValue:     {schema.EventTypeRegistry, schema.SeverityMedium, "RegistrySetValue"},
	SysmonRegistryRename:       {schema.EventTypeRegistry, schema.SeverityMedium, "RegistryRename"},
	SysmonFileCreateStreamHash: {schema.EventTypeFile, schema.SeverityMedium, "FileCreateStreamHash"},
	SysmonPipeCreated:          {schema.EventTypeProcess, schema.SeverityLow, "PipeCreated"},
	SysmonPipeConnected:        {schema.EventTypeProcess, schema.SeverityLow, "PipeConnected"},
	SysmonDNSQuery:             {schema.EventTypeNetwork, schema.SeverityLow, "DNSQuery"},
	SysmonFileDeleteDetected:   {schema.EventTypeFile, schema.SeverityMedium, "FileDeleteDetected"},
}

// SysmonCollector wraps EventLogCollector restricted to the Sysmon channel.
type SysmonCollector struct {
	inner   *EventLogCollector
	agentID string
	host    string
	rawIn   chan schema.Event
	out     chan<- schema.Event
	logger  *slog.Logger
}

func NewSysmonCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *SysmonCollector {
	rawIn := make(chan schema.Event, 512)
	return &SysmonCollector{
		inner:   NewEventLogCollector([]string{sysmonChannel}, agentID, host, rawIn, logger),
		agentID: agentID,
		host:    host,
		rawIn:   rawIn,
		out:     out,
		logger:  logger,
	}
}

func (s *SysmonCollector) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.inner.Run(ctx) }()

	for {
		select {
		case <-ctx.Done():
			return <-errCh
		case ev := <-s.rawIn:
			enriched := s.mapSysmonEvent(ev)
			select {
			case s.out <- enriched:
			default:
				s.logger.Warn("sysmon: out channel full, dropping event")
			}
		}
	}
}

// wireEvent is the JSON structure stored by eventlog.go:
//
//	{"event_id":N, "channel":"...", "event_data":{"Image":"...","CommandLine":"...",...}}
type wireEvent struct {
	EventID   uint32            `json:"event_id"`
	Channel   string            `json:"channel"`
	Provider  string            `json:"provider"`
	RecordID  uint64            `json:"record_id"`
	Level     uint8             `json:"level"`
	EventData map[string]string `json:"event_data"`
}

// sysmonFirst returns the first non-empty value for the given keys from the event_data map.
func sysmonFirst(d map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(d[k]); v != "" && v != "-" {
			return v
		}
	}
	return ""
}

func sysmonParsePort(d map[string]string, key string) int {
	v := d[key]
	if v == "" { return 0 }
	p, _ := strconv.Atoi(v)
	return p
}

func sysmonParsePID(d map[string]string, key string) int {
	v := strings.TrimPrefix(d[key], "0x")
	if v == "" { return 0 }
	// Try hex first, then decimal
	if i, err := strconv.ParseInt(v, 16, 64); err == nil { return int(i) }
	i, _ := strconv.Atoi(d[key])
	return i
}

// lastName returns the filename component of a Windows path.
func sysmonLastName(path string) string {
	if path == "" { return "" }
	path = strings.ReplaceAll(path, "\\", "/")
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

// mapSysmonEvent extracts fields from the event_data map that eventlog.go already
// parsed from the Windows XML. The raw JSON is {"event_data":{"Image":"..."},...}.
func (s *SysmonCollector) mapSysmonEvent(ev schema.Event) schema.Event {
	// Decode the wire format written by eventlog.go
	var wire wireEvent
	if err := json.Unmarshal(ev.Raw, &wire); err != nil || wire.EventData == nil {
		// Fallback: pass through with Sysmon type
		ev.EventType = schema.EventTypeSysmon
		ev.Source = "Sysmon"
		return ev
	}
	d := wire.EventData

	meta, ok := sysmonMeta[ev.EventID]
	if !ok {
		ev.EventType = schema.EventTypeSysmon
		ev.Source = "Sysmon"
		return ev
	}

	// Build enriched raw payload with all Sysmon fields for backend storage
	enrichedRaw := map[string]interface{}{
		"event_id":   ev.EventID,
		"event_name": meta.name,
		"source":     "Sysmon",
		"event_data": d,
	}
	rawBytes, _ := json.Marshal(enrichedRaw)

	out := schema.Event{
		Time:      ev.Time,
		AgentID:   s.agentID,
		Host:      s.host,
		OS:        "windows",
		EventType: meta.eventType,
		Severity:  meta.severity,
		Source:    "Sysmon",
		EventID:   ev.EventID,
		Channel:   sysmonChannel,
		Raw:       rawBytes,
	}

	// ── Process fields (all event types that have a subject process) ──────
	image := sysmonFirst(d, "Image", "NewProcessName", "ProcessName")
	out.ProcessName = sysmonLastName(image)
	out.ImagePath   = image
	out.CommandLine = sysmonFirst(d, "CommandLine")
	out.UserName    = sysmonFirst(d, "User", "SubjectUserName", "TargetUserName")
	out.PID         = sysmonParsePID(d, "ProcessId")
	out.PPID        = sysmonParsePID(d, "ParentProcessId")

	// ── Per event-type field extraction ───────────────────────────────────
	switch ev.EventID {

	case SysmonProcessCreate: // Event 1
		out.CommandLine  = sysmonFirst(d, "CommandLine")
		out.ImagePath    = sysmonFirst(d, "Image")
		out.ProcessName  = sysmonLastName(out.ImagePath)
		out.FileHash     = sysmonFirst(d, "Hashes")

	case SysmonNetworkConnect: // Event 3
		out.DstIP   = sysmonFirst(d, "DestinationIp", "DestinationHostname")
		out.SrcIP   = sysmonFirst(d, "SourceIp")
		out.DstPort = sysmonParsePort(d, "DestinationPort")
		out.SrcPort = sysmonParsePort(d, "SourcePort")
		out.Proto   = sysmonFirst(d, "Protocol")

	case SysmonDNSQuery: // Event 22
		out.DstIP      = sysmonFirst(d, "QueryName")
		out.EventType  = schema.EventTypeDNS

	case SysmonFileCreate, SysmonRawAccessRead, SysmonFileCreateStreamHash, SysmonFileDeleteDetected: // 11,9,15,23
		out.FilePath = sysmonFirst(d, "TargetFilename", "Device")
		out.FileHash = sysmonFirst(d, "Hash", "Hashes")

	case SysmonRegistryCreate, SysmonRegistrySetValue, SysmonRegistryRename: // 12,13,14
		out.RegKey   = sysmonFirst(d, "TargetObject")
		out.RegValue = sysmonFirst(d, "Details", "NewName")

	case SysmonImageLoad: // Event 7
		out.FilePath  = sysmonFirst(d, "ImageLoaded")
		out.FileHash  = sysmonFirst(d, "Hashes")

	case SysmonCreateRemoteThread: // Event 8
		out.DstIP = sysmonFirst(d, "TargetImage") // abuse dst for target process

	case SysmonProcessAccess: // Event 10
		out.DstIP = sysmonFirst(d, "TargetImage")
	}

	return out
}
