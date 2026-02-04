// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package BPF

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	kwlog "KubeWard/log"
	kwtypes "KubeWard/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type default_context -type file_opration_context -type process_management_context -type network_opration_context ringbuffer ./cfile/monitor.c

// Syscall category constants matching the C enum syscall_category in monitor.c.
const (
	FILE_OPERATION            = 0
	NETWORK_OPERATION         = 1
	PROCESS_MANAGEMENT        = 2
	FILE_DESCRIPTOR           = 3
	MEMORY_MANAGEMENT         = 4
	SIGNALS                   = 5
	TIMERS                    = 6
	USER_AND_GROUP_MANAGEMENT = 7
	SYSTEM_INFORMATION        = 8
)

// Buffer size constants matching the C #define values.
const (
	TaskCommLen      = 16
	DirNameLen       = 4096
	FileNameLen      = 256
	ExePathLen       = 256
	SystemNameLen    = 80
	KernelVersionLen = 80
)

// EventHeader matches the C struct default_context.
type EventHeader struct {
	Ts        uint64
	PidNs     uint32
	MntNs     uint32
	HostPpid  uint32
	HostPid   uint32
	Ppid      uint32
	Pid       uint32
	Uid       uint32
	SyscallId uint32
	EventType uint32
	_         uint32
	RetValue  int64
	Comm      [TaskCommLen]int8
}

// FileOpEvent matches the C struct file_opration_context.
type FileOpEvent struct {
	Header   EventHeader
	Dirname  [DirNameLen]int8
	Filename [FileNameLen]int8
}

// NetworkOpEvent matches the C struct network_opration_context.
type NetworkOpEvent struct {
	Header   EventHeader
	DestIpv4 uint32
	DestPort uint16
	_        [2]byte
}

// ProcessMgmtEvent matches the C struct process_management_context.
type ProcessMgmtEvent struct {
	Header  EventHeader
	ExePath [ExePathLen]int8
	Dirname [DirNameLen]int8
}

// FdEvent matches the C struct file_descriptor_context.
type FdEvent struct {
	Header  EventHeader
	ExePath [ExePathLen]int8
	OldFd   uint32
	NewFd   uint32
}

// MemoryEvent matches the C struct memory_management_context.
type MemoryEvent struct {
	Header EventHeader
	Size   uint64
}

// SignalsEvent matches the C struct signals_context.
type SignalsEvent struct {
	Header    EventHeader
	Signum    uint32
	SenderPid uint32
	TargetPid uint32
	_         uint32
}

// TimersEvent matches the C struct timers_context.
type TimersEvent struct {
	Header EventHeader
}

// UserGroupEvent matches the C struct user_and_group_management_context.
type UserGroupEvent struct {
	Header EventHeader
}

// SysInfoEvent matches the C struct system_information_context.
type SysInfoEvent struct {
	Header        EventHeader
	SystemName    [SystemNameLen]int8
	KernelVersion [KernelVersionLen]int8
}

// MonitorHandlerType manages the eBPF monitoring lifecycle.
type MonitorHandlerType struct {
	NsToContainer map[kwtypes.NsKey]kwtypes.Container
	nsLock        sync.RWMutex

	VisibilityMap *ebpf.Map

	object ringbufferObjects

	kprobeProgram    []*ebpf.Program
	kretprobeProgram []*ebpf.Program

	kprobeLinker []link.Link
	kprobeReader *ringbuf.Reader
	kprobeRecord chan ringbuf.Record

	kretprobeLinker []link.Link
	kretprobeReader *ringbuf.Reader
	kretprobeRecord chan ringbuf.Record
}

// MonitorH is the global eBPF monitor handler instance.
var (
	MonitorH MonitorHandlerType
)

// IniteBPF loads eBPF objects, creates ring buffer readers, and starts event processing.
func (ch *MonitorHandlerType) IniteBPF(stopCh chan struct{}) error {
	var err error
	MonitorH.NsToContainer = make(map[kwtypes.NsKey]kwtypes.Container)

	if err = rlimit.RemoveMemlock(); err != nil {
		kwlog.Errf("MonitorHandler: fail to remove memory lock: %s", err)
	}

	MonitorH.object = ringbufferObjects{}
	if err = loadRingbufferObjects(&MonitorH.object, nil); err != nil {
		kwlog.Errf("MonitorHandler: fail to load and assgin: %s", err)
	}

	MonitorH.VisibilityMap = MonitorH.object.ContainerMap

	makeReader()
	geteBPFProgram()

	go readRecords(MonitorH.kprobeReader, MonitorH.kprobeRecord)
	go readRecords(MonitorH.kretprobeReader, MonitorH.kretprobeRecord)

	go showKprobeEvent(MonitorH.kprobeRecord)
	go showKretprobeEvent(MonitorH.kretprobeRecord)

	<-stopCh
	cleanup()

	return nil
}

// makeReader creates ring buffer readers and event channels.
func makeReader() {
	var err error

	if MonitorH.kprobeReader, err = ringbuf.NewReader(MonitorH.object.KprobeMap); err != nil {
		kwlog.Errf("MonitorHandler: fail to make new reader : %s", err)
	}
	if MonitorH.kretprobeReader, err = ringbuf.NewReader(MonitorH.object.KretprobeMap); err != nil {
		kwlog.Errf("MonitorHandler: fail to make new reader : %s", err)
	}
	MonitorH.kprobeRecord = make(chan ringbuf.Record)
	MonitorH.kretprobeRecord = make(chan ringbuf.Record)
}

// geteBPFProgram discovers all kprobe and kretprobe programs from loaded eBPF objects.
func geteBPFProgram() {
	MonitorH.kprobeProgram = []*ebpf.Program{}
	MonitorH.kretprobeProgram = []*ebpf.Program{}

	v := reflect.ValueOf(MonitorH.object)
	v = reflect.Indirect(v)
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)

		if field.Kind() == reflect.Struct {
			field = reflect.Indirect(field)
			for j := 0; j < field.NumField(); j++ {
				subField := field.Field(j)
				if subField.Kind() == reflect.Ptr && subField.Elem().Type() == reflect.TypeOf(ebpf.Program{}) {
					prog, ok := subField.Interface().(*ebpf.Program)
					if !ok || prog == nil {
						continue
					}

					fieldName := field.Type().Field(j).Name
					if len(fieldName) >= 9 && fieldName[:9] == "KprobeX64" {
						MonitorH.kprobeProgram = append(MonitorH.kprobeProgram, prog)
					} else if len(fieldName) >= 12 && fieldName[:12] == "KretprobeX64" {
						MonitorH.kretprobeProgram = append(MonitorH.kretprobeProgram, prog)
					}
				}
			}
		}
	}
}

// readRecords continuously reads events from an eBPF ring buffer.
func readRecords(reader *ringbuf.Reader, c chan ringbuf.Record) {
	for {
		record, err := reader.Read()
		if err != nil {
			kwlog.Printf("MonitorHandler: fail to read: %s", err)
			close(c)
			return
		}
		c <- record
	}
}

// parseEventHeader reads only the EventHeader from raw bytes.
func parseEventHeader(raw []byte) (EventHeader, error) {
	var header EventHeader
	headerSize := int(unsafe.Sizeof(header))
	if len(raw) < headerSize {
		return header, fmt.Errorf("raw sample too small for header: got %d, need %d", len(raw), headerSize)
	}
	err := binary.Read(bytes.NewReader(raw[:headerSize]), binary.LittleEndian, &header)
	return header, err
}

// eventTypeName converts a syscall category constant to a human-readable string.
func eventTypeName(eventType uint32) string {
	switch eventType {
	case FILE_OPERATION:
		return "File Operations"
	case NETWORK_OPERATION:
		return "Network Operations"
	case PROCESS_MANAGEMENT:
		return "Process Management"
	case FILE_DESCRIPTOR:
		return "File Descriptor Operations"
	case MEMORY_MANAGEMENT:
		return "Memory Management"
	case SIGNALS:
		return "Signals"
	case TIMERS:
		return "Timers"
	case USER_AND_GROUP_MANAGEMENT:
		return "User and Group Management"
	case SYSTEM_INFORMATION:
		return "System Information"
	default:
		return "Unknown"
	}
}

// showKprobeEvent processes kprobe events from the ring buffer channel.
func showKprobeEvent(kprobeChannel chan ringbuf.Record) {
	for {
		select {
		case record, ok := <-kprobeChannel:
			if !ok {
				return
			}

			header, err := parseEventHeader(record.RawSample)
			if err != nil {
				kwlog.Printf("MonitorHandler: fail to read kprobe header: %s, data: %v\n", err, record.RawSample)
				continue
			}

			kwlog.Printf("[Kprobe] => ")
			showProbeEvent(header)

			showCategoryDetails(header.EventType, record.RawSample)
		}
	}
}

// showKretprobeEvent processes kretprobe events from the ring buffer channel.
func showKretprobeEvent(kretprobeChannel chan ringbuf.Record) {
	for {
		select {
		case record, ok := <-kretprobeChannel:
			if !ok {
				return
			}

			header, err := parseEventHeader(record.RawSample)
			if err != nil {
				kwlog.Printf("MonitorHandler: fail to read kretprobe header: %s, data: %v\n", err, record.RawSample)
				continue
			}

			kwlog.Printf("[Kretprobe] => ")
			showProbeEvent(header)
			kwlog.Printf("  RetValue: %d\n", header.RetValue)

			showCategoryDetails(header.EventType, record.RawSample)
		}
	}
}

// showCategoryDetails parses and logs category-specific event details.
func showCategoryDetails(eventType uint32, raw []byte) {
	switch eventType {
	case FILE_OPERATION:
		var event FileOpEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err == nil {
			filename := intArrayToString(event.Filename[:])
			dirname := intArrayToString(event.Dirname[:])
			if filename != "" {
				kwlog.Printf("  File: %s", filename)
			}
			if dirname != "" {
				kwlog.Printf("  Dir: %s", dirname)
			}
			fmt.Println()
		}
	case NETWORK_OPERATION:
		var event NetworkOpEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err == nil {
			destIpv4 := intToIPString(event.DestIpv4)
			kwlog.Printf("  DestIPv4: %s, DestPort: %d\n", destIpv4, event.DestPort)
		}
	case PROCESS_MANAGEMENT:
		var event ProcessMgmtEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err == nil {
			exePath := intArrayToString(event.ExePath[:])
			dirname := intArrayToString(event.Dirname[:])
			if exePath != "" {
				kwlog.Printf("  ExePath: %s", exePath)
			}
			if dirname != "" {
				kwlog.Printf("  Dir: %s", dirname)
			}
			fmt.Println()
		}
	case FILE_DESCRIPTOR:
		var event FdEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err == nil {
			kwlog.Printf("  OldFd: %d, NewFd: %d\n", event.OldFd, event.NewFd)
		}
	case MEMORY_MANAGEMENT:
		var event MemoryEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err == nil {
			kwlog.Printf("  Size: %d\n", event.Size)
		}
	case SIGNALS:
		var event SignalsEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err == nil {
			kwlog.Printf("  Signum: %d, SenderPid: %d, TargetPid: %d\n", event.Signum, event.SenderPid, event.TargetPid)
		}
	case SYSTEM_INFORMATION:
		var event SysInfoEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err == nil {
			sysName := intArrayToString(event.SystemName[:])
			kernelVer := intArrayToString(event.KernelVersion[:])
			if sysName != "" {
				kwlog.Printf("  SystemName: %s", sysName)
			}
			if kernelVer != "" {
				kwlog.Printf("  KernelVersion: %s", kernelVer)
			}
			fmt.Println()
		}
	default:
		fmt.Println()
	}
}

// showProbeEvent logs the common header information for both kprobe and kretprobe events.
func showProbeEvent(header EventHeader) {
	nskey := kwtypes.NsKey{PidNs: header.PidNs, MntNs: header.MntNs}
	commStr := intArrayToString(header.Comm[:])

	MonitorH.nsLock.RLock()
	container := MonitorH.NsToContainer[nskey]
	MonitorH.nsLock.RUnlock()

	kwlog.Printf("MonitorHandler: ContainerID: %s, Name: %s, Namespace: %s\n PidId: %d MntId: %d HostPpid: %d HostPid: %d Ppid: %d Pid: %d Uid: %d SyscallId: %d, eventType: %s, Comm: %s\n",
		container.ContainerID, container.ContainerName, container.NamespaceName,
		header.PidNs, header.MntNs, header.HostPpid, header.HostPid, header.Ppid, header.Pid, header.Uid, header.SyscallId, eventTypeName(header.EventType), commStr)
}

// intArrayToString converts a null-terminated int8 array to a Go string.
func intArrayToString(arr []int8) string {
	bytes := make([]byte, len(arr))
	for i, b := range arr {
		bytes[i] = byte(b)
	}
	n := 0
	for n < len(bytes) && bytes[n] != 0 {
		n++
	}
	return string(bytes[:n])
}

// intToIPString converts a uint32 IPv4 address to dotted-decimal string.
func intToIPString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// AttacheBPFProgram detaches existing probes and attaches new ones based on CRD spec.
func (ch *MonitorHandlerType) AttacheBPFProgram(resource kwtypes.MyResourceSpec) {
	ch.DetacheBPFProgram()
	linkKprobe(resource.Kprobe)
	linkKretprobe(resource.Kretprobe)
}

// DetacheBPFProgram detaches all currently active kprobe and kretprobe links.
func (ch *MonitorHandlerType) DetacheBPFProgram() {
	if MonitorH.kprobeLinker != nil {
		for _, link := range MonitorH.kprobeLinker {
			if err := link.Close(); err != nil {
				kwlog.Printf("MonitorHandler: Failed to detach Kprobe link: %v\n", err)
			} else {
				kwlog.Printf("MonitorHandler: Successfully detached Kprobe link\n")
			}
		}
		MonitorH.kprobeLinker = nil
	}

	if MonitorH.kretprobeLinker != nil {
		for _, link := range MonitorH.kretprobeLinker {
			if err := link.Close(); err != nil {
				kwlog.Printf("MonitorHandler: Failed to detach Kretprobe link: %v\n", err)
			} else {
				kwlog.Printf("MonitorHandler: Successfully detached Kretprobe link\n")
			}
		}
		MonitorH.kretprobeLinker = nil
	}
}

// linkKprobe attaches kprobe programs to the specified syscall entry points.
func linkKprobe(probes []kwtypes.Kprobe) {
	for _, probe := range probes {
		program, exists := getKprobeProgram(probe.Name)
		if !exists {
			kwlog.Printf("MonitorHandler: Program %s not found\n", probe.Name)
			continue
		}
		kprobeLink, err := link.Kprobe(probe.Name, program, nil)
		if err != nil {
			kwlog.Printf("MonitorHandler: Failed to link program %s: %v\n", probe.Name, err)
		} else {
			MonitorH.kprobeLinker = append(MonitorH.kprobeLinker, kprobeLink)
			kwlog.Printf("MonitorHandler: Successfully linked program %s\n", probe.Name)
		}
	}
}

// getKprobeProgram finds a kprobe program by syscall name.
func getKprobeProgram(name string) (*ebpf.Program, bool) {
	name = "kprobe___x64_" + name
	for _, prog := range MonitorH.kprobeProgram {
		if prog != nil && getProgramName(prog) == name {
			return prog, true
		}
	}
	return nil, false
}

// linkKretprobe attaches kretprobe programs to the specified syscall exit points.
func linkKretprobe(probes []kwtypes.Kretprobe) {
	for _, probe := range probes {
		program, exists := getKretprobeProgram(probe.Name)
		if !exists {
			kwlog.Printf("MonitorHandler: Program %s not found\n", probe.Name)
			continue
		}
		kretprobeLink, err := link.Kretprobe(probe.Name, program, nil)
		if err != nil {
			kwlog.Printf("MonitorHandler: Failed to link program %s: %v\n", probe.Name, err)
		} else {
			MonitorH.kretprobeLinker = append(MonitorH.kretprobeLinker, kretprobeLink)
			kwlog.Printf("MonitorHandler: Successfully linked program %s\n", probe.Name)
		}
	}
}

// getKretprobeProgram finds a kretprobe program by syscall name.
func getKretprobeProgram(name string) (*ebpf.Program, bool) {
	name = "kretprobe___x64_" + name

	for _, prog := range MonitorH.kretprobeProgram {
		if prog != nil && getProgramName(prog) == name {
			return prog, true
		}
	}
	return nil, false
}

// getProgramName extracts the program name from the eBPF program string representation.
func getProgramName(prog *ebpf.Program) string {
	name := prog.String()
	start := strings.Index(name, "(")
	end := strings.Index(name, ")")
	if start != -1 && end != -1 && end > start {
		return name[start+1 : end]
	}
	return name
}

// AddNsToContainer registers a container in both the Go-side map and the eBPF container_map.
func AddNsToContainer(nsKey kwtypes.NsKey, container kwtypes.Container) {
	MonitorH.nsLock.Lock()
	MonitorH.NsToContainer[nsKey] = container
	MonitorH.nsLock.Unlock()

	if err := MonitorH.VisibilityMap.Put(nsKey, uint16(1)); err != nil {
		kwlog.Printf("MonitorHandler: MonitorHandler: cannot insert insert visibility map into kernel nskey=%+v, error=%s\n", nsKey, err)
	}
	kwlog.Printf("MonitorHandler: MonitorHandler: successfully added visibility map with key=%+v to the kernel\n\n", nsKey)
}

// DeleteNsToContainer removes a container from both the Go-side map and the eBPF container_map.
func DeleteNsToContainer(nsKey kwtypes.NsKey) {
	MonitorH.nsLock.Lock()
	delete(MonitorH.NsToContainer, nsKey)
	MonitorH.nsLock.Unlock()

	if err := MonitorH.VisibilityMap.Delete(nsKey); err != nil {
		kwlog.Printf("MonitorHandler: MonitorHandler: cannot delete visibility map from kernel nskey=%+v, error=%s\n", nsKey, err)
	}
	kwlog.Printf("MonitorHandler: MonitorHandler: successfully deleted visibility map with key=%+v from the kernel\n\n", nsKey)
}

// cleanup performs graceful shutdown of the eBPF monitoring system.
func cleanup() {
	MonitorH.DetacheBPFProgram()

	if MonitorH.kprobeReader != nil {
		MonitorH.kprobeReader.Close()
	}
	if MonitorH.kretprobeReader != nil {
		MonitorH.kretprobeReader.Close()
	}

	MonitorH.object.Close()

	kwlog.Printf("MonitorHandler: cleanup done")
}
