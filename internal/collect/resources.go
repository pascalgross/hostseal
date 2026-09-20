package collect

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// loadBandPercent is the granularity CPU load is reported at, in percentage points.
//
// It is a bandwidth decision rather than a measurement one. docs/PROTOCOL.md §4.1 makes the steady-state
// heartbeat a digest, and a digest saves nothing on a section that is never twice the same — so a CPU
// figure reported to the nearest percentage point would put every host in every fleet into a full report
// on every beat, which §4.1 calls a production incident rather than an inefficiency. What it costs is
// the difference between a host at 31% and one at 34%, which is not a difference anybody acts on at
// fleet scale.
//
// The band alone is not enough, and that is why loadWindowField exists beside it. Five percentage points
// of one processor is five hundredths of a load average, which the *one-minute* figure crosses between
// any two heartbeats on a single-vCPU machine — the commonest machine in a fleet. Banding a number that
// noisy is a band that never holds.
const loadBandPercent = 5

// loadWindowField is which of /proc/loadavg's three averages is reported: the fifteen-minute one.
//
// The heartbeat is a minute apart, so the one-minute average is very nearly an independent sample on
// each beat and the fifteen-minute one is very nearly the same sample — which is the difference between
// a section that re-digests constantly and one that holds still. It is also the better answer to the
// question actually being asked. "Which host is not keeping up" is about sustained load; a machine that
// was busy for ninety seconds is not a fleet problem, and a low-frequency snapshot has no business
// pretending to catch one.
const loadWindowField = 2

// memoryBandPercent is the granularity memory use is reported at, in percentage points.
//
// Separate from loadBandPercent even though it holds the same value, because the two are the same
// number for different reasons and one of them may need to move. Memory is banded for the digest reason
// above and for a second one: MemAvailable moves by hundreds of megabytes on an idle machine as the page
// cache breathes, so whole percentage points on an eight-gigabyte host would change on nearly every
// read while saying nothing an operator would act on.
const memoryBandPercent = 5

// filesystemBandPercent is the granularity filesystem use is reported at, in percentage points.
//
// One, unlike the two above, and the asymmetry is deliberate. A disk is the resource that fills slowly
// and then matters suddenly, and the distance between 90% and 94% is the distance between "next month"
// and "tonight" — banding that to five would hide exactly the movement worth seeing. It costs nothing on
// the digest, because a percentage point of a root filesystem is gigabytes: the number is already stable
// across a heartbeat on any host that is not actively filling up, and a host that *is* actively filling
// up is one whose full report is worth the bytes.
const filesystemBandPercent = 1

// bytesPerGiB is the unit per-interface traffic counters are reported in.
//
// Interface byte counters are monotonic and move on every packet, so reporting them in bytes would make
// this section change on literally every read on any host that is doing anything — the one shape the
// digest can never survive. A gibibyte is coarse on purpose: at a sustained megabyte a second the
// counter advances about once every seventeen minutes, so a busy host sends a handful of full reports an
// hour rather than one per beat, and an idle host sends none. The counters stay monotonic, so a control
// plane that wants a rate differences two reports and divides by the interval between them — which is
// the same low-frequency snapshot the rest of this package is, rather than the time series README.md
// says HostSeal is not.
const bytesPerGiB = 1 << 30

// kibibyte is the unit /proc/meminfo expresses its values in.
//
// Named rather than written inline for the reason clockTicksPerSecond is: every value in that file
// carries a `kB` suffix which is really a kibibyte, and getting the factor wrong scales every memory
// figure by 1024 — which reads as a host with eight terabytes of RAM rather than as a units bug, and
// looks plausible enough on a graph that nobody checks.
const kibibyte = 1024

// virtualFilesystems are the filesystem types that are not a disk and are therefore not reported.
//
// It is a denylist rather than an allowlist of real filesystems, and that direction is the safe one
// here: a new real filesystem type appearing in a fleet — bcachefs, say — is then reported by default
// rather than silently omitted, and an omission is the failure this package spends most of its comments
// trying not to ship. Every entry is either a kernel interface with no storage behind it, or storage
// that cannot fill in a way an operator can act on.
//
// Two entries are worth naming. `squashfs` covers snap mounts, of which an Ubuntu desktop has dozens and
// every one of them reports itself permanently one hundred per cent full, because that is what a
// read-only image is. `overlay` covers the per-container upper layers on a Docker host, which are the
// container's business and are already counted inside the filesystem they sit on.
var virtualFilesystems = map[string]bool{
	"autofs": true, "bpf": true, "binfmt_misc": true, "cgroup": true, "cgroup2": true,
	"configfs": true, "debugfs": true, "devpts": true, "devtmpfs": true, "efivarfs": true,
	"fusectl": true, "hugetlbfs": true, "mqueue": true, "nsfs": true,
	"overlay": true, "proc": true, "pstore": true, "ramfs": true, "securityfs": true,
	"squashfs": true, "sysfs": true, "tmpfs": true, "tracefs": true,
}

// remoteFilesystems are the filesystem types this agent will not ask the kernel about.
//
// **This list exists to keep one stale mount from stopping a fleet agent for ever, and that is not a
// figure of speech.** `statfs(2)` on a hard-mounted NFS share whose server has gone away does not return
// an error: it blocks in uninterruptible sleep, where no context, no timeout and not even SIGKILL
// reaches it. The scan runs inside the heartbeat, so a single such mount would wedge the heartbeat loop
// and the job poll behind it — and the host would drop off the fleet list, which is the one outcome
// internal/collect/facts.go's whole design is arranged to prevent. Nothing in HostSeal probed an
// arbitrary mount point until this collector existed, so this hazard arrived with it.
//
// Bounding the call instead was considered and is worse. A goroutine with a timeout does not cancel the
// syscall, it abandons it: the thread stays blocked for the life of the process, and one more leaks on
// every heartbeat until the runtime's thread limit kills the agent — a crash on a timer in place of a
// hang, on hosts that are already having a bad day.
//
// Refusing to look costs little, because the question was never really this host's. How full a network
// share is belongs to the machine serving it, which is a host HostSeal can manage on its own account.
// A skipped mount is named in ResourceReport.Note rather than silently absent.
var remoteFilesystems = map[string]bool{
	"9p": true, "afs": true, "beegfs": true, "ceph": true, "cifs": true, "coda": true,
	"davfs": true, "gfs2": true, "glusterfs": true, "lustre": true, "ncpfs": true, "nfs": true,
	"nfs4": true, "ocfs2": true, "orangefs": true, "smb3": true, "smbfs": true,
}

// fusePrefix marks a filesystem served by a userspace daemon.
//
// Every one of them is refused, for the reason the remote list is: when the daemon dies, its mount point
// stops answering and a call into it blocks the same way a dead NFS server does. The cost is that a
// local FUSE filesystem somebody relies on — ntfs-3g, mergerfs — is not reported either, and that is the
// right side of the trade: a gap in a disk report is visible and survivable, and a wedged agent is
// neither.
const fusePrefix = "fuse."

// refusedFilesystem reports whether a filesystem type is one this collector will not measure.
//
// It exists so that the two reasons stay two reasons. A virtual filesystem is skipped because there is
// no disk behind it to fill up; a remote or userspace one is skipped because asking can hang this
// process for ever. Folding them into one map would leave a reader to guess which sentence applies to
// which entry, and the second sentence is the one somebody must not delete by accident.
func refusedFilesystem(fsType string) (refused, remote bool) {
	switch {
	case remoteFilesystems[fsType], strings.HasPrefix(fsType, fusePrefix):
		return true, true
	case virtualFilesystems[fsType]:
		return true, false
	default:
		return false, false
	}
}

// sandboxedMountPoints are the paths the agent's own systemd sandbox replaces with an empty filesystem.
//
// `ProtectHome=yes` and `PrivateTmp=yes` in packaging/hostseal-agent.service give this process a mount
// namespace in which these three are empty and virtual, whatever the host has underneath. Without this
// list the collector would skip them as virtual and report nothing, which is a host whose separate
// `/home` partition is simply missing from its own disk report — a plausible answer arrived at by not
// looking, which is the failure this whole package is written against. Naming them lets the report say
// so in words instead.
var sandboxedMountPoints = map[string]bool{
	"/home": true, "/root": true, "/tmp": true, "/var/tmp": true,
}

// Filesystem is one mounted filesystem's capacity and how much of it is gone.
type Filesystem struct {
	// Device is the mount source, such as "/dev/vda1" or a UUID for a filesystem mounted by one.
	//
	// It is reported beside the mount point rather than instead of it because the two answer different
	// questions: an operator reads the mount point and acts on the device, and a fleet where three hosts
	// report "/" needs the device to tell which disk to grow.
	Device string `json:"device,omitempty"`

	// MountPoint is where the filesystem is mounted, as this agent's mount namespace sees it.
	//
	// The namespace qualifier is not pedantry; see ResourceReport.Note. It is also the reason this field
	// exists at all despite internal/collect/containers.go deliberately refusing to report host paths
	// from mountinfo. That refusal is about paths disclosed as a side effect of asking a different
	// question, and it stands. Here the path *is* the question: "which host is about to run out of disk"
	// has no useful answer that does not name the filesystem, and a bare percentage would be a number
	// nobody could act on.
	MountPoint string `json:"mountPoint"`

	// Type is the filesystem type, such as "ext4" or "xfs".
	Type string `json:"type,omitempty"`

	// SizeBytes is the total capacity.
	//
	// It changes only when somebody resizes the disk, which is what makes it the half of this struct the
	// digest-first design is happy with, and it is reported exactly rather than banded for the same
	// reason.
	SizeBytes int64 `json:"sizeBytes"`

	// UsedPercent is how full it is, rounded down to filesystemBandPercent.
	//
	// The denominator is df's — used over used-plus-*available*, not used over total — because the two
	// differ by the root reserve, and a fleet dashboard that disagreed with the command an operator is
	// about to run is a dashboard they check once. On a default ext4 that reserve is five per cent of the
	// disk, which is the difference between this reading 95% and 100%.
	//
	// The rounding is not df's, and the one point of difference is worth stating rather than discovering.
	// df rounds the percentage **up**; every figure in this report rounds **down**, so a disk df calls 22%
	// full reads 21 here. Down is the right direction for a number somebody sets an alert on — a host
	// reported at 90 is never more than 94 — and matching df's direction would mean this one field
	// disagreed with the four beside it.
	UsedPercent int `json:"usedPercent"`

	// InodesUsedPercent is how many inodes are gone, rounded the same way, absent where the filesystem
	// has no fixed inode count.
	//
	// It is here because running out of inodes on a filesystem with free space is the disk-full failure
	// that takes longest to diagnose: everything reports space available and nothing can be written. It
	// is absent rather than zero on btrfs and xfs, which allocate inodes dynamically and report no total
	// — and absent means "this filesystem cannot run out that way", which is a different claim from
	// "none are used".
	InodesUsedPercent *int `json:"inodesUsedPercent,omitempty"`
}

// InterfaceTraffic is one network interface's counters since boot.
//
// It is keyed by the same Name the network collector reports, and the two sections are deliberately
// separate: `extra.network` is configuration and changes when somebody changes it, `extra.resources` is
// use and changes on its own. Putting the counters in the configuration section would have made an
// ungated section volatile, and a host would have had no way to refuse the churn.
type InterfaceTraffic struct {
	// Name is the kernel's name for the interface, matching extra.network's entry for it.
	Name string `json:"name"`

	// ReceivedGiB is whole gibibytes received since boot; see bytesPerGiB for why the unit is coarse.
	ReceivedGiB int64 `json:"receivedGiB"`

	// TransmittedGiB is whole gibibytes transmitted since boot.
	TransmittedGiB int64 `json:"transmittedGiB"`

	// ReceiveErrors is the receive error counter.
	//
	// **These four counters are the exception to the banding, and the exception is stated rather than
	// glossed over.** They are reported exactly, so an interface whose counters are moving puts its host
	// into a full report on every heartbeat. That is the right trade — an interface dropping packets is
	// one whose full report is worth the bytes, and the value of these numbers is almost entirely in
	// whether they are moving at all, which banding would answer by deleting.
	//
	// It is worth knowing which way it costs. `rx_dropped` counts frames the kernel discarded for
	// reasons that include ordinary unwanted multicast, so on a broadcast LAN it can climb slowly on a
	// perfectly healthy host, and such a host sends full reports. That is the case for setting
	// `[resources] report = false` on a metered link, and the shipped policy file says so.
	ReceiveErrors int64 `json:"receiveErrors"`

	// ReceiveDrops is the receive drop counter, which is what a saturated ring buffer looks like.
	ReceiveDrops int64 `json:"receiveDrops"`

	// TransmitErrors is the transmit error counter.
	TransmitErrors int64 `json:"transmitErrors"`

	// TransmitDrops is the transmit drop counter.
	TransmitDrops int64 `json:"transmitDrops"`
}

// CPUReport is how much of this host's processing capacity is spoken for.
type CPUReport struct {
	// Cores is how many logical processors the kernel lists in /proc/stat.
	//
	// It is read from /proc/stat rather than from runtime.NumCPU because the two answer different
	// questions: NumCPU reports the CPUs this *process* may run on, which a CPUAffinity= directive or a
	// cpuset would narrow, and the host's capacity is not the agent's share of it.
	Cores int `json:"cores"`

	// LoadPerCorePercent is the fifteen-minute load average as a percentage of Cores, banded by
	// loadBandPercent.
	//
	// **This is load average, not CPU-time utilisation, and the distinction is stated rather than
	// glossed.** A load average counts runnable *and* uninterruptible-sleep tasks, so a host blocked on
	// a failing disk reads high here while its processors idle. That is a feature at fleet scale — both
	// are "this machine is not keeping up" — but a reader who assumes `top`'s number will misread it.
	//
	// It is load average rather than a delta of /proc/stat's jiffy counters because a delta needs the
	// previous sample, and that would make this collector the only stateful one in the package: a value
	// that depends on when it was last called, that is wrong on the first heartbeat after every restart,
	// and that has no honest answer at all when the agent has just started. A load average carries its
	// own averaging window and needs no memory of anything.
	//
	// Fifteen minutes rather than one, for the reason loadWindowField gives: a minute-old average
	// resampled every minute is noise the band cannot absorb, and sustained load is the question anyway.
	//
	// Absent rather than zero when /proc/loadavg cannot be read or Cores is zero, because an idle host
	// and an unmeasured one must not encode the same way.
	LoadPerCorePercent *int `json:"loadPerCorePercent,omitempty"`
}

// MemoryReport is how much of this host's memory is spoken for.
type MemoryReport struct {
	// TotalBytes is MemTotal, the memory the kernel manages.
	TotalBytes int64 `json:"totalBytes"`

	// UsedPercent is how much is unavailable to a new allocation, banded by memoryBandPercent.
	//
	// It is computed from MemAvailable rather than from MemFree, and that is the whole correctness of
	// this field. MemFree excludes the page cache, so a healthy Linux host that has been up a week
	// reports itself at ninety-odd per cent used and every fleet dashboard built on it shows a fleet
	// permanently out of memory. MemAvailable is the kernel's own estimate of what a new allocation
	// could actually get, which is the number `free` learned to show for the same reason.
	//
	// Absent when MemAvailable is not in /proc/meminfo, which is every kernel before 3.14 and no kernel
	// HostSeal supports — but absent rather than guessed, because a fallback computed from MemFree plus
	// cached would be the wrong number reported confidently.
	UsedPercent *int `json:"usedPercent,omitempty"`

	// SwapTotalBytes is SwapTotal, zero on a host with no swap.
	SwapTotalBytes int64 `json:"swapTotalBytes"`

	// SwapUsedPercent is how much of the swap is in use, banded the same way, absent where there is no
	// swap.
	//
	// Absent rather than zero on a swapless host, because "nothing is swapped" and "there is nowhere to
	// swap to" lead to opposite conclusions about a machine that is about to be killed by the OOM
	// killer.
	SwapUsedPercent *int `json:"swapUsedPercent,omitempty"`
}

// ResourceReport is what one host says about its capacity and how much of it is gone.
//
// It is a report object rather than three loose sections for the reason ContainerReport is one: the
// flags saying what the agent could not see need somewhere to live, and a document with nowhere to put
// them is a document that quietly reads as complete.
//
// Every volatile figure in it is banded — see loadBandPercent, memoryBandPercent, filesystemBandPercent
// and bytesPerGiB — so that an unchanged host produces byte-identical bytes and the digest-first
// heartbeat in docs/PROTOCOL.md §4.1 keeps working. That is the difference between this section and
// `extra.containers`, whose figures are exact and which therefore puts a host into a full report on
// every beat; it is also why this section can ship on by default and that one cannot.
type ResourceReport struct {
	// CPU is the processing capacity and how much of it is spoken for, absent when /proc/stat could not
	// be read.
	CPU *CPUReport `json:"cpu,omitempty"`

	// Memory is the memory capacity and how much of it is spoken for, absent when /proc/meminfo could
	// not be read.
	Memory *MemoryReport `json:"memory,omitempty"`

	// Filesystems is the list, sorted by mount point and capped at MaxFilesystems.
	//
	// It is never nil and has no omitempty, so an empty list is an explicit `[]` on the wire: "I looked
	// and found no ordinary filesystem" and "this section was not produced" must not encode identically.
	Filesystems []Filesystem `json:"filesystems"`

	// FilesystemsTotal is how many were found before the cap was applied.
	FilesystemsTotal int `json:"filesystemsTotal"`

	// FilesystemsTruncated reports that the list was cut short, so a reader knows the total and the list
	// disagree on purpose rather than by a bug.
	FilesystemsTruncated bool `json:"filesystemsTruncated,omitempty"`

	// FilesystemsUnmeasured names the mount points this agent found and could not measure.
	//
	// It exists because dropping them silently and reporting them as nought bytes are both wrong, in
	// opposite directions, and the third answer needs somewhere to live. A filesystem whose statfs
	// failed — a mount point under a directory this unprivileged agent cannot traverse is the usual
	// cause — has no row here, and without this field that absence is indistinguishable from a host that
	// never had the filesystem. Those are opposite answers to "is that disk full", which is the one
	// question this section exists to answer.
	//
	// A mount point appears here only when *no* mount of its device could be measured, so a disk whose
	// size is reported through one path is not also listed as unmeasured through another. ScanComplete
	// is false whenever this is non-empty: a scan that could not measure everything it found did not
	// complete, whatever else it managed.
	FilesystemsUnmeasured []string `json:"filesystemsUnmeasured,omitempty"`

	// Interfaces is per-interface traffic, sorted by name and capped at MaxInterfaces.
	//
	// Never nil, for the same reason Filesystems is never nil.
	Interfaces []InterfaceTraffic `json:"interfaces"`

	// InterfacesTruncated reports that the interface list was cut short.
	InterfacesTruncated bool `json:"interfacesTruncated,omitempty"`

	// ScanComplete reports whether this agent read everything it set out to read.
	//
	// It covers partial failure as well as total: false means one of the four files could not be read,
	// *or* that a filesystem this scan found could not be measured. A reader that acts on this one
	// boolean is then never told a number is complete when it is not, and FilesystemsUnmeasured and Note
	// say which part was missing. Erring towards false is the safe direction for a flag whose whole job
	// is to stop a gap from reading as an answer.
	//
	// It has no omitempty, deliberately, and the rule is the one stated on RebootReport.Conclusive and
	// ContainerReport.ScanComplete: a flag whose alarming value is false must not have omitempty, or it
	// vanishes from the wire in exactly the case worth seeing. "This host has no filesystems" and "I
	// could not see the filesystems it has" must never render the same way.
	ScanComplete bool `json:"scanComplete"`

	// Note explains in words what the numbers cannot.
	//
	// It carries two things. The first is why a scan came up short. The second is the one honest thing
	// this collector can say about its own sandbox: `ProtectHome=yes` and `PrivateTmp=yes` in the
	// agent's unit replace /home, /root and /tmp with empty filesystems inside this process's mount
	// namespace, so a host whose /home is a separate partition has one this report cannot see. Saying so
	// is the whole reason the field carries prose — an omission nobody is told about is indistinguishable
	// from a host that has no such partition.
	Note string `json:"note,omitempty"`
}

// filesystemUsage is what one statfs call tells this package.
//
// It is a struct of whole numbers rather than the raw syscall type so that the platform-specific half of
// this collector is one small function per operating system, and so that everything downstream of it —
// the df arithmetic, the banding, the inode rule — is ordinary testable code that compiles everywhere.
type filesystemUsage struct {
	// sizeBytes is the total capacity.
	sizeBytes int64

	// usedBytes is the capacity that is gone, counted the way df counts it.
	usedBytes int64

	// availableBytes is what an unprivileged process could still write, which excludes the root reserve.
	availableBytes int64

	// inodesTotal is the fixed inode count, zero on a filesystem that allocates them dynamically.
	inodesTotal int64

	// inodesUsed is how many are allocated.
	inodesUsed int64
}

// CollectResources reports this host's capacity and how much of it is gone, from the real /proc.
//
// It never returns an error. Every way this can come up short — a /proc this agent cannot read, a
// filesystem statfs refuses, a kernel that does not publish MemAvailable — is a fact about the host that
// the report itself states, and a collector that returned an error would have its section dropped
// entirely, which is the one outcome that tells an operator nothing.
func CollectResources() ResourceReport {
	return collectResourcesFrom(ProcRoot, diskUsage)
}

// collectResourcesFrom scans an explicit /proc root with an explicit capacity reader.
//
// The root is a parameter for the reason collectContainersFrom's are: the whole of this file is then
// tested against fixture trees rather than against whatever the machine running the tests happens to be
// doing. The capacity reader is a parameter as well, and that one is not about fixtures — statfs is a
// system call with no file behind it, so it cannot be faked with a directory, and passing it in is the
// same shape as collect.ParseSimulation taking its origin test as a function.
func collectResourcesFrom(procRoot string, usage func(mountPoint string) (filesystemUsage, bool)) ResourceReport {
	report := ResourceReport{
		Filesystems:  []Filesystem{},
		Interfaces:   []InterfaceTraffic{},
		ScanComplete: true,
	}

	var missing []string

	report.CPU = readCPU(procRoot)
	if report.CPU == nil {
		missing = append(missing, filepath.Join(procRoot, "stat"))
	}
	report.Memory = readMemory(procRoot)
	if report.Memory == nil {
		missing = append(missing, filepath.Join(procRoot, "meminfo"))
	}

	filesystems, unmeasured, hidden, skipped, mountsRead := readFilesystems(procRoot, usage)
	if !mountsRead {
		missing = append(missing, filepath.Join(procRoot, "self", "mountinfo"))
	}
	report.FilesystemsUnmeasured = unmeasured
	report.FilesystemsTotal = len(filesystems)
	if len(filesystems) > MaxFilesystems {
		filesystems = filesystems[:MaxFilesystems]
		report.FilesystemsTruncated = true
	}
	report.Filesystems = filesystems

	interfaces, netRead := readInterfaceTraffic(procRoot)
	if !netRead {
		missing = append(missing, filepath.Join(procRoot, "net", "dev"))
	}
	if len(interfaces) > MaxInterfaces {
		interfaces = interfaces[:MaxInterfaces]
		report.InterfacesTruncated = true
	}
	report.Interfaces = interfaces

	var notes []string
	if len(missing) > 0 {
		// Incomplete rather than absent. A host where one of four files could not be read still has
		// three worth reporting, and the flag is what stops the three from reading as all there is.
		report.ScanComplete = false
		notes = append(notes, "this agent could not read "+strings.Join(missing, ", "))
	}
	if len(unmeasured) > 0 {
		// The flag as well as the prose. A client that reads only ScanComplete must not be told the
		// filesystem list is complete when a disk on it could not be measured.
		report.ScanComplete = false
		notes = append(notes, "these mount points were found and could not be measured: "+
			strings.Join(unmeasured, ", "))
	}
	if len(skipped) > 0 {
		notes = append(notes, "these mount points are on remote or userspace filesystems and are not "+
			"measured, because a request to one that has stopped answering cannot be interrupted and "+
			"would stop this agent reporting at all: "+strings.Join(skipped, ", "))
	}
	if len(hidden) > 0 {
		notes = append(notes, "this agent's own systemd sandbox replaces "+strings.Join(hidden, ", ")+
			" with an empty filesystem, so what the host has mounted there is not in this report")
	}
	report.Note = strings.Join(notes, "; ")
	return report
}

// readCPU reports the host's processor count and current load, or nil if /proc/stat is unreadable.
//
// nil rather than a zero-valued report, because a host with no processors does not exist and a report
// claiming one would be a plausible wrong answer rather than a visible failure.
func readCPU(procRoot string) *CPUReport {
	raw, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return nil
	}

	cores := 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		// The aggregate line is "cpu " with two spaces and every per-processor line is "cpuN", so
		// requiring a digit after the prefix is what separates the capacity from the total. Counting the
		// aggregate as a core would report every single-processor host as having two.
		name, _, _ := strings.Cut(scanner.Text(), " ")
		if suffix, isCPU := strings.CutPrefix(name, "cpu"); isCPU && suffix != "" {
			if _, convErr := strconv.Atoi(suffix); convErr == nil {
				cores++
			}
		}
	}

	report := &CPUReport{Cores: cores}
	if centiLoad, ok := readLoadAverage(procRoot); ok && cores > 0 {
		// centiLoad is the load times a hundred and cores is a count, so the division is already a
		// percentage of one processor: a load of 2.00 on four cores is 200/4 = 50 per cent.
		banded := band(int(centiLoad/int64(cores)), loadBandPercent)
		report.LoadPerCorePercent = &banded
	}
	return report
}

// readLoadAverage reads the fifteen-minute load average from /proc/loadavg, as hundredths.
//
// Hundredths, parsed by hand from the two halves of the decimal, rather than a float: docs/PROTOCOL.md
// §8 rejects floating-point values outright and the facts document is digested with that encoder, so a
// float reaching the wire would fail the digest and take the whole heartbeat with it. Parsing to an
// integer here means there is never a float in the file to leak into a field by accident.
func readLoadAverage(procRoot string) (int64, bool) {
	raw, err := os.ReadFile(filepath.Join(procRoot, "loadavg"))
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) <= loadWindowField {
		return 0, false
	}
	whole, fraction, _ := strings.Cut(fields[loadWindowField], ".")
	units, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, false
	}
	// The kernel always prints two decimal places, but a truncated or padded field is read as written
	// rather than assumed: "1.5" is fifty hundredths and "1.5000" is the same, and neither should become
	// five.
	hundredths := int64(0)
	if fraction != "" {
		if len(fraction) > 2 {
			fraction = fraction[:2]
		}
		for len(fraction) < 2 {
			fraction += "0"
		}
		if parsed, convErr := strconv.ParseInt(fraction, 10, 64); convErr == nil {
			hundredths = parsed
		}
	}
	return units*100 + hundredths, true
}

// readMemory reports memory and swap capacity and use, or nil if /proc/meminfo is unreadable.
func readMemory(procRoot string) *MemoryReport {
	values, ok := readMeminfo(filepath.Join(procRoot, "meminfo"))
	if !ok {
		return nil
	}
	total, haveTotal := values["MemTotal"]
	if !haveTotal {
		return nil
	}

	report := &MemoryReport{TotalBytes: total, SwapTotalBytes: values["SwapTotal"]}
	if available, have := values["MemAvailable"]; have && total > 0 {
		used := band(percent(total-available, total), memoryBandPercent)
		report.UsedPercent = &used
	}
	if free, have := values["SwapFree"]; have && report.SwapTotalBytes > 0 {
		used := band(percent(report.SwapTotalBytes-free, report.SwapTotalBytes), memoryBandPercent)
		report.SwapUsedPercent = &used
	}
	return report
}

// readMeminfo parses /proc/meminfo into a map of bytes, keyed without the colon.
//
// It is not readKeyedFile, and the difference is the trap. Every line there is "MemTotal:  8167848 kB":
// the key keeps a colon, and the value is in kibibytes with a unit suffix that readKeyedFile would drop
// silently — so reusing it would produce a map keyed on "MemTotal:" holding a number 1024 times too
// small, with nothing anywhere to say so.
func readMeminfo(path string) (map[string]int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	values := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		key, rest, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, convErr := strconv.ParseInt(fields[0], 10, 64)
		if convErr != nil {
			continue
		}
		// A few entries — HugePages_Total among them — are counts rather than sizes and carry no unit.
		// Multiplying those by a kibibyte would be wrong, so the suffix decides rather than the file.
		if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
			value *= kibibyte
		}
		values[key] = value
	}
	return values, true
}

// readFilesystems reports the ordinary filesystems mounted here, and which sandboxed paths were hidden.
//
// The second return value is what keeps the sandbox from lying: a /home that the agent's own unit
// replaced with an empty filesystem is skipped like any other virtual mount, and this is what lets the
// report say that rather than leaving an operator to notice the partition is missing.
func readFilesystems(procRoot string, usage func(string) (filesystemUsage, bool)) (
	out []Filesystem, unmeasured, hidden, skipped []string, ok bool) {

	raw, err := os.ReadFile(filepath.Join(procRoot, "self", "mountinfo"))
	if err != nil {
		return []Filesystem{}, nil, nil, nil, false
	}

	out = []Filesystem{}
	var candidates []mountEntry
	hiddenSeen := map[string]bool{}
	remoteSeen := map[string]bool{}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		entry, parsed := parseMountinfoLine(scanner.Text())
		if !parsed {
			continue
		}
		if refused, remote := refusedFilesystem(entry.fsType); refused {
			switch {
			case remote && !remoteSeen[entry.point]:
				// Named rather than dropped in silence. A host whose /srv is on NFS would otherwise
				// report no /srv at all, which reads as a host that has none — and the reason this one
				// is missing is a decision this agent made, not a fact about the machine.
				remoteSeen[entry.point] = true
				skipped = append(skipped, entry.point)
			case sandboxedMountPoints[entry.point] && !hiddenSeen[entry.point]:
				hiddenSeen[entry.point] = true
				hidden = append(hidden, entry.point)
			}
			continue
		}
		// A read-only mount cannot fill up, so reporting how full it is answers a question nobody asked
		// and spends a row of a bounded list doing it.
		if entry.readOnly() {
			continue
		}
		candidates = append(candidates, entry)
	}

	// Sorted before anything is dropped or measured, which is what makes both deterministic. A host over
	// the cap then reports the same filesystems on every beat rather than a different set each time —
	// which would change the facts digest for no reason at all — and the mount kept for a device that has
	// several is the first in path order rather than whichever the kernel happened to list first.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].point < candidates[j].point })
	sort.Strings(hidden)
	sort.Strings(skipped)

	// Keyed on the device alone, so a disk mounted in several places is counted once. Both ways of
	// mounting it twice want that answer: a bind mount is the same filesystem seen again, and a btrfs
	// subvolume shares its pool's free space, so statfs returns identical figures for every subvolume and
	// listing five of them would make a fleet's total capacity five times the disk anybody bought.
	seen := map[string]bool{}
	var refusedMounts []mountEntry
	for _, entry := range candidates {
		if seen[entry.deviceID] {
			continue
		}
		capacity, measured := usage(entry.point)
		if !measured || capacity.sizeBytes <= 0 {
			// Not reported as a row, because a row of zeroes would read as a disk with nothing on it —
			// but named, because dropping it in silence is the other half of the same mistake. A mount
			// this agent could not measure and a mount the host does not have produce the same absent
			// row, and they are opposite answers to "is that disk full".
			//
			// The device is deliberately *not* marked seen here, so a later mount of the same device
			// still gets its turn. Marking it would let one unmeasurable mount point suppress a
			// measurable one — a disk missing from the report because of the path it was asked about
			// rather than because of anything wrong with the disk.
			refusedMounts = append(refusedMounts, entry)
			continue
		}
		seen[entry.deviceID] = true
		out = append(out, describeFilesystem(entry, capacity))
	}

	// A device measured through one of its mount points is measured, whichever other one failed first —
	// so the comparison is on the device rather than on the path. Comparing paths would let a bind mount
	// this agent cannot traverse name a disk as unmeasurable in the same report that gives its size,
	// which is a document contradicting itself.
	for _, entry := range refusedMounts {
		if !seen[entry.deviceID] {
			unmeasured = append(unmeasured, entry.point)
		}
	}
	sort.Strings(unmeasured)
	return out, unmeasured, hidden, skipped, true
}

// describeFilesystem turns one mount entry and its capacity into a reported row.
//
// It is separate from the loop above so that the arithmetic — which is where a wrong disk figure would
// come from — is a small function a test can drive directly with numbers rather than with a fixture
// tree and a fake syscall.
func describeFilesystem(entry mountEntry, capacity filesystemUsage) Filesystem {
	row := Filesystem{
		Device:     entry.source,
		MountPoint: entry.point,
		Type:       entry.fsType,
		SizeBytes:  capacity.sizeBytes,
		// df's denominator, not the disk's: used over used-plus-available leaves the root reserve out of
		// the denominator, which is what stops a fresh ext4 filesystem from reading five per cent fuller
		// here than in the command the operator is about to run.
		UsedPercent: band(percent(capacity.usedBytes, capacity.usedBytes+capacity.availableBytes),
			filesystemBandPercent),
	}
	if capacity.inodesTotal > 0 {
		inodes := band(percent(capacity.inodesUsed, capacity.inodesTotal), filesystemBandPercent)
		row.InodesUsedPercent = &inodes
	}
	return row
}

// readInterfaceTraffic reports each interface's counters from /proc/net/dev.
//
// The counters are read from a file rather than from the netlink statistics the network collector's
// net.Interfaces call would reach, because this one works under a seccomp filter with no AF_NETLINK and
// because it is the same shape as every other read in this file.
func readInterfaceTraffic(procRoot string) ([]InterfaceTraffic, bool) {
	raw, err := os.ReadFile(filepath.Join(procRoot, "net", "dev"))
	if err != nil {
		return []InterfaceTraffic{}, false
	}

	out := []InterfaceTraffic{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		// The two header lines carry no colon, and the interface name is glued to the first counter on a
		// host whose name is long enough — "enp0s31f6:1234" — so cutting on the colon is what makes this
		// correct on both. Splitting the whole line on whitespace is the classic way to get this wrong.
		name, rest, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || name == "lo" {
			// The loopback interface is the same on every host and tells an operator nothing, which is
			// the same judgement the network collector makes about it one section over.
			continue
		}
		fields := strings.Fields(rest)
		// Sixteen columns: eight received, then eight transmitted. A shorter line is a format this code
		// was not written for, and skipping it is better than reading a transmit counter as a receive
		// one.
		if len(fields) < 16 {
			continue
		}
		out = append(out, InterfaceTraffic{
			Name:           name,
			ReceivedGiB:    counter(fields[0]) / bytesPerGiB,
			ReceiveErrors:  counter(fields[2]),
			ReceiveDrops:   counter(fields[3]),
			TransmittedGiB: counter(fields[8]) / bytesPerGiB,
			TransmitErrors: counter(fields[10]),
			TransmitDrops:  counter(fields[11]),
		})
	}

	// Sorted before the cap for the reason the filesystems are: a deterministic cut keeps the digest
	// still on a host that has more interfaces than the protocol will carry.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

// counter parses one /proc/net/dev column, treating anything unreadable as zero.
//
// Zero rather than absent, unlike everywhere else in this package, and the exception is deliberate:
// these columns are always present and always numeric on every kernel HostSeal supports, so a parse
// failure is a file that is not /proc/net/dev at all. Threading an absent value through six fields to
// describe a case that cannot happen would cost every reader of this struct a pointer dereference.
func counter(field string) int64 {
	value, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return 0
	}
	return value
}

// percent returns part as a whole percentage of total, clamped to 0..100.
//
// Integer arithmetic throughout, because docs/PROTOCOL.md §8 rejects floats and this is the one function
// in the package where somebody would reach for one. The clamp exists because a filesystem can report
// more used than the caller's denominator during a resize, and a disk reported as 104% full is a bug
// report about the dashboard rather than about the disk.
func percent(part, total int64) int {
	if total <= 0 {
		return 0
	}
	// Multiplying first keeps the precision that matters at the top of the range — but part*100 overflows
	// an int64 above about 82 PiB, and the clamp would turn that into a confident nought. Dividing first
	// loses a little precision and cannot wrap, so the large case takes that branch: on a filesystem that
	// big, one per cent is eight hundred terabytes and the precision was never the point.
	if part > math.MaxInt64/100 {
		return clampPercent(part / max(total/100, 1))
	}
	return clampPercent(part * 100 / total)
}

// clampPercent holds a computed percentage inside nought to a hundred.
//
// Separate from percent because both of its branches reach it, and because the clamp is the part worth
// naming: a filesystem can report more used than the denominator while it is being resized, and a disk
// shown as 104% full is a bug report about the dashboard rather than about the disk.
func clampPercent(value int64) int {
	switch {
	case value < 0:
		return 0
	case value > 100:
		return 100
	default:
		return int(value)
	}
}

// band rounds a percentage down to a multiple of size.
//
// Down rather than to nearest, so that the reported figure is never higher than the truth: an operator
// acting on "90% full" should find at most ninety-four per cent gone, not eighty-five. Rounding to
// nearest would put a host at 88% into the 90 band and make the alert that fired unexplainable from the
// number beside it.
func band(value, size int) int {
	if size <= 1 {
		return value
	}
	return value / size * size
}
