package collect

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProcRoot is the proc filesystem the container scan reads.
//
// It is a package constant with a …From variant beside it rather than a filesystem seam, following
// platform.DetectFrom and policy.LoadFrom: the production path is fixed so that nothing can point the
// scan somewhere else, and tests get their fixtures by naming a directory.
const ProcRoot = "/proc"

// CgroupRoot is the unified cgroup v2 hierarchy the container scan reads.
//
// Only the unified hierarchy is read. Docker on a cgroup v1 host puts container state under a set of
// per-controller mount points with a different layout, and reporting a v1 host as having no containers
// is a better failure than reporting half-parsed numbers from a tree this code was not written for —
// the supported releases (Ubuntu 22.04 and later, Debian 12 and later) are all v2 by default.
const CgroupRoot = "/sys/fs/cgroup"

// clockTicksPerSecond is the USER_HZ that /proc/<pid>/stat expresses process times in.
//
// It is sysconf(_SC_CLK_TCK), which Go cannot call without cgo, and cgo is not worth giving up a static
// binary for one number that has been 100 on every Linux port HostSeal runs on. The value is named
// rather than written inline because getting it wrong scales every reported start time by a constant
// factor, which looks like a clock problem on the host rather than a units problem in the agent — and
// people chase clock problems for a long time.
const clockTicksPerSecond = 100

// capLastCapPath is where the kernel publishes the highest capability number it knows.
//
// The full capability set — what `docker run --privileged` grants — is every bit up to this number, and
// the number grows with kernel releases. Comparing against a hard-coded mask would mean that a kernel
// with one more capability than the agent knew about made every privileged container look unprivileged,
// which is a silent false negative on the one field an operator would act on.
const capLastCapPath = "sys/kernel/cap_last_cap"

// capLastCapFallback is the highest capability number assumed when the kernel does not say.
//
// 40 is CAP_CHECKPOINT_RESTORE, the last capability on every kernel the supported releases ship. It is
// a safe fallback in both directions: a privileged container on a newer kernel still has all forty of
// these bits and is still reported as privileged, and no unprivileged container Docker creates comes
// close to holding them all.
const capLastCapFallback = 40

// dockerSocketName is the basename a bind-mounted Docker socket has.
//
// Matching the basename rather than a full path is deliberate: the mount point inside the container is
// whatever the operator chose, and the risk is the same wherever it was put.
const dockerSocketName = "docker.sock"

// Container is one Docker container as seen from the host's /proc and cgroup tree.
//
// Everything here is read without the Docker API, so the fields are the ones the kernel already knows.
// The image name, the exit code and the restart count are not among them; see ContainerReport for what
// that costs and why it is the trade this collector makes.
type Container struct {
	// ID is the full 64-character container id.
	ID string `json:"id"`

	// ShortID is the first twelve characters, which is what `docker ps` prints.
	//
	// It is computed here rather than left to every client, because a client that truncated to a
	// different length would produce ids an operator could not paste into `docker inspect`.
	ShortID string `json:"shortId"`

	// MainPID is the host-side pid of the container's process 1.
	//
	// It is the process every other field in this struct is read from, so a container whose main pid
	// could not be identified reports the cgroup figures and nothing else.
	MainPID int `json:"mainPid,omitempty"`

	// Command is the executable name of the main process, from /proc/<pid>/comm.
	//
	// It is deliberately not /proc/<pid>/cmdline, and that line is the reason this collector can ship
	// with a policy gate rather than without one. An argument vector is exactly where credentials end
	// up — a password passed as --password, a token as --auth-token — and issue #6 says so; comm is
	// capped by the kernel at fifteen bytes and cannot carry one. Reporting a name rather than a
	// command line is what keeps `[containers] report = true` from being an all-or-nothing choice
	// between knowing what runs on a host and publishing that host's secrets to the control plane.
	Command string `json:"command,omitempty"`

	// StartedAt is when the main process started, not when the container was created.
	//
	// It is /proc/<pid>/stat's starttime, in clock ticks since boot, plus /proc/stat's btime. The
	// distinction matters: a restarted container reports the new process's start, so a value minutes
	// old on a container that has run for months means the process was replaced rather than that the
	// container is new. The container's own Created time exists only in the Docker API, which this
	// collector deliberately does not reach.
	//
	// The resolution is one second, because the arithmetic divides by clockTicksPerSecond and because
	// docs/PROTOCOL.md §8 rejects floating-point values outright.
	StartedAt *time.Time `json:"startedAt,omitempty"`

	// Running reports that the container's cgroup still holds at least one process.
	//
	// It has no omitempty: a container that is down is the case an operator is looking for, and a
	// false that vanished from the wire would be the one worth seeing. Note that a container which has
	// exited entirely has no cgroup and no processes and therefore does not appear in this report at
	// all — see ContainerReport.Note.
	Running bool `json:"running"`

	// Paused reports that the container's cgroup is frozen.
	//
	// `docker pause` uses the cgroup freezer rather than a signal, so this is genuinely observable
	// without the Docker API. A paused container is still populated, so it reports Running and Paused
	// together, which is what Docker itself calls the "paused" state.
	Paused bool `json:"paused"`

	// MemoryBytes is memory.current less memory.stat's inactive_file, which is what `docker stats`
	// shows.
	//
	// The subtraction is not cosmetic. memory.current includes reclaimable page cache, so reporting it
	// raw makes every container look like it is using several times what the operator sees in
	// `docker stats`, and a fleet dashboard that disagrees with the tool people already trust is a
	// dashboard nobody reads twice.
	//
	// It is a pointer because the file exists only when the memory controller is enabled in the
	// parent's cgroup.subtree_control. Absent means not measured; zero would be a claim about this
	// container's memory, and the two are different answers.
	MemoryBytes *int64 `json:"memoryBytes,omitempty"`

	// MemoryLimitBytes is memory.max, absent when the container is unlimited.
	//
	// memory.max reads "max" for a container with no limit, and that is reported as an absent field
	// rather than as a very large number: a limit nobody set is not a limit. An absent field therefore
	// means either "no limit" or "the memory controller is off", and MemoryBytes is what tells the two
	// apart.
	MemoryLimitBytes *int64 `json:"memoryLimitBytes,omitempty"`

	// CPUSeconds is cpu.stat's usage_usec, in whole seconds.
	//
	// Whole seconds rather than a fraction because docs/PROTOCOL.md §8 rejects floats, and a facts
	// document containing one would fail to digest and take the whole heartbeat with it. The kernel
	// accounts usage_usec whether or not the cpu controller is enabled, so this is present on
	// containers whose CPU is not being controlled at all.
	CPUSeconds *int64 `json:"cpuSeconds,omitempty"`

	// CPUThrottledSeconds is cpu.stat's throttled_usec, in whole seconds, when the cpu controller is
	// enabled.
	//
	// It is absent rather than zero when the controller is off, because "this container was never
	// throttled" and "nothing was measuring whether it was throttled" lead to opposite conclusions
	// about a container that is running slowly.
	CPUThrottledSeconds *int64 `json:"cpuThrottledSeconds,omitempty"`

	// Pids is how many processes the container holds.
	Pids int `json:"pids"`

	// PidsSource names the file Pids was read from: "pids.current", "cgroup.procs" or "/proc".
	//
	// The two are not the same measurement — pids.current is the pids controller's own counter and
	// counts threads a caller may not be able to see, while counting cgroup.procs counts thread group
	// leaders — and mixing them silently would make one host's number quietly incomparable with the
	// next host's. Saying which was used costs one string.
	PidsSource string `json:"pidsSource,omitempty"`

	// OOMKills is memory.events' oom_kill counter, when the memory controller is enabled.
	//
	// It is the field that explains a container which looks healthy now and was not five minutes ago,
	// and it survives the restart that hid the evidence.
	OOMKills *int64 `json:"oomKills,omitempty"`

	// PostureKnown reports that the four security fields below were actually read.
	//
	// They are read from the main process's /proc/<pid>/status and /proc/<pid>/mountinfo, and a
	// container that exits between the scan finding it and the scan reading it leaves all four at
	// false — which is exactly the reassuring answer, arrived at by not looking. It has no omitempty
	// for the reason RebootReport.Conclusive has none: the value worth seeing is the false one.
	PostureKnown bool `json:"postureKnown"`

	// RunsAsRoot reports that the main process's real uid is 0.
	RunsAsRoot bool `json:"runsAsRoot"`

	// Privileged reports that the main process holds the full effective capability set.
	//
	// That is what `docker run --privileged` grants and what no ordinary container has: Docker's
	// default set is a small subset. A privileged container is root on the host wearing a namespace,
	// which is the same statement docs/SECURITY.md §6 makes about the docker group.
	Privileged bool `json:"privileged"`

	// SeccompDisabled reports that the main process runs with no seccomp filter (Seccomp: 0).
	//
	// It is the state `--security-opt seccomp=unconfined` produces, and it removes the filter that
	// stands between a container process and most of the kernel's attack surface.
	SeccompDisabled bool `json:"seccompDisabled"`

	// DockerSocketMounted reports that something named docker.sock is mounted into the container.
	//
	// This is the field the whole issue is about. "Docker socket access is root equivalence" is the
	// sentence in docs/SECURITY.md §6 that keeps the agent out of the docker group, and a container
	// with the socket bind-mounted has exactly the access that sentence refuses — discovered on a host
	// rather than assumed from a deployment manifest somebody has not read.
	//
	// Only the boolean is reported. The host paths in mountinfo would say where the socket lives and
	// what else is mounted where, and that is inventory of the host's filesystem layout that the
	// control plane has no business holding.
	DockerSocketMounted bool `json:"dockerSocketMounted"`
}

// ContainerReport is what one host says about the containers running on it.
//
// It is a report object rather than a bare array for the reason RebootReport is a struct: the flags
// that say what the agent could not see need somewhere to live, and a list with nowhere to put them is
// a list that quietly reads as complete.
//
// What it cannot answer is worth stating up front, because the answer is smaller than the Docker API's
// on purpose. There is no image name, no exit code, no restart count and no health status here: those
// live behind /var/run/docker.sock, which is root:docker, and reaching it would mean either adding the
// agent to the docker group — refused by docs/SECURITY.md §6 — or a fourth root helper, refused by
// docs/SECURITY.md §3. A container that has exited has no processes and no cgroup, so it is not in
// this list at all; this reports what is running, never what ran.
//
// One operational consequence deserves naming. The resource figures change on every collection, so a
// host that turns this section on sends a full report on every heartbeat rather than a digest — the
// digest-first design in docs/PROTOCOL.md §4.1 saves nothing on a section that is never twice the
// same. That is the price of live figures, and one more reason the gate ships off.
type ContainerReport struct {
	// Containers is the list, sorted by id and capped at MaxContainers.
	//
	// It is never nil and has no omitempty, so an empty list is an explicit `[]` on the wire: "I
	// looked and found none" and "this section was not produced" must not encode identically.
	Containers []Container `json:"containers"`

	// Total is how many containers were found, before the cap was applied.
	//
	// It is counted first for the reason Summarise counts packages first: a host running six hundred
	// containers must report six hundred and say the list was cut short, because reporting two hundred
	// is a quietly wrong answer to the question that was asked.
	Total int `json:"total"`

	// Truncated reports that the list was cut short, so a reader knows Total and Containers disagree
	// on purpose rather than by a bug.
	Truncated bool `json:"truncated,omitempty"`

	// ScanComplete reports whether this agent could see the host's processes and cgroups at all.
	//
	// It is false when /proc is mounted with hidepid, which hides other users' processes from an
	// unprivileged agent, and when the agent's own /proc/self/cgroup reads "0::/", which means it is in
	// a private cgroup namespace and is looking at a tree that is not the host's.
	//
	// It has no omitempty, deliberately, and the rule is the one stated on RebootReport.Conclusive: a
	// flag whose alarming value is false must not have omitempty, or it vanishes from the wire in
	// exactly the case worth seeing. "No containers are running" and "I could not see the containers
	// that are" must never render the same way.
	ScanComplete bool `json:"scanComplete"`

	// Note explains an empty list in words, where an empty list is explicable.
	//
	// Three answers arrive as an empty array and mean entirely different things: no container runtime
	// is installed on this host, a runtime is running and nothing is up, and the agent could not see.
	// The network collector does the same thing for an empty interface list and for the same reason.
	Note string `json:"note,omitempty"`
}

// CollectContainers reports the containers visible on this host from the real /proc and cgroup tree.
//
// It never returns an error. Every way this can fail — no /proc entries readable, no cgroup files, no
// Docker at all — is a fact about the host that the report itself can state, and a collector that
// returned an error would have its section dropped entirely, which is the one outcome that tells an
// operator nothing.
func CollectContainers() ContainerReport {
	return collectContainersFrom(ProcRoot, CgroupRoot)
}

// collectContainersFrom scans an explicit /proc and cgroup root.
//
// The two roots are parameters so the whole of this file can be tested against fixture trees rather
// than against whatever happens to be running on the machine the tests run on — the same reason
// platform.DetectFrom and policy.LoadFrom exist. There is no fs.FS seam here because there is none
// anywhere else in this package, and one invented for a single collector would be a second idiom.
func collectContainersFrom(procRoot, cgroupRoot string) ContainerReport {
	report := ContainerReport{Containers: []Container{}, ScanComplete: true}

	obstruction := scanObstruction(procRoot)

	entries, err := os.ReadDir(procRoot)
	if err != nil && obstruction == "" {
		obstruction = "this agent cannot read " + procRoot + ", so it cannot see any process on this host"
	}

	members, cgroupPaths, runtimeSeen := scanProcesses(procRoot, entries)

	ids := make([]string, 0, len(members))
	for id := range members {
		ids = append(ids, id)
	}
	// Sorted before the cap, so the cut is at least deterministic: a host over the limit reports the
	// same two hundred containers on every beat instead of a different two hundred each time, which
	// would make the facts digest change for no reason at all.
	sort.Strings(ids)

	report.Total = len(ids)
	if len(ids) > MaxContainers {
		ids = ids[:MaxContainers]
		report.Truncated = true
	}

	btime := bootTime(procRoot)
	capMask := fullCapabilitySet(procRoot)
	for _, id := range ids {
		report.Containers = append(report.Containers,
			describeContainer(procRoot, cgroupRoot, id, cgroupPaths[id], members[id], btime, capMask))
	}

	switch {
	case obstruction != "":
		report.ScanComplete = false
		report.Note = obstruction
	case len(report.Containers) > 0:
		// A list with rows in it explains itself. The note exists for the three ways an empty one can
		// arise, which are otherwise indistinguishable.
	case runtimeSeen:
		report.Note = "a container runtime is running and no container holds a process; a container " +
			"that has exited leaves no cgroup and is not visible from the host filesystem"
	default:
		report.Note = "no container runtime is visible on this host"
	}
	return report
}

// scanProcesses walks the pids in /proc and groups the ones in a Docker container cgroup.
//
// Enumeration starts from /proc rather than from the cgroup tree because the cgroup tree's shape is a
// configuration choice and /proc's is not. One pass over /proc/<pid>/cgroup covers Docker's systemd
// driver, its cgroupfs driver, a custom --cgroup-parent and rootless Docker under a user slice,
// whereas walking a fixed path under /sys/fs/cgroup finds the default installation and silently misses
// the other three.
//
// It also reports whether a container runtime was seen at all, which is what lets an empty list say
// "nothing is installed here" rather than leaving an operator to guess.
func scanProcesses(procRoot string, entries []os.DirEntry) (members map[string][]int,
	cgroupPaths map[string]string, runtimeSeen bool) {

	members = map[string][]int{}
	cgroupPaths = map[string]string{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cgroup"))
		if err != nil {
			// A process that exited between the directory listing and this read. Normal on any busy
			// host and not worth a log line every heartbeat.
			continue
		}
		path := unifiedCgroupPath(raw)
		if path == "" {
			continue
		}
		if isRuntimeService(path) {
			runtimeSeen = true
			continue
		}
		id := dockerContainerID(path)
		if id == "" {
			continue
		}
		runtimeSeen = true
		members[id] = append(members[id], pid)
		if _, seen := cgroupPaths[id]; !seen {
			cgroupPaths[id] = path
		}
	}
	return members, cgroupPaths, runtimeSeen
}

// describeContainer fills in one container from its cgroup files and its main process.
//
// The cgroup half is read first and unconditionally, because it answers for the container as a whole;
// the process half is everything that needs a pid to read, and a container whose main process cannot be
// identified reports the first half rather than nothing.
func describeContainer(procRoot, cgroupRoot, id, cgroupPath string, pids []int,
	btime int64, capMask uint64) Container {

	c := Container{ID: id, ShortID: id[:12]}
	dir := filepath.Join(cgroupRoot, filepath.Clean("/"+cgroupPath))

	procs, procsErr := cgroupProcs(filepath.Join(dir, "cgroup.procs"))
	candidates := procs
	if procsErr != nil || len(candidates) == 0 {
		candidates = pids
	}
	sort.Ints(candidates)
	c.MainPID = mainPID(procRoot, candidates)

	if events, ok := readKeyedFile(filepath.Join(dir, "cgroup.events")); ok {
		c.Running = events["populated"] == 1
		c.Paused = events["frozen"] == 1
	} else {
		// The container was found through a live process, so its cgroup is populated by construction.
		// cgroup.events is what would have told us about the freezer, and without it a paused container
		// reports as merely running — a smaller wrong answer than claiming a running container is down.
		c.Running = true
	}

	if current, ok := readInt(filepath.Join(dir, "memory.current")); ok {
		used := current
		if stat, statOK := readKeyedFile(filepath.Join(dir, "memory.stat")); statOK {
			used -= stat["inactive_file"]
		}
		if used < 0 {
			used = 0
		}
		c.MemoryBytes = &used
	}
	if limit, ok := readMemoryMax(filepath.Join(dir, "memory.max")); ok {
		c.MemoryLimitBytes = &limit
	}
	if events, ok := readKeyedFile(filepath.Join(dir, "memory.events")); ok {
		if kills, present := events["oom_kill"]; present {
			c.OOMKills = &kills
		}
	}
	if cpu, ok := readKeyedFile(filepath.Join(dir, "cpu.stat")); ok {
		if usec, present := cpu["usage_usec"]; present {
			seconds := usec / 1_000_000
			c.CPUSeconds = &seconds
		}
		if usec, present := cpu["throttled_usec"]; present {
			seconds := usec / 1_000_000
			c.CPUThrottledSeconds = &seconds
		}
	}

	switch current, ok := readInt(filepath.Join(dir, "pids.current")); {
	case ok:
		c.Pids, c.PidsSource = int(current), "pids.current"
	case procsErr == nil:
		c.Pids, c.PidsSource = len(procs), "cgroup.procs"
	default:
		c.Pids, c.PidsSource = len(pids), "/proc"
	}

	if c.MainPID > 0 {
		describeMainProcess(&c, procRoot, btime, capMask)
	}
	return c
}

// describeMainProcess reads everything about a container that needs its main process's pid.
//
// It is separate from describeContainer so that the one rule this half has to obey is visible in one
// place: the four security fields are only claimed when they were actually read. All four default to
// the reassuring value, so a process that exits between being found and being inspected would
// otherwise be reported as an unprivileged, seccomp-confined container with no socket mounted, which is
// the most dangerous shape a wrong answer could take here.
func describeMainProcess(c *Container, procRoot string, btime int64, capMask uint64) {
	dir := filepath.Join(procRoot, strconv.Itoa(c.MainPID))

	if raw, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		c.Command = strings.TrimSpace(string(raw))
	}
	if started, ok := processStart(filepath.Join(dir, "stat"), btime); ok {
		c.StartedAt = &started
	}

	status, statusOK := readProcessStatus(filepath.Join(dir, "status"))
	mounted, mountsOK := hasDockerSocketMount(filepath.Join(dir, "mountinfo"))
	if !statusOK || !mountsOK {
		return
	}
	c.PostureKnown = true
	c.RunsAsRoot = status.realUID == 0
	c.Privileged = capMask != 0 && status.capEff&capMask == capMask
	c.SeccompDisabled = status.seccompSeen && status.seccomp == 0
	c.DockerSocketMounted = mounted
}

// mainPID picks the container's process 1 out of the pids in its cgroup.
//
// The reliable signal is NSpid: a process inside a pid namespace lists its host pid first and its
// namespace pid last, so the entry whose NSpid line ends in 1 is the container's init whatever order
// the kernel listed the cgroup in. A container started with --pid=host is in no pid namespace at all
// and has a single-entry NSpid, and for that one the lowest pid in the cgroup is the best available
// answer — it is the process the others were forked from.
func mainPID(procRoot string, pids []int) int {
	lowest := 0
	for _, pid := range pids {
		if lowest == 0 || pid < lowest {
			lowest = pid
		}
		ns := namespacePids(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
		if len(ns) > 1 && ns[len(ns)-1] == "1" {
			return pid
		}
	}
	return lowest
}

// scanObstruction reports, in words, why this agent cannot see the host's containers — or "" if it can.
//
// Both conditions it checks produce the same symptom: an empty or short container list on a host that
// is running containers. Neither produces an error, which is why they are looked for deliberately
// rather than inferred from a disappointing result.
func scanObstruction(procRoot string) string {
	if hidepidInForce(filepath.Join(procRoot, "self", "mountinfo")) {
		return "/proc is mounted with hidepid, so this unprivileged agent can only see its own " +
			"processes; container state cannot be read from the host filesystem in that configuration"
	}
	if raw, err := os.ReadFile(filepath.Join(procRoot, "self", "cgroup")); err == nil {
		if unifiedCgroupPath(raw) == "/" {
			return "this agent is in a private cgroup namespace and sees its own cgroup as the root, " +
				"so the host's container cgroups are not visible to it"
		}
	}
	return ""
}

// hidepidInForce reports whether /proc is mounted with hidepid set to anything but off.
//
// hidepid hides other users' /proc entries from an unprivileged reader, which turns this whole
// collector into a report about the agent itself. mountinfo is the only place the option is visible;
// /proc/mounts does not carry the super-block options of the proc mount reliably.
func hidepidInForce(mountinfoPath string) bool {
	raw, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		mount, ok := parseMountinfoLine(scanner.Text())
		if !ok || mount.point != "/proc" || mount.fsType != "proc" {
			continue
		}
		for _, opt := range strings.Split(mount.superOptions, ",") {
			value, found := strings.CutPrefix(opt, "hidepid=")
			// hidepid takes both numeric and named values — 0/off, 1/noaccess, 2/invisible — and only
			// the first pair means "not in force".
			if found && value != "0" && value != "off" {
				return true
			}
		}
	}
	return false
}

// mountEntry is the part of one /proc/<pid>/mountinfo line this package reads.
type mountEntry struct {
	// point is the mount point, as seen in the mount namespace the file belongs to.
	point string

	// fsType is the filesystem type, from after the separator.
	fsType string

	// superOptions are the per-superblock options, the last field on the line.
	superOptions string

	// deviceID is the "major:minor" of the device behind the mount.
	//
	// It is what tells two mounts of the same disk apart from two disks, which the mount point cannot
	// do and the source string cannot either — a filesystem mounted by UUID and the same one mounted by
	// path carry different sources and the same device.
	deviceID string

	// source is the mount source, such as "/dev/vda1", as the first field after the separator gives it.
	source string

	// mountOptions are the per-mount options, the sixth field of the line.
	//
	// They are separate from superOptions because the two can disagree, and the disagreement is the
	// useful case: a filesystem mounted read-write at the superblock can be mounted read-only here.
	mountOptions string
}

// readOnly reports whether the filesystem itself is mounted read-only.
//
// **The superblock options only, and never the per-mount options.** That distinction is the whole of
// this function and it was got wrong once. `ProtectSystem=strict` in the agent's own systemd unit is a
// read-only bind remount of the entire hierarchy, and a read-only bind remount sets `ro` in the
// per-mount field while leaving the superblock reading `rw`:
//
//	73 48 254:0 /usr /usr ro,relatime - ext4 /dev/vda rw,resv_strict
//
// So a check that consulted the per-mount options would find every filesystem on the host read-only,
// report none of them, and do it silently on every host in the fleet — a plausible answer arrived at by
// not looking, which is the failure this package exists to refuse. The superblock field is what
// distinguishes a disk that genuinely cannot be written — a squashfs image, a `mount -o ro` data disk —
// from one this process merely cannot write.
func (m mountEntry) readOnly() bool {
	for _, option := range strings.Split(m.superOptions, ",") {
		if option == "ro" {
			return true
		}
	}
	return false
}

// unescapeMountPath decodes the octal escapes mountinfo uses for awkward characters in a path.
//
// The kernel escapes space, tab, newline and backslash as a backslash and three octal digits, and
// decodes nothing else — so this decodes nothing else either. A decoder that accepted any escape would
// turn a path containing a literal backslash followed by digits into a different path, which is a worse
// answer than leaving it alone.
func unescapeMountPath(raw string) string {
	if !strings.Contains(raw, `\`) {
		return raw
	}
	var out strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] == '\\' && i+3 < len(raw) {
			if value, err := strconv.ParseUint(raw[i+1:i+4], 8, 8); err == nil {
				switch byte(value) {
				case ' ', '\t', '\n', '\\':
					out.WriteByte(byte(value))
					i += 4
					continue
				}
			}
		}
		out.WriteByte(raw[i])
		i++
	}
	return out.String()
}

// parseMountinfoLine splits one mountinfo line into the fields this package needs.
//
// The format has a variable number of optional fields before a " - " separator, so the fields after it
// cannot be reached by index from the start of the line. Splitting on the separator first is what makes
// this correct on a mount with shared/master propagation set and on one without.
func parseMountinfoLine(line string) (mountEntry, bool) {
	before, after, found := strings.Cut(line, " - ")
	if !found {
		return mountEntry{}, false
	}
	head := strings.Fields(before)
	tail := strings.Fields(after)
	if len(head) < 6 || len(tail) < 3 {
		return mountEntry{}, false
	}
	// Mountinfo escapes space, tab, newline and backslash in paths as octal. The mount point is now
	// reported for display as well as compared, so it is unescaped here rather than at one of the two
	// call sites: a filesystem mounted at "/mnt/my backup" would otherwise be reported as
	// "/mnt/my\040backup", which is a path an operator cannot paste into anything.
	return mountEntry{
		point:        unescapeMountPath(head[4]),
		fsType:       tail[0],
		superOptions: tail[2],
		deviceID:     head[2],
		source:       tail[1],
		mountOptions: head[5],
	}, true
}

// hasDockerSocketMount reports whether a process has something named docker.sock mounted into it.
//
// The second return value is whether mountinfo could be read at all, because a false from an
// unreadable file is the reassuring answer to the most important question this collector asks, and it
// must not be reported as if it had been established.
func hasDockerSocketMount(mountinfoPath string) (mounted, readable bool) {
	raw, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return false, false
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		mount, ok := parseMountinfoLine(scanner.Text())
		if ok && filepath.Base(mount.point) == dockerSocketName {
			return true, true
		}
	}
	return false, true
}

// processStatus is the part of /proc/<pid>/status this package reads.
type processStatus struct {
	// realUID is the first field of the Uid line, the process's real user id.
	realUID int

	// capEff is the CapEff mask, the capabilities the process holds right now.
	capEff uint64

	// seccomp is the Seccomp mode: 0 disabled, 1 strict, 2 filtered.
	seccomp int

	// seccompSeen records that the Seccomp line was present.
	//
	// A kernel built without CONFIG_SECCOMP prints no line at all, and treating that absence as mode 0
	// would report every container on such a kernel as deliberately unconfined. The supported releases
	// all have seccomp, so this exists to keep the claim honest rather than to handle a case anyone
	// expects to hit.
	seccompSeen bool
}

// readProcessStatus parses the four lines of /proc/<pid>/status this collector needs.
//
// The second return value is whether the file could be read, which is what PostureKnown is set from.
func readProcessStatus(path string) (processStatus, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return processStatus{}, false
	}
	status := processStatus{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		switch key {
		case "Uid":
			if uid, convErr := strconv.Atoi(fields[0]); convErr == nil {
				status.realUID = uid
			}
		case "CapEff":
			if mask, convErr := strconv.ParseUint(fields[0], 16, 64); convErr == nil {
				status.capEff = mask
			}
		case "Seccomp":
			if mode, convErr := strconv.Atoi(fields[0]); convErr == nil {
				status.seccomp = mode
				status.seccompSeen = true
			}
		}
	}
	return status, true
}

// namespacePids returns the NSpid entries of a process, outermost first.
//
// It is separate from readProcessStatus because it is asked of every pid in a cgroup while the rest of
// the status file is only ever read for the one that turns out to be the main process.
func namespacePids(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		if value, found := strings.CutPrefix(scanner.Text(), "NSpid:"); found {
			return strings.Fields(value)
		}
	}
	return nil
}

// fullCapabilitySet returns the mask a fully privileged process holds on this kernel.
//
// It is read once per scan rather than per container, because it is a property of the kernel and
// re-reading it for every container would be the same answer at a hundred times the cost.
func fullCapabilitySet(procRoot string) uint64 {
	last := int64(capLastCapFallback)
	if value, ok := readInt(filepath.Join(procRoot, capLastCapPath)); ok && value >= 0 && value < 63 {
		last = value
	}
	return uint64(1)<<uint(last+1) - 1
}

// bootTime returns the host's boot time in seconds since the epoch, or 0 if /proc/stat cannot say.
//
// It is the other half of the process start time: /proc/<pid>/stat measures from boot, so without
// btime the number is an uptime rather than a timestamp, and a report full of 1970 dates is worse than
// a report with no dates at all.
func bootTime(procRoot string) int64 {
	raw, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return 0
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		if value, found := strings.CutPrefix(scanner.Text(), "btime "); found {
			if seconds, convErr := strconv.ParseInt(strings.TrimSpace(value), 10, 64); convErr == nil {
				return seconds
			}
		}
	}
	return 0
}

// processStart converts /proc/<pid>/stat's starttime into a wall-clock time.
//
// Field 22 is counted from the start of the line, but the second field is the executable name in
// parentheses and may itself contain spaces and parentheses — a process called "(evil) x" is enough to
// break a naive split, and is a name anybody can choose. Everything after the *last* closing
// parenthesis is field 3 onwards, which is what makes this parse correct rather than usually correct.
func processStart(statPath string, btime int64) (time.Time, bool) {
	raw, err := os.ReadFile(statPath)
	if err != nil || btime == 0 {
		return time.Time{}, false
	}
	line := string(raw)
	lastParen := strings.LastIndex(line, ")")
	if lastParen < 0 {
		return time.Time{}, false
	}
	fields := strings.Fields(line[lastParen+1:])
	// fields[0] is field 3 of the line, so field 22 is at index 19.
	const starttimeIndex = 19
	if len(fields) <= starttimeIndex {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseInt(fields[starttimeIndex], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(btime+ticks/clockTicksPerSecond, 0).UTC(), true
}

// unifiedCgroupPath returns the path from the "0::" line of a /proc/<pid>/cgroup file.
//
// Hierarchy 0 with an empty controller list is the cgroup v2 unified hierarchy. A v1 host has numbered
// lines with controller names instead and no "0::" line at all, so this returns "" there — which is
// what makes an unsupported v1 host report no containers rather than nonsense.
func unifiedCgroupPath(raw []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		if path, found := strings.CutPrefix(scanner.Text(), "0::"); found {
			return strings.TrimSpace(path)
		}
	}
	return ""
}

// dockerContainerID returns the container id in a cgroup path, or "" if it is not a Docker container.
//
// Two shapes are matched, which is the whole point of enumerating from /proc: "docker-<id>.scope" is
// the systemd cgroup driver, the default on cgroup v2, and a "docker" segment followed by the bare id
// is the cgroupfs driver. Matching them at any depth covers a custom --cgroup-parent and rootless
// Docker under a user slice, neither of which lives where a fixed path would look.
//
// Kubernetes pods are excluded explicitly. A kubepods slice holds containers created by the kubelet
// through a CRI runtime, and dockershim-era clusters put them in scopes named exactly like Docker's —
// reporting those as Docker containers would tell an operator that a machine they manage with
// kubectl is one they can manage with docker.
func dockerContainerID(path string) string {
	segments := strings.Split(path, "/")
	for _, segment := range segments {
		if segment == "kubepods" || segment == "kubepods.slice" ||
			strings.HasPrefix(segment, "kubepods-") {
			return ""
		}
	}
	for i, segment := range segments {
		if id, found := strings.CutSuffix(segment, ".scope"); found {
			if id, ok := strings.CutPrefix(id, "docker-"); ok && isContainerID(id) {
				return id
			}
			continue
		}
		if segment == "docker" && i+1 < len(segments) && isContainerID(segments[i+1]) {
			return segments[i+1]
		}
	}
	return ""
}

// isRuntimeService reports whether a cgroup path belongs to a container runtime's own daemon.
//
// It is how an empty container list can say "nothing is installed here" rather than leaving an
// operator to guess whether the collector works. The daemon's own processes are never containers, so
// recognising them costs nothing extra: the scan is already reading every process's cgroup line.
func isRuntimeService(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		switch {
		case segment == "docker.service", segment == "containerd.service":
			return true
		case strings.HasPrefix(segment, "snap.docker.") && strings.HasSuffix(segment, ".service"):
			return true
		}
	}
	return false
}

// isContainerID reports whether a string is a full-length Docker container id.
//
// Docker ids are 32 bytes rendered as 64 lowercase hex characters. Checking the shape rather than
// accepting whatever followed the prefix is what keeps a directory somebody created by hand under
// /sys/fs/cgroup/docker from appearing in a fleet report as a container.
func isContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// cgroupProcs reads the pids in a cgroup.procs file.
//
// It is the authoritative membership list for a cgroup, where the pids found by walking /proc are only
// the ones this agent could read. The two agree on an ordinary host and diverge on a restricted one,
// which is why the count says which of them it came from.
func cgroupProcs(path string) ([]int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, line := range strings.Fields(string(raw)) {
		if pid, convErr := strconv.Atoi(line); convErr == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// readKeyedFile parses a cgroup file of "key value" lines into a map.
//
// cpu.stat, memory.stat, memory.events and cgroup.events all have this shape, and parsing them once
// rather than four times is the difference between one place where a malformed line is handled and
// four places where it might not be.
func readKeyedFile(path string) (map[string]int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	values := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if value, convErr := strconv.ParseInt(fields[1], 10, 64); convErr == nil {
			values[fields[0]] = value
		}
	}
	return values, true
}

// readInt reads a cgroup or procfs file holding a single integer.
//
// The boolean says whether the file was there, which every caller needs: an absent controller file and
// a controller reporting zero are different claims, and this package refuses to let them encode the
// same way.
func readInt(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// readMemoryMax reads memory.max, treating the literal "max" as no limit at all.
//
// An unlimited container is reported as having no limit field rather than as having a limit of
// 9223372036854771712, which is what the kernel would have to invent to express "max" as a number and
// what a client would then render as an 8-exabyte quota.
func readMemoryMax(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	text := strings.TrimSpace(string(raw))
	if text == "max" {
		return 0, false
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}
