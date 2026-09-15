package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pascalgross/hostseal/internal/canonical"
)

// fixtureCapacity is the capacity every fixture filesystem reports unless a test says otherwise.
//
// Statfs is a system call with no file behind it, so it cannot be put in a fixture tree the way
// /proc/meminfo can; the numbers arrive through the function collectResourcesFrom takes instead. They
// are spelled out here rather than inline so that a failing test names a disk rather than a literal.
//
// Two hundred gibibytes with a hundred and fifty gone, five of which are the root reserve: used over
// used-plus-available is 150/195, which is 76 per cent, while used over total would be 75. The fixture
// is chosen so that the two definitions give different answers — a test that could not tell them apart
// would pass on the wrong one.
var fixtureCapacity = filesystemUsage{
	sizeBytes:      200 << 30,
	usedBytes:      150 << 30,
	availableBytes: 45 << 30,
	inodesTotal:    1000,
	inodesUsed:     123,
}

// resourcesIn runs the scan against one fixture tree with a fixed capacity for every filesystem.
func resourcesIn(t *testing.T, scenario string) ResourceReport {
	t.Helper()
	return resourcesInWith(t, scenario, func(string) (filesystemUsage, bool) { return fixtureCapacity, true })
}

// resourcesInWith runs the scan against one fixture tree with a capacity reader the test chooses.
//
// The trees are real /proc shapes rather than minimal invented ones, for the reason the container
// fixtures are: every trap this file exists to catch — the aggregate cpu line, the kibibyte suffix, the
// interface name glued to its first counter — lives in the parts a minimal fixture would leave out.
func resourcesInWith(t *testing.T, scenario string,
	usage func(string) (filesystemUsage, bool)) ResourceReport {

	t.Helper()
	dir := filepath.Join("testdata", "resources", scenario)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("fixture tree %s: %v", scenario, err)
	}
	return collectResourcesFrom(filepath.Join(dir, "proc"), usage)
}

// byMountPoint indexes a report so a test can name the filesystem it is asserting about.
func byMountPoint(report ResourceReport) map[string]Filesystem {
	out := map[string]Filesystem{}
	for _, fs := range report.Filesystems {
		out[fs.MountPoint] = fs
	}
	return out
}

// byInterface indexes a report so a test can name the interface it is asserting about.
func byInterface(report ResourceReport) map[string]InterfaceTraffic {
	out := map[string]InterfaceTraffic{}
	for _, iface := range report.Interfaces {
		out[iface.Name] = iface
	}
	return out
}

// TestAnOrdinaryHostReportsItsCapacity covers the shape almost every host has.
//
// It is where the numbers are checked in full, because a wrong figure here is the one an operator would
// notice by comparing this against `df -h` and `free -m` — and the two definitions this file could have
// used for each of them differ by exactly the amount that makes a dashboard untrustworthy.
func TestAnOrdinaryHostReportsItsCapacity(t *testing.T) {
	report := resourcesIn(t, "ordinary")

	if !report.ScanComplete {
		t.Fatalf("the scan reported itself incomplete on an ordinary host: %q", report.Note)
	}
	if report.Note != "" {
		t.Errorf("an ordinary host carries a note: %q", report.Note)
	}

	if report.CPU == nil {
		t.Fatal("no cpu section on a host whose /proc/stat lists two processors")
	}
	if report.CPU.Cores != 2 {
		// The aggregate "cpu " line is not a processor. Counting it reports every single-core host as
		// having two, which halves every load figure on the fleet.
		t.Errorf("cores is %d, want 2 — the aggregate cpu line is not a processor", report.CPU.Cores)
	}
	if report.CPU.LoadPerCorePercent == nil {
		t.Fatal("no load figure on a host whose /proc/loadavg is readable")
	}
	// The fixture's fifteen-minute load is 0.71, and 71 hundredths over two processors is thirty-five per
	// cent of one of them once banded down to five. Reading the one-minute figure instead would give 75,
	// which is what makes this assertion worth having: the two windows are in the same file, one field
	// apart, and the noisy one is the one that looks obvious.
	if got := *report.CPU.LoadPerCorePercent; got != 35 {
		t.Errorf("loadPerCorePercent is %d, want 35 — it must read the fifteen-minute average", got)
	}

	if report.Memory == nil {
		t.Fatal("no memory section on a host whose /proc/meminfo is readable")
	}
	// 8167848 kB, in bytes. A report of 8167848 means the kibibyte suffix was dropped.
	if want := int64(8167848) * 1024; report.Memory.TotalBytes != want {
		t.Errorf("totalBytes is %d, want %d — /proc/meminfo is in kibibytes",
			report.Memory.TotalBytes, want)
	}
	if report.Memory.UsedPercent == nil {
		t.Fatal("no memory use on a host whose /proc/meminfo carries MemAvailable")
	}
	// MemAvailable is exactly half of MemTotal. Computing this from MemFree instead would report 97 per
	// cent, which is what makes every healthy Linux host look like it is out of memory.
	if got := *report.Memory.UsedPercent; got != 50 {
		t.Errorf("memory usedPercent is %d, want 50 — it must come from MemAvailable, not MemFree", got)
	}
	if want := int64(2097152) * 1024; report.Memory.SwapTotalBytes != want {
		t.Errorf("swapTotalBytes is %d, want %d", report.Memory.SwapTotalBytes, want)
	}
	if report.Memory.SwapUsedPercent == nil || *report.Memory.SwapUsedPercent != 25 {
		t.Errorf("swapUsedPercent is %v, want 25", report.Memory.SwapUsedPercent)
	}
}

// TestOnlyFilesystemsThatCanFillUpAreReported covers every rule that keeps a mount out of the list.
//
// The fixture's mount table holds one of each: a pseudo filesystem, a tmpfs, a read-only squashfs of the
// kind snap creates by the dozen, a read-only data disk, and a bind mount of a filesystem already
// listed. Each is excluded for its own reason, and a change that lost one of the reasons would still
// produce a plausible-looking list.
func TestOnlyFilesystemsThatCanFillUpAreReported(t *testing.T) {
	report := resourcesIn(t, "ordinary")

	var points []string
	for _, fs := range report.Filesystems {
		points = append(points, fs.MountPoint)
	}
	if got := strings.Join(points, " "); got != "/ /var" {
		t.Fatalf("filesystems are %q, want %q", got, "/ /var")
	}
	if report.FilesystemsTotal != 2 {
		t.Errorf("filesystemsTotal is %d, want 2", report.FilesystemsTotal)
	}
	if report.FilesystemsTruncated {
		t.Error("a two-filesystem host reports its list as truncated")
	}

	root := byMountPoint(report)["/"]
	if root.Device != "/dev/vda1" || root.Type != "ext4" {
		t.Errorf("/ is %q (%s), want /dev/vda1 (ext4)", root.Device, root.Type)
	}
	if root.SizeBytes != fixtureCapacity.sizeBytes {
		t.Errorf("/ sizeBytes is %d, want %d", root.SizeBytes, fixtureCapacity.sizeBytes)
	}
	// 150 used over 195 available-to-anybody is 76 per cent, which is what df prints. Dividing by the
	// total instead gives 75, and the fixture exists to tell those apart.
	if root.UsedPercent != 76 {
		t.Errorf("/ usedPercent is %d, want 76 — it must exclude the root reserve from the denominator",
			root.UsedPercent)
	}
	if root.InodesUsedPercent == nil || *root.InodesUsedPercent != 12 {
		t.Errorf("/ inodesUsedPercent is %v, want 12", root.InodesUsedPercent)
	}
}

// TestADiskMountedTwiceIsCountedOnce covers the bind mount in the ordinary fixture.
//
// /mnt/backup is a bind mount of a subtree of the same device as /. Reporting it as a second filesystem
// would make a fleet's total capacity larger than the disks anybody bought, and it would do so on
// exactly the hosts that are carefully organised.
func TestADiskMountedTwiceIsCountedOnce(t *testing.T) {
	report := resourcesIn(t, "ordinary")

	devices := map[string]int{}
	for _, fs := range report.Filesystems {
		devices[fs.Device]++
	}
	if devices["/dev/vda1"] != 1 {
		t.Errorf("/dev/vda1 appears %d times, want once", devices["/dev/vda1"])
	}
	if _, bound := byMountPoint(report)["/mnt/backup"]; bound {
		t.Error("a bind mount of an already-reported device is in the list")
	}
}

// TestTheSandboxIsReportedRatherThanLetToLie covers the agent's own systemd unit hiding /home.
//
// ProtectHome=yes and PrivateTmp=yes put an empty filesystem over /home, /root and /tmp inside the
// agent's mount namespace, so a host whose /home is a separate partition has one this scan cannot see.
// Skipping it silently would be a disk that is simply missing from a disk report — a plausible answer
// arrived at by not looking, which is the failure this package is written against.
func TestTheSandboxIsReportedRatherThanLetToLie(t *testing.T) {
	report := resourcesIn(t, "sandboxed")

	if !report.ScanComplete {
		t.Errorf("the sandbox made the scan report itself incomplete: %q", report.Note)
	}
	for _, hidden := range []string{"/home", "/root", "/tmp"} {
		if !strings.Contains(report.Note, hidden) {
			t.Errorf("the note does not name %s: %q", hidden, report.Note)
		}
	}
	if !strings.Contains(report.Note, "sandbox") {
		t.Errorf("the note does not say why those paths are missing: %q", report.Note)
	}
	if _, present := byMountPoint(report)["/home"]; present {
		t.Error("the empty filesystem the sandbox mounts over /home is reported as a disk")
	}
}

// TestInterfaceTrafficIsReadFromTheGluedFormat covers /proc/net/dev's two traps at once.
//
// The interface name is glued to its first counter when the name is long enough, and the file opens with
// two header lines carrying no counters at all. Splitting the whole line on whitespace — the obvious
// implementation — gets both wrong, and gets them wrong by shifting every column by one, which reports
// transmitted bytes as received.
func TestInterfaceTrafficIsReadFromTheGluedFormat(t *testing.T) {
	report := resourcesIn(t, "ordinary")

	if len(report.Interfaces) != 2 {
		t.Fatalf("found %d interfaces, want 2 (loopback excluded): %+v",
			len(report.Interfaces), report.Interfaces)
	}
	if report.Interfaces[0].Name >= report.Interfaces[1].Name {
		t.Errorf("interfaces are not sorted by name: %q then %q",
			report.Interfaces[0].Name, report.Interfaces[1].Name)
	}
	if _, loopback := byInterface(report)["lo"]; loopback {
		t.Error("the loopback interface is reported")
	}

	eth0 := byInterface(report)["eth0"]
	if eth0.ReceivedGiB != 412 || eth0.TransmittedGiB != 90 {
		t.Errorf("eth0 moved %d/%d GiB, want 412/90 — received and transmitted may be swapped",
			eth0.ReceivedGiB, eth0.TransmittedGiB)
	}
	if eth0.ReceiveErrors != 3 || eth0.ReceiveDrops != 7 {
		t.Errorf("eth0 receive errors/drops are %d/%d, want 3/7", eth0.ReceiveErrors, eth0.ReceiveDrops)
	}
	if eth0.TransmitErrors != 1 || eth0.TransmitDrops != 2 {
		t.Errorf("eth0 transmit errors/drops are %d/%d, want 1/2",
			eth0.TransmitErrors, eth0.TransmitDrops)
	}

	// One byte short of a gibibyte, which must round down rather than up: a host that has moved almost
	// nothing should read as nothing rather than as one.
	if eth1 := byInterface(report)["eth1"]; eth1.ReceivedGiB != 0 {
		t.Errorf("eth1 received %d GiB from 1073741823 bytes, want 0", eth1.ReceivedGiB)
	}
}

// TestAnUnreadableProcMakesTheResourceScanIncompleteRatherThanAnError covers the degraded case.
//
// A collector that returned an error would have its section dropped entirely, which tells an operator
// nothing; a report of zero bytes everywhere would tell them something false. The flag and the note are
// the third answer.
func TestAnUnreadableProcMakesTheResourceScanIncompleteRatherThanAnError(t *testing.T) {
	report := resourcesIn(t, "unreadable")

	if report.ScanComplete {
		t.Error("a scan that could read nothing reports itself complete")
	}
	if report.Note == "" {
		t.Error("an incomplete scan carries no note saying what could not be read")
	}
	if report.CPU != nil || report.Memory != nil {
		t.Errorf("sections were reported from files that do not exist: cpu=%+v memory=%+v",
			report.CPU, report.Memory)
	}
	if report.Filesystems == nil || report.Interfaces == nil {
		// Nil encodes as null rather than as [], and "I looked and found none" must not encode the same
		// way as "this section was not produced".
		t.Error("the lists are nil rather than empty")
	}
}

// TestAFilesystemStatfsRefusesIsNamedRatherThanDroppedInSilence covers a mount that cannot be measured.
//
// A mount point this agent cannot traverse is the usual cause once remote filesystems are excluded
// outright. Both obvious answers are wrong in opposite directions: a row of zeroes reads as a disk with
// nothing on it, and a silently missing row reads as a host that never had the disk. The third answer is
// no row, a name in filesystemsUnmeasured, a note, and scanComplete false — because a client acting on
// that one boolean must not be told the list is complete when a disk on it could not be measured.
func TestAFilesystemStatfsRefusesIsNamedRatherThanDroppedInSilence(t *testing.T) {
	report := resourcesInWith(t, "ordinary", func(mountPoint string) (filesystemUsage, bool) {
		if mountPoint == "/var" {
			return filesystemUsage{}, false
		}
		return fixtureCapacity, true
	})

	if _, present := byMountPoint(report)["/var"]; present {
		t.Error("a filesystem statfs refused is in the list as a row")
	}
	if _, present := byMountPoint(report)["/"]; !present {
		t.Error("one unmeasurable filesystem removed the others")
	}
	if got := strings.Join(report.FilesystemsUnmeasured, " "); got != "/var" {
		t.Errorf("filesystemsUnmeasured is %q, want %q", got, "/var")
	}
	if report.ScanComplete {
		t.Error("a scan that could not measure a filesystem it found reports itself complete")
	}
	if !strings.Contains(report.Note, "/var") {
		t.Errorf("the note does not name the mount point that could not be measured: %q", report.Note)
	}
}

// TestADiskMeasuredThroughOneMountIsNotAlsoCalledUnmeasured covers the two lists disagreeing.
//
// The ordinary fixture has /dev/vda1 at both "/" and "/mnt/backup". If the bind mount is the one that
// cannot be traversed, the disk is still measured — and a report that gave its size in one field and
// named it as unmeasurable in another would be a report that contradicted itself.
func TestADiskMeasuredThroughOneMountIsNotAlsoCalledUnmeasured(t *testing.T) {
	report := resourcesInWith(t, "ordinary", func(mountPoint string) (filesystemUsage, bool) {
		if mountPoint == "/" {
			return filesystemUsage{}, false
		}
		return fixtureCapacity, true
	})

	if len(report.FilesystemsUnmeasured) != 0 {
		t.Errorf("a disk measured through /mnt/backup is also named unmeasured: %v",
			report.FilesystemsUnmeasured)
	}
	if !report.ScanComplete {
		t.Errorf("the scan reports itself incomplete although every disk was measured: %q", report.Note)
	}
}

// TestRemoteFilesystemsAreRefusedAndSaidSo is the one finding on this collector that could stop a fleet.
//
// statfs on a hard-mounted NFS share whose server has gone away blocks in uninterruptible sleep: no
// context, no timeout and no signal reaches it. The scan runs inside the heartbeat, so one such mount
// would wedge the heartbeat loop and the job poll behind it, and the host would vanish from the fleet
// list — which is the failure internal/collect is arranged around. The fix is to refuse to ask; this
// asserts both halves of it, because refusing in silence would leave an operator looking for a /srv the
// report does not mention.
func TestRemoteFilesystemsAreRefusedAndSaidSo(t *testing.T) {
	// A capacity reader that fails the test rather than answering: nothing in the remote fixture may
	// reach statfs at all, which is the whole point. A stub that returned a plausible number would let
	// the bug back in while the test went on passing.
	report := resourcesInWith(t, "remote", func(mountPoint string) (filesystemUsage, bool) {
		if mountPoint != "/" {
			t.Errorf("the scan called statfs on %q, which is a remote or userspace mount point and "+
				"can block this agent for ever", mountPoint)
		}
		return fixtureCapacity, true
	})

	var points []string
	for _, fs := range report.Filesystems {
		points = append(points, fs.MountPoint)
	}
	if got := strings.Join(points, " "); got != "/" {
		t.Errorf("filesystems are %q, want just the local root", got)
	}
	for _, want := range []string{"/srv/shared", "/mnt/windows", "/mnt/remote-home", "/mnt/ntfs"} {
		if !strings.Contains(report.Note, want) {
			t.Errorf("the note does not name the skipped mount %s: %q", want, report.Note)
		}
	}

	// Refused by decision rather than by failure, so the scan is complete and the mounts are not named
	// as unmeasurable. The two are different claims: one says this agent chose not to look, the other
	// says it looked and could not see.
	if !report.ScanComplete {
		t.Errorf("refusing to probe a remote mount made the scan report itself incomplete: %q",
			report.Note)
	}
	if len(report.FilesystemsUnmeasured) != 0 {
		t.Errorf("a deliberately skipped mount is reported as unmeasurable: %v",
			report.FilesystemsUnmeasured)
	}
}

// TestRefusedFilesystemSeparatesItsTwoReasons covers the predicate directly.
//
// The two reasons must stay two reasons: a virtual filesystem has no disk behind it, and a remote or
// userspace one has a disk this agent must not ask about. Only the second is worth telling an operator,
// and folding them together would either fill the note with tmpfs rows or drop the sentence that
// explains a missing /srv.
func TestRefusedFilesystemSeparatesItsTwoReasons(t *testing.T) {
	cases := map[string][2]bool{
		"ext4":           {false, false},
		"xfs":            {false, false},
		"btrfs":          {false, false},
		"bcachefs":       {false, false},
		"tmpfs":          {true, false},
		"squashfs":       {true, false},
		"overlay":        {true, false},
		"nfs":            {true, true},
		"nfs4":           {true, true},
		"cifs":           {true, true},
		"ceph":           {true, true},
		"fuse.sshfs":     {true, true},
		"fuse.ntfs-3g":   {true, true},
		"fuse.glusterfs": {true, true},
	}
	for fsType, want := range cases {
		refused, remote := refusedFilesystem(fsType)
		if refused != want[0] || remote != want[1] {
			t.Errorf("refusedFilesystem(%q) = %t, %t, want %t, %t",
				fsType, refused, remote, want[0], want[1])
		}
	}
}

// TestAnUnmeasurableMountDoesNotSuppressAMeasurableOne guards the order of two lines.
//
// A device is reported once, and which of its mounts supplies the row is decided by path order — but a
// device must not be *consumed* by a mount that could not be measured. The ordinary fixture has
// /dev/vda1 at both "/" and "/mnt/backup", and "/" sorts first: marking the device seen before the
// measurement succeeded would let a "/" this agent cannot statfs take the slot and hide a bind mount of
// the same disk that it can. The disk would then be missing from the report with scanComplete still
// true, which is the failure this whole file is written against.
func TestAnUnmeasurableMountDoesNotSuppressAMeasurableOne(t *testing.T) {
	report := resourcesInWith(t, "ordinary", func(mountPoint string) (filesystemUsage, bool) {
		if mountPoint == "/" {
			return filesystemUsage{}, false
		}
		return fixtureCapacity, true
	})

	if _, present := byMountPoint(report)["/mnt/backup"]; !present {
		t.Errorf("an unmeasurable / consumed its device, hiding the same disk at /mnt/backup: %+v",
			report.Filesystems)
	}
}

// TestFilesystemsAreCountedBeforeTruncating covers the cap on the filesystem list.
//
// A host over the limit must report the real total and say the list was cut, because reporting fifty as
// though it were all of them is a quietly wrong answer to the question that was asked.
func TestFilesystemsAreCountedBeforeTruncating(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc", "self")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	var lines strings.Builder
	for i := range MaxFilesystems + 7 {
		// A distinct device each time, so nothing is deduplicated, and a zero-padded mount point so that
		// the sort order is the numeric one and the assertion below can name the cut.
		lines.WriteString(strings.NewReplacer("N", itoa(i)).Replace(
			"30 1 8:N / /disk-N rw,relatime - ext4 /dev/sdN rw\n"))
	}
	if err := os.WriteFile(filepath.Join(proc, "mountinfo"), []byte(lines.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	report := collectResourcesFrom(filepath.Join(root, "proc"),
		func(string) (filesystemUsage, bool) { return fixtureCapacity, true })

	if report.FilesystemsTotal != MaxFilesystems+7 {
		t.Errorf("filesystemsTotal is %d, want %d", report.FilesystemsTotal, MaxFilesystems+7)
	}
	if len(report.Filesystems) != MaxFilesystems {
		t.Errorf("reported %d filesystems, want the cap of %d", len(report.Filesystems), MaxFilesystems)
	}
	if !report.FilesystemsTruncated {
		t.Error("a cut list is not flagged as truncated")
	}
}

// itoa renders a small non-negative integer, zero-padded to three digits.
//
// Zero-padded so that a lexicographic sort over the generated mount points is also the numeric one,
// which is what lets the truncation test say which rows survived the cut rather than only how many.
func itoa(n int) string {
	digits := []byte{byte('0' + n/100%10), byte('0' + n/10%10), byte('0' + n%10)}
	return string(digits)
}

// TestTwoConsecutiveSamplesProduceOneDigest is the property this whole section is shaped around.
//
// The gate ships **on**, so every host in every fleet carries this section — which makes
// docs/PROTOCOL.md §4.1 the thing that has to survive it. A digest saves nothing on a section that is
// never twice the same, and §4.1 calls losing it a production incident rather than an inefficiency. The
// banding is the mechanism; this is the assertion that the mechanism works, and without it the four
// bands are four numbers nobody ever checks.
//
// The two fixtures are a minute apart on an ordinary working host: the load average moved, the page
// cache breathed, swap moved a little, and the interfaces carried a hundred megabytes. None of it is a
// change an operator would act on, and none of it may change the digest. A failure here means a band is
// too fine — not that the fixture is wrong.
func TestTwoConsecutiveSamplesProduceOneDigest(t *testing.T) {
	first, err := canonical.Digest(resourcesIn(t, "ordinary"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonical.Digest(resourcesIn(t, "ordinary-later"))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		before, _ := canonical.Marshal(resourcesIn(t, "ordinary"))
		after, _ := canonical.Marshal(resourcesIn(t, "ordinary-later"))
		t.Errorf("an ordinary minute changed the facts digest, so this host sends a full report on "+
			"every heartbeat\n before: %s\n  after: %s", before, after)
	}
}

// TestAChangeWorthSeeingDoesChangeTheDigest is the other half, and it is the one that keeps the first
// honest.
//
// A band wide enough to hold still through anything is a field that reports nothing. This asserts the
// opposite direction: a filesystem that has genuinely filled up since the last beat must change the
// digest, because that is the heartbeat somebody needs to receive.
func TestAChangeWorthSeeingDoesChangeTheDigest(t *testing.T) {
	quiet, err := canonical.Digest(resourcesIn(t, "ordinary"))
	if err != nil {
		t.Fatal(err)
	}
	filling := filesystemUsage{
		sizeBytes:      fixtureCapacity.sizeBytes,
		usedBytes:      190 << 30,
		availableBytes: 5 << 30,
		inodesTotal:    fixtureCapacity.inodesTotal,
		inodesUsed:     fixtureCapacity.inodesUsed,
	}
	loud, err := canonical.Digest(resourcesInWith(t, "ordinary",
		func(string) (filesystemUsage, bool) { return filling, true }))
	if err != nil {
		t.Fatal(err)
	}
	if quiet == loud {
		t.Error("a root filesystem going from 76% to 97% full did not change the facts digest")
	}
}

// TestResourceReportCarriesNoFloatingPointValues covers the constraint that would break every heartbeat.
//
// docs/PROTOCOL.md §8 rejects floats outright, and the facts document is digested with the same encoder.
// A float anywhere in this section would not break this section: it would fail canonical.Digest and take
// the entire heartbeat with it, on every cycle, on every host — and unlike the container section, this
// one ships on. That is why every percentage here is a whole number and why the load average is parsed
// into hundredths by hand rather than through strconv.ParseFloat.
func TestResourceReportCarriesNoFloatingPointValues(t *testing.T) {
	for _, scenario := range []string{
		"ordinary", "ordinary-later", "protected", "remote", "sandboxed", "unreadable",
	} {
		if _, err := canonical.Marshal(resourcesIn(t, scenario)); err != nil {
			t.Errorf("%s: the report does not canonicalise: %v", scenario, err)
		}
	}
}

// TestTheResourceScanFlagSurvivesEncodingWhenFalse covers the omitempty rule on the flag that matters.
//
// A flag whose alarming value is false must not carry omitempty, or it vanishes from the wire in exactly
// the case worth seeing. The same assertion guards ContainerReport.ScanComplete one file over.
func TestTheResourceScanFlagSurvivesEncodingWhenFalse(t *testing.T) {
	raw, err := json.Marshal(resourcesIn(t, "unreadable"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"scanComplete":false`, `"filesystems":[]`, `"interfaces":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the encoded report does not contain %s: %s", want, raw)
		}
	}
}

// TestBandsRoundDownRatherThanToNearest covers the direction of the rounding.
//
// Down, so that a reported figure is never higher than the truth: an operator acting on "90% full"
// should find at most ninety-four per cent gone. Rounding to nearest would put a host at 88 into the 90
// band and make the alert that fired unexplainable from the number printed beside it.
func TestBandsRoundDownRatherThanToNearest(t *testing.T) {
	cases := map[int]int{0: 0, 1: 0, 4: 0, 5: 5, 9: 5, 88: 85, 90: 90, 94: 90, 100: 100}
	for value, want := range cases {
		if got := band(value, 5); got != want {
			t.Errorf("band(%d, 5) = %d, want %d", value, got, want)
		}
	}
	// A band of one is the identity, which is what makes filesystemBandPercent's one a real setting
	// rather than a special case the caller has to know about.
	for _, value := range []int{0, 37, 99} {
		if got := band(value, 1); got != value {
			t.Errorf("band(%d, 1) = %d, want %d", value, got, value)
		}
	}
}

// TestPercentClampsRatherThanOverflowing covers the arithmetic at both ends.
//
// A filesystem can report more used than the caller's denominator while it is being resized, and a disk
// shown as 104% full is a bug report about the dashboard rather than about the disk. A zero denominator
// is the same question asked about a filesystem with no blocks.
//
// The petabyte rows are the ones with teeth, and the test was named for them long before it exercised
// them. Multiplying a byte count by a hundred overflows an int64 above about 82 PiB, and the negative
// clamp one line down would then absorb the wrap and report a filesystem that is ninety per cent gone as
// nought per cent — a plausible wrong answer rather than a visible failure, which is the shape this
// package refuses. Above roughly 170 PiB the wrapped product comes back *positive* and the clamp cannot
// see it at all. A CephFS, Lustre or GPFS mount is neither virtual nor read-only, so it reaches this
// arithmetic through the ordinary path on an ordinary Debian node.
func TestPercentClampsRatherThanOverflowing(t *testing.T) {
	const pib = 1 << 50
	cases := []struct {
		part, total int64
		want        int
	}{
		{0, 100, 0}, {50, 100, 50}, {100, 100, 100}, {150, 100, 100}, {-5, 100, 0}, {5, 0, 0}, {5, -1, 0},
		// Below the threshold, where multiplying first is exact.
		{80 * pib, 90 * pib, 88},
		// Above it: without the scaling branch these report 0, 0 and 96 respectively, and only the first
		// two of those are visible as wrong.
		{90 * pib, 100 * pib, 90},
		{100 * pib, 110 * pib, 90},
		{250 * pib, 260 * pib, 96},
	}
	for _, c := range cases {
		if got := percent(c.part, c.total); got != c.want {
			t.Errorf("percent(%d, %d) = %d, want %d", c.part, c.total, got, c.want)
		}
	}
}

// TestLoadAverageIsParsedWithoutAFloat covers the hand-rolled decimal reader.
//
// It is hand-rolled precisely so that no float exists anywhere in the file to leak into a field by
// accident, which makes the table of odd spellings worth having: a truncated fraction, a padded one, an
// integer load with no point at all, and the truncated file a container's /proc sometimes is. Every case
// puts a distinct value in the fifteen-minute column, so reading the wrong one of the three fails here
// rather than looking plausible on a dashboard.
func TestLoadAverageIsParsedWithoutAFloat(t *testing.T) {
	cases := map[string]int64{
		"1.50 0.98 0.71 2/318 5678": 71,
		"0.00 0.00 0.00 1/100 2":    0,
		"1.00 1.00 12.34 1/1 1":     1234,
		"1.00 1.00 1.5 1/1 1":       150,
		"1.00 1.00 1.5000 1/1 1":    150,
		"1.00 1.00 3 1/1 1":         300,
		"1.00 1.00":                 -1,
	}
	for contents, want := range cases {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "loadavg"), []byte(contents+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, ok := readLoadAverage(root)
		// A want of -1 marks a file with no fifteen-minute column, which must report itself unreadable
		// rather than fall back to a column that means something else.
		if want < 0 {
			if ok {
				t.Errorf("readLoadAverage(%q) = %d, true, want no answer", contents, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("readLoadAverage(%q) = %d, %t, want %d, true", contents, got, ok, want)
		}
	}
	if _, ok := readLoadAverage(t.TempDir()); ok {
		t.Error("a missing /proc/loadavg reports a load average anyway")
	}
}

// TestMeminfoKeepsItsUnitsAndLosesItsColon covers why readKeyedFile is not reused for this file.
//
// Every line of /proc/meminfo is "MemTotal:  8167848 kB": the key carries a colon and the value carries
// a unit. Reusing the cgroup reader would produce a map keyed on "MemTotal:" holding a number 1024 times
// too small, with nothing anywhere to say so — and a host reporting eight megabytes of RAM is odd enough
// to notice, while one reporting eight terabytes is not.
func TestMeminfoKeepsItsUnitsAndLosesItsColon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meminfo")
	contents := "MemTotal:        1024 kB\nHugePages_Total:       7\nAnonHugePages:      2 kB\nrubbish\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	values, ok := readMeminfo(path)
	if !ok {
		t.Fatal("a readable /proc/meminfo reported itself unreadable")
	}
	if values["MemTotal"] != 1024*1024 {
		t.Errorf("MemTotal is %d, want %d — the kB suffix is a kibibyte", values["MemTotal"], 1024*1024)
	}
	// A count rather than a size, and multiplying it by a kibibyte would be wrong. The suffix decides,
	// not the file.
	if values["HugePages_Total"] != 7 {
		t.Errorf("HugePages_Total is %d, want 7 — a value with no unit is not in kibibytes",
			values["HugePages_Total"])
	}
	if _, present := values["MemTotal:"]; present {
		t.Error("the key kept its colon")
	}
}

// TestAReadOnlyMountIsNotADiskThatCanFillUp covers the field this check must not read.
//
// **The second case is the one this test exists for, and it is a bug that shipped once.**
// `ProtectSystem=strict` in the agent's own unit is a read-only bind remount of the whole hierarchy, and
// a read-only bind remount writes `ro` into the *per-mount* options while the superblock keeps saying
// `rw` — verified against a real kernel, not assumed. A check that read the per-mount field would
// therefore find every filesystem on every host read-only and report none of them, silently, under
// exactly the systemd unit HostSeal ships.
//
// The rest of the table is the distinction that has to survive that fix: a filesystem that genuinely
// cannot be written says so in the superblock, which is what a squashfs image and a `mount -o ro` data
// disk both do.
func TestAReadOnlyMountIsNotADiskThatCanFillUp(t *testing.T) {
	cases := map[string]bool{
		// An ordinary writable filesystem.
		"30 1 8:1 / /a rw,relatime - ext4 /dev/sda1 rw": false,
		// The ProtectSystem=strict shape: read-only to this process, writable underneath.
		"73 48 254:0 /usr /usr ro,relatime - ext4 /dev/vda rw,resv_strict": false,
		// Genuinely read-only: the superblock says so.
		"30 1 8:1 / /a rw,relatime - ext4 /dev/sda1 ro":       true,
		"30 1 8:1 / /a rw,relatime - squashfs /dev/loop0 ro":  true,
		"30 1 8:1 / /a rw,relatime shared:1 - ext4 /d rw,ro":  true,
		"30 1 8:1 / /a rw,nosuid - ext4 /dev/sda1 rw,errors":  false,
		"30 1 8:1 / /a rw,relatime shared:1 - ext4 /d rw,rox": false,
		"30 1 8:1 / /a rw,relatime shared:1 - ext4 /d rw,nro": false,
	}
	for line, want := range cases {
		entry, ok := parseMountinfoLine(line)
		if !ok {
			t.Fatalf("parseMountinfoLine(%q) refused a well-formed line", line)
		}
		if got := entry.readOnly(); got != want {
			t.Errorf("readOnly(%q) = %t, want %t", line, got, want)
		}
	}
}

// TestASandboxedHierarchyStillReportsItsDisks is the same bug asserted end to end.
//
// The unit test above pins the predicate; this pins the consequence, because the consequence is what
// somebody would actually notice — and what nobody would notice, since the failure mode is an empty list
// rather than an error. The fixture is a mount table as the agent sees it under its own unit: every real
// filesystem bind-remounted read-only, /home and /tmp replaced, /proc still there.
func TestASandboxedHierarchyStillReportsItsDisks(t *testing.T) {
	report := resourcesIn(t, "protected")

	if len(report.Filesystems) == 0 {
		t.Fatalf("a host under the shipped systemd unit reports no filesystems at all: note %q",
			report.Note)
	}
	points := byMountPoint(report)
	for _, want := range []string{"/", "/var"} {
		if _, present := points[want]; !present {
			t.Errorf("%s is missing from a sandboxed host's report: %+v", want, report.Filesystems)
		}
	}
	// The genuinely read-only disk is still excluded, so the fix did not simply stop excluding things.
	if _, present := points["/mnt/readonly"]; present {
		t.Error("a filesystem whose superblock is read-only is reported as a disk that can fill up")
	}
}

// TestOctalEscapesInAMountPointAreDecoded covers a path the report now prints.
//
// Mountinfo escapes space, tab, newline and backslash, and until the mount point was reported rather
// than only compared, leaving them escaped cost nothing. It costs something now: "/mnt/my\040backup" is
// not a path an operator can paste into `df` or `du`.
func TestOctalEscapesInAMountPointAreDecoded(t *testing.T) {
	cases := map[string]string{
		`/mnt/my\040backup`: "/mnt/my backup",
		`/mnt/a\011b`:       "/mnt/a\tb",
		`/mnt/a\134b`:       `/mnt/a\b`,
		"/mnt/plain":        "/mnt/plain",
		// Not one of the four the kernel escapes, so it is left exactly as written rather than decoded
		// into something else.
		`/mnt/a\101b`: `/mnt/a\101b`,
	}
	for raw, want := range cases {
		if got := unescapeMountPath(raw); got != want {
			t.Errorf("unescapeMountPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestMountinfoCarriesTheDeviceAndTheSource covers the two fields the filesystem report added.
//
// They are reached by index from opposite ends of the line, which is the part that breaks silently: the
// optional fields before the separator have no fixed count, so a source read from the wrong side would
// be right on a mount with no propagation set and wrong on every mount that has one.
func TestMountinfoCarriesTheDeviceAndTheSource(t *testing.T) {
	cases := map[string]mountEntry{
		"30 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw": {
			point: "/", fsType: "ext4", deviceID: "252:1", source: "/dev/vda1",
		},
		"32 30 0:29 / /run rw,nosuid - tmpfs tmpfs rw,size=8k": {
			point: "/run", fsType: "tmpfs", deviceID: "0:29", source: "tmpfs",
		},
		"33 30 8:2 / /var rw,relatime shared:4 master:2 - xfs /dev/sdb2 rw": {
			point: "/var", fsType: "xfs", deviceID: "8:2", source: "/dev/sdb2",
		},
	}
	for line, want := range cases {
		entry, ok := parseMountinfoLine(line)
		if !ok {
			t.Fatalf("parseMountinfoLine(%q) refused a well-formed line", line)
		}
		if entry.point != want.point || entry.fsType != want.fsType ||
			entry.deviceID != want.deviceID || entry.source != want.source {
			t.Errorf("parseMountinfoLine(%q) = %+v, want point/type/device/source %q/%q/%q/%q",
				line, entry, want.point, want.fsType, want.deviceID, want.source)
		}
	}
	if _, ok := parseMountinfoLine("30 1 252:1 / / rw,relatime shared:1 ext4 /dev/vda1 rw"); ok {
		t.Error("a line with no separator was parsed anyway")
	}
}
