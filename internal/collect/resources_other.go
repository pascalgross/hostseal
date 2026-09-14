//go:build !linux

package collect

// diskUsage reports that filesystem capacity cannot be measured on this operating system.
//
// It exists so that internal/collect keeps compiling for Windows, where the agent runs the read tier and
// where /proc does not exist either — so the whole resource scan comes up empty there, says so through
// ResourceReport.ScanComplete and its note, and reports nothing it has not measured. A Windows
// implementation would be GetDiskFreeSpaceEx over the drive letters, and it is not written rather than
// stubbed out to return plausible zeroes: docs/SECURITY.md §12 is explicit that a Windows host answers
// what it can and refuses to approximate the rest, and a disk report of nought bytes free is exactly the
// approximation that would page somebody at three in the morning.
func diskUsage(string) (filesystemUsage, bool) {
	return filesystemUsage{}, false
}
