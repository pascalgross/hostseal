//go:build linux

package collect

import (
	"math"
	"syscall"
)

// diskUsage asks the kernel how large a mounted filesystem is and how much of it is gone.
//
// It is the one system call this package makes, and it is here rather than in resources.go because
// syscall.Statfs does not exist outside Unix — internal/collect carries no build constraint anywhere
// else and cross-compiles for Windows today, so a bare statfs in the shared file would break the
// Windows agent's build rather than degrade it.
//
// The standard library's syscall package rather than golang.org/x/sys/unix, deliberately: .golangci.yml
// denies that import across the whole repository because it offers Exec, Execve and Fexecve, which would
// make an execve reachable without importing os/exec at all. internal/privsep reaches SO_PEERCRED the
// same way and for the same reason.
func diskUsage(mountPoint string) (filesystemUsage, bool) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &fs); err != nil {
		// False rather than a zero-valued struct. statfs fails on an unreachable NFS mount and on a
		// directory this agent cannot traverse, and a filesystem of nought bytes is a claim about a disk
		// rather than an admission that nobody looked.
		return filesystemUsage{}, false
	}

	// Frsize is the fragment size the block counts below are actually expressed in; Bsize is the
	// "optimal transfer block size" and is the same number on every filesystem Linux ships without being
	// guaranteed to be. Using the wrong one scales every figure on the host by a constant, which looks
	// like a disk of the wrong size rather than like a units bug — so Frsize is preferred and Bsize is
	// the fallback for a filesystem that does not set it.
	//
	//nolint:unconvert // The conversion is a no-op on amd64, arm64 and riscv64, where these fields are
	// already int64 — and it is load-bearing on linux/arm and linux/386, where they are int32 and this
	// file would not compile without it. Only amd64 and arm64 are released, but the build tag on this
	// file is `linux`, so it claims the rest.
	blockSize := int64(fs.Frsize)
	if blockSize <= 0 {
		blockSize = int64(fs.Bsize) //nolint:unconvert // The same 32-bit case as the line above.
	}

	total := blocksToBytes(fs.Blocks, blockSize)
	free := blocksToBytes(fs.Bfree, blockSize)

	return filesystemUsage{
		sizeBytes: total,
		// Used is total less *free*, not less available: the root reserve is genuinely occupied by
		// nothing and counting it as used would report every fresh ext4 filesystem as five per cent
		// full. What the reserve does affect is the denominator, which describeFilesystem handles.
		usedBytes:      total - free,
		availableBytes: blocksToBytes(fs.Bavail, blockSize),
		// Files is zero on a filesystem that allocates inodes dynamically — btrfs and xfs among them —
		// and readFilesystems reads that zero as "this filesystem cannot run out of inodes" rather than
		// as "none are free". The counts are file counts rather than block counts, so they take the same
		// clamp with a block size of one.
		inodesTotal: blocksToBytes(fs.Files, 1),
		inodesUsed:  blocksToBytes(fs.Files-min(fs.Ffree, fs.Files), 1),
	}, true
}

// blocksToBytes multiplies an unsigned block count by a block size without wrapping.
//
// The kernel counts blocks in a uint64 and every field in filesystemUsage is a signed int64, so the
// conversion has to happen somewhere. Doing it here, once, with the bound checked first, is the
// difference between a filesystem larger than eight exabytes reporting a saturated figure and one
// reporting a *negative* size — which would sail through the percentage arithmetic and out onto the
// wire as a plausible number. No such filesystem exists today; a statfs implementation that returns
// nonsense for a mount it cannot measure is a great deal more likely, and this catches that too.
func blocksToBytes(blocks uint64, blockSize int64) int64 {
	if blockSize <= 0 {
		return 0
	}
	if blocks > uint64(math.MaxInt64)/uint64(blockSize) {
		return math.MaxInt64
	}
	//nolint:gosec // G115 flags the uint64 to int64 conversion, which is the whole subject of this
	// function: the line above establishes that blocks * blockSize fits in an int64, so this one cannot
	// wrap. The check is the fix gosec would ask for, and it is two lines up.
	return int64(blocks) * blockSize
}
