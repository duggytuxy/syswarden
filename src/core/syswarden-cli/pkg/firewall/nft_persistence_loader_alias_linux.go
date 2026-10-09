//go:build linux

package firewall

import (
	"fmt"
	"os"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
)

type nftPersistenceLoaderAlias struct {
	Target         string `json:"target"`
	FilesystemUUID string `json:"filesystem_uuid"`
	Inode          uint64 `json:"inode"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	Mode           uint32 `json:"mode"`
	NLink          uint64 `json:"nlink"`
	ModifiedNS     int64  `json:"modified_ns"`
	ChangedNS      int64  `json:"changed_ns"`
	Device         uint64 `json:"-"`
}

// The standard /sbin alias is supported only for this read-only executable
// observation. Persistence sources and unit paths retain their no-link policy.
func resolveNFTPersistenceLoaderBinary(host nftPersistenceFilesystem, binary string) (string, *nftPersistenceLoaderAlias, error) {
	if binary != "/sbin/nft" {
		return binary, nil, nil
	}
	parent, err := host.openDirectory("/")
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = parent.Close() }()
	before, err := parent.Lstat("sbin")
	if err != nil {
		return "", nil, err
	}
	if host.trustedMetadata(before, true) {
		return binary, nil, nil
	}
	stat, valid := before.Sys().(*syscall.Stat_t)
	if !valid || before.Mode() != os.ModeSymlink|0777 || stat.Uid != host.expectedUID || stat.Gid != host.expectedGID || stat.Nlink != 1 {
		return "", nil, fmt.Errorf("nftables loader executable alias is not a trusted standard link")
	}
	target, err := parent.Readlink("sbin")
	after, statErr := parent.Lstat("sbin")
	if err != nil || statErr != nil || !sameNFTPersistenceIdentity(before, after) || target != "usr/sbin" && target != "/usr/sbin" {
		return "", nil, fmt.Errorf("nftables loader executable alias changed or has an unsupported target")
	}
	file, err := parent.Open(".")
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = file.Close() }()
	uuid, err := wireguardstate.CaptureFilesystemUUID(file)
	if err != nil {
		return "", nil, err
	}
	alias := &nftPersistenceLoaderAlias{
		Target: target, FilesystemUUID: uuid, Inode: stat.Ino,
		UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode, NLink: uint64(stat.Nlink),
		ModifiedNS: before.ModTime().UnixNano(), ChangedNS: stat.Ctim.Sec*1e9 + stat.Ctim.Nsec, Device: uint64(stat.Dev),
	}
	return "/usr/sbin/nft", alias, nil
}
