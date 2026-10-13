package journal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const AuthorityEndpointRecordName = ".authority-v1-owner"

const maxEndpointRecordBytes = 1024

// This is private lifecycle evidence, not a bearer token, signature or permission
// to reclaim an existing socket. This component never adopts an existing record.
// Decimal strings keep inode/device values exact for future offline inspection.
type endpointOwnershipRecord struct {
	Schema       string `json:"schema"`
	Nonce        string `json:"nonce"`
	DirectoryDev string `json:"directory_dev"`
	DirectoryIno string `json:"directory_ino"`
	DirectoryUID string `json:"directory_uid"`
	DirectoryGID string `json:"directory_gid"`
	SocketDev    string `json:"socket_dev"`
	SocketIno    string `json:"socket_ino"`
	SocketUID    string `json:"socket_uid"`
	SocketGID    string `json:"socket_gid"`
	ChangedSec   string `json:"socket_changed_sec"`
	ChangedNSec  string `json:"socket_changed_nsec"`
}

func (s *authoritySocket) openEndpointRecord() error {
	if err := s.attestSocketLocked(); err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	dir, socket := s.dirStamp, s.entry
	data, err := json.Marshal(endpointOwnershipRecord{
		Schema: "syswarden.authority-endpoint-owner.v1", Nonce: hex.EncodeToString(nonce[:]),
		DirectoryDev: strconv.FormatUint(uint64(dir.Dev), 10), DirectoryIno: strconv.FormatUint(dir.Ino, 10),
		DirectoryUID: strconv.FormatUint(uint64(dir.Uid), 10), DirectoryGID: strconv.FormatUint(uint64(dir.Gid), 10),
		SocketDev: strconv.FormatUint(uint64(socket.Dev), 10), SocketIno: strconv.FormatUint(socket.Ino, 10),
		SocketUID: strconv.FormatUint(uint64(socket.Uid), 10), SocketGID: strconv.FormatUint(uint64(socket.Gid), 10),
		ChangedSec: strconv.FormatInt(int64(socket.Ctim.Sec), 10), ChangedNSec: strconv.FormatInt(int64(socket.Ctim.Nsec), 10),
	})
	if err != nil || len(data) == 0 || len(data) > maxEndpointRecordBytes {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	fd, err := unix.Openat(int(s.directory.Fd()), AuthorityEndpointRecordName, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0600)
	if err != nil {
		return err
	}
	s.recordFile = diskFile{os.NewFile(uintptr(fd), "authority-endpoint-owner")}
	s.record, s.preserve = data, true
	st, err := s.endpointRecordStamp()
	if err != nil || st.Size != 0 {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	s.recordStamp = st
	return nil
}

func (s *authoritySocket) createEndpointRecord() error {
	if err := s.openEndpointRecord(); err != nil {
		return err
	}
	return s.syncEndpointRecord(s.directory.Sync)
}

func (s *authoritySocket) syncEndpointRecord(syncDirectory func() error) error {
	n, err := s.recordFile.Write(s.record)
	if err != nil || n != len(s.record) {
		return errors.Join(ErrCommitUncertain, io.ErrShortWrite, err)
	}
	st, err := s.endpointRecordStamp()
	if err != nil || st.Gid != s.recordStamp.Gid || st.Dev != s.recordStamp.Dev || st.Ino != s.recordStamp.Ino {
		return errors.Join(ErrCommitUncertain, ErrAuthorityEndpoint, err)
	}
	s.recordStamp = st
	if err = s.recordFile.Sync(); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	if err = syncDirectory(); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	// Only the exact bytes and inode written by this handle can become ready.
	s.recordReady = true
	if err = s.attestLocked(); err != nil {
		s.recordReady = false
		return errors.Join(ErrCommitUncertain, err)
	}
	s.preserve = false
	return nil
}

func (s *authoritySocket) endpointRecordStamp() (unix.Stat_t, error) {
	var fd, entry unix.Stat_t
	if s.recordFile == nil || s.directory == nil {
		return fd, ErrAuthorityEndpoint
	}
	if err := unix.Fstat(int(s.recordFile.Fd()), &fd); err != nil || !privateFile(fd) || fd.Size > maxEndpointRecordBytes {
		return fd, errors.Join(ErrAuthorityEndpoint, err)
	}
	if err := unix.Fstatat(int(s.directory.Fd()), AuthorityEndpointRecordName, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameStamp(fd, entry) {
		return fd, errors.Join(ErrAuthorityEndpoint, err)
	}
	err := noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(int(s.recordFile.Fd()), name, nil) })
	return fd, err
}

func (s *authoritySocket) attestEndpointRecord() error {
	if s.closed {
		return ErrClosed
	}
	if !s.recordReady {
		return ErrAuthorityEndpoint
	}
	st, err := s.endpointRecordStamp()
	if err != nil || !sameStamp(st, s.recordStamp) || st.Size != int64(len(s.record)) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	var data [maxEndpointRecordBytes]byte
	n, err := s.recordFile.ReadAt(data[:len(s.record)], 0)
	if err != nil || n != len(s.record) || !bytes.Equal(data[:n], s.record) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	after, err := s.endpointRecordStamp()
	if err != nil || !sameStamp(after, st) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	return nil
}
