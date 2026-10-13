package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const AuthorityEndpointPinName = ".authority-v1-pin"
const maxEndpointPinBytes = 2048

// Pins are private lifecycle evidence, not authentication or authorization.
// Only the live creator writes one, before listening, into separately provisioned
// storage. Recovery opens an existing pin read-only and never manufactures one.
type endpointPinDocument struct {
	Schema       string          `json:"schema"`
	DirectoryDev string          `json:"directory_dev"`
	DirectoryIno string          `json:"directory_ino"`
	DirectoryUID string          `json:"directory_uid"`
	DirectoryGID string          `json:"directory_gid"`
	RecordSHA256 string          `json:"record_sha256"`
	Record       json.RawMessage `json:"record"`
}

type endpointPin struct {
	directory *os.File
	file      segmentFile
	dirStamp  unix.Stat_t
	stamp     unix.Stat_t
	data      []byte
	record    []byte
}

func encodeEndpointPin(dir unix.Stat_t, record []byte) ([]byte, error) {
	return json.Marshal(endpointPinDocument{
		Schema:       "syswarden.authority-endpoint-pin.v1",
		DirectoryDev: strconv.FormatUint(uint64(dir.Dev), 10), DirectoryIno: strconv.FormatUint(dir.Ino, 10),
		DirectoryUID: strconv.FormatUint(uint64(dir.Uid), 10), DirectoryGID: strconv.FormatUint(uint64(dir.Gid), 10),
		RecordSHA256: recoveryDigest(record), Record: record,
	})
}

func openEndpointPinDirectory(directory *os.File) (_ *endpointPin, err error) {
	dir, err := openDirectory(directory)
	if err != nil {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	p := &endpointPin{directory: dir}
	if err = unix.Fstat(int(dir.Fd()), &p.dirStamp); err == nil {
		err = p.attestDirectory()
	}
	if err != nil {
		return nil, errors.Join(err, p.close())
	}
	return p, nil
}

func (p *endpointPin) attestDirectory() error {
	var st unix.Stat_t
	if p == nil || p.directory == nil {
		return ErrAuthorityEndpoint
	}
	fd := int(p.directory.Fd())
	if err := unix.Fstat(fd, &st); err != nil || !privateDirectory(st) || st.Dev != p.dirStamp.Dev || st.Ino != p.dirStamp.Ino || st.Gid != p.dirStamp.Gid {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	return noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) })
}

func (p *endpointPin) fileStamp() (unix.Stat_t, error) {
	var st, entry unix.Stat_t
	if err := p.attestDirectory(); err != nil || p.file == nil {
		return st, errors.Join(ErrAuthorityEndpoint, err)
	}
	fd := int(p.file.Fd())
	if err := unix.Fstat(fd, &st); err != nil || !privateFile(st) || st.Size > maxEndpointPinBytes {
		return st, errors.Join(ErrAuthorityEndpoint, err)
	}
	if err := unix.Fstatat(int(p.directory.Fd()), AuthorityEndpointPinName, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameStamp(st, entry) {
		return st, errors.Join(ErrAuthorityEndpoint, err)
	}
	err := noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) })
	return st, err
}

func (p *endpointPin) attest() error {
	if p == nil {
		return nil // Bare internal socket fixtures have no independent pin provider.
	}
	st, err := p.fileStamp()
	if err != nil || !sameStamp(st, p.stamp) || len(p.data) == 0 || st.Size != int64(len(p.data)) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	var data [maxEndpointPinBytes]byte
	n, err := p.file.ReadAt(data[:len(p.data)], 0)
	if err != nil || n != len(p.data) || !bytes.Equal(data[:n], p.data) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	after, err := p.fileStamp()
	if err != nil || !sameStamp(st, after) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	return nil
}

func (p *endpointPin) create(record []byte, syncDirectory func() error) error {
	if err := p.open(record); err != nil {
		return err
	}
	return p.write(syncDirectory)
}

func (p *endpointPin) open(record []byte) error {
	if err := p.attestDirectory(); err != nil || len(record) == 0 || len(record) > maxEndpointRecordBytes {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	data, err := encodeEndpointPin(p.dirStamp, record)
	if err != nil || len(data) > maxEndpointPinBytes {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	fd, err := unix.Openat(int(p.directory.Fd()), AuthorityEndpointPinName, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0600)
	if err != nil {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	p.file = diskFile{os.NewFile(uintptr(fd), "authority-endpoint-pin")}
	p.record, p.data = bytes.Clone(record), data
	p.stamp, err = p.fileStamp()
	if err != nil || p.stamp.Size != 0 {
		return errors.Join(ErrCommitUncertain, ErrAuthorityEndpoint, err)
	}
	return nil
}

// The file and directory sync seams are private deterministic fault injection.
func (p *endpointPin) write(syncDirectory func() error) error {
	n, err := p.file.Write(p.data)
	if err != nil || n != len(p.data) {
		return errors.Join(ErrCommitUncertain, io.ErrShortWrite, err)
	}
	st, err := p.fileStamp()
	if err != nil || st.Dev != p.stamp.Dev || st.Ino != p.stamp.Ino || st.Gid != p.stamp.Gid {
		return errors.Join(ErrCommitUncertain, ErrAuthorityEndpoint, err)
	}
	p.stamp = st
	if err = p.file.Sync(); err == nil {
		err = syncDirectory()
	}
	if err == nil {
		err = p.attest()
	}
	if err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

func readEndpointPin(directory *os.File) (_ *endpointPin, err error) {
	p, err := openEndpointPinDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.close())
		}
	}()
	fd, err := unix.Openat(int(p.directory.Fd()), AuthorityEndpointPinName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	p.file = diskFile{os.NewFile(uintptr(fd), "authority-recovery-pin")}
	p.stamp, err = p.fileStamp()
	if err != nil || p.stamp.Size <= 0 {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	p.data = make([]byte, int(p.stamp.Size))
	n, err := p.file.ReadAt(p.data, 0)
	if err != nil || n != len(p.data) {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	var doc endpointPinDocument
	if err = json.Unmarshal(p.data, &doc); err != nil || len(doc.Record) == 0 || len(doc.Record) > maxEndpointRecordBytes {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	expected, err := encodeEndpointPin(p.dirStamp, doc.Record)
	if err != nil || !bytes.Equal(expected, p.data) {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	p.record = bytes.Clone(doc.Record)
	if err = p.attest(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *endpointPin) retire(ops endpointRecoveryOps) error {
	if p == nil {
		return nil
	}
	if err := p.attest(); err != nil {
		return err
	}
	fd := int(p.directory.Fd())
	err := ops.unlink(fd, AuthorityEndpointPinName, 0)
	err = errors.Join(err, ops.sync(p.directory))
	if err == nil {
		err = errors.Join(p.attestDirectory(), endpointAbsent(fd, AuthorityEndpointPinName))
	}
	if err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

func (p *endpointPin) close() error {
	if p == nil {
		return nil
	}
	var err error
	if p.file != nil {
		err = p.file.Close()
		p.file = nil
	}
	if p.directory != nil {
		err = errors.Join(err, p.directory.Close())
		p.directory = nil
	}
	return err
}

func openPinnedAuthoritySocket(c AuthorityServerConfig) (*authoritySocket, error) {
	p, err := openEndpointPinDirectory(c.PinDirectory)
	if err != nil {
		return nil, err
	}
	// A pin must not alias any independently locked authority resource.
	for _, dir := range []*os.File{c.Directory, c.Authority.PolicyDirectory, c.Authority.CustodyDirectory, c.Authority.AnchorDirectory, c.Authority.JournalDirectory} {
		var st unix.Stat_t
		if dir == nil {
			err = ErrAuthorityEndpoint
		} else if e := unix.Fstat(int(dir.Fd()), &st); e != nil {
			err = e
		} else if st.Dev == p.dirStamp.Dev && st.Ino == p.dirStamp.Ino {
			err = ErrAuthorityEndpoint
		}
		if err != nil {
			return nil, errors.Join(err, p.close())
		}
	}
	if err = endpointAbsent(int(p.directory.Fd()), AuthorityEndpointPinName); err != nil {
		return nil, errors.Join(err, p.close())
	}
	s, err := openAuthoritySocketWithRecord(c.Directory, c.GroupID, c.Transport.MaxPeers, func(s *authoritySocket) error {
		if err := s.createEndpointRecord(); err != nil {
			return err
		}
		// From here every uncertain pin write retains the complete endpoint pair.
		s.preserve = true
		if err := p.create(s.record, p.directory.Sync); err != nil {
			return err
		}
		s.pin, s.preserve = p, false
		return nil
	})
	if err != nil {
		return nil, errors.Join(err, p.close())
	}
	return s, nil
}
