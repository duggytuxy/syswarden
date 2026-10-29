package system

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- APKv2 registration C requires SHA1; release authenticity still requires the signed artifact SHA256.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"strings"
)

// apkRegistrationStreamReader preserves io.ByteReader so gzip.Multistream(false)
// consumes precisely one compressed stream. Bytes prefetched by bufio for a later
// stream are not hashed until gzip actually consumes them. Hashing during the
// validated read also avoids computing identity from a second, possibly changed
// read of the descriptor.
type apkRegistrationStreamReader struct {
	reader     *bufio.Reader
	digest     hash.Hash
	byteBuffer [1]byte
}

func newAPKRegistrationStreamReader(reader *bufio.Reader, data bool) *apkRegistrationStreamReader {
	if data {
		return &apkRegistrationStreamReader{reader: reader, digest: sha256.New()}
	}
	// #nosec G401 -- This is the APKv2 native registration identity, not an authenticity decision.
	return &apkRegistrationStreamReader{reader: reader, digest: sha1.New()}
}

func (reader *apkRegistrationStreamReader) Read(data []byte) (int, error) {
	n, err := reader.reader.Read(data)
	_, _ = reader.digest.Write(data[:n]) // hash.Hash.Write cannot return an error.
	return n, err
}

func (reader *apkRegistrationStreamReader) ReadByte() (byte, error) {
	value, err := reader.reader.ReadByte()
	if err == nil {
		reader.byteBuffer[0] = value
		_, _ = reader.digest.Write(reader.byteBuffer[:]) // hash.Hash.Write cannot return an error.
	}
	return value, err
}

type apkRegistrationCapture struct {
	controlChecksum string
	dataSHA256      string
	metadata        []byte
}

func (capture *apkRegistrationCapture) observe(kind string, metadata []byte, reader *apkRegistrationStreamReader) {
	switch kind {
	case "apk-control":
		capture.controlChecksum = "Q1" + base64.StdEncoding.EncodeToString(reader.digest.Sum(nil))
		capture.metadata = metadata
	case "apk-data":
		capture.dataSHA256 = hex.EncodeToString(reader.digest.Sum(nil))
	}
}

// readAuthenticatedAPKRegistrationChecksum returns APKv2's C field: Q1 followed
// by base64(SHA1(the exact compressed control stream)), including gzip framing.
// The complete package uses the identity reader's bounded stream, tar and
// metadata validation. This bridge additionally requires cut signature/control
// segments, as emitted by nfpm; APK3 tools reject padded control segments.
// A malformed later stream yields no checksum.
// Unlike the generic identity reader, this requires one canonical datahash and
// verifies the actual compressed data SHA256 in the same bounded stream read.
// Legacy APK2 without datahash uses a different native C checksum scope and is
// deliberately unsupported here. APKv3 remains unsupported. Unsigned modern v2
// framing is accepted; the caller must separately require its native signature and existing
// signed artifact SHA256 authentication. This checksum never supplies approval
// or substitutes for either authentication boundary.
func readAuthenticatedAPKRegistrationChecksum(ctx context.Context, file *os.File) (string, error) {
	var capture apkRegistrationCapture
	_, err := readAuthenticatedAPKObservedRegistration(ctx, file, nil, &capture)
	if err != nil {
		return "", err
	}
	if capture.controlChecksum == "" || capture.dataSHA256 == "" {
		return "", errors.New("authenticated APK registration control stream is unavailable")
	}
	var expected string
	for _, line := range strings.Split(string(capture.metadata), "\n") {
		key, value, ok := strings.Cut(line, " = ")
		if !ok || !strings.EqualFold(key, "datahash") {
			continue
		}
		if key != "datahash" || expected != "" || !validSHA256(value) {
			return "", errors.New("authenticated APK registration datahash is noncanonical or duplicated")
		}
		expected = value
	}
	if expected == "" || expected != capture.dataSHA256 {
		return "", errors.New("authenticated APK registration requires an exact compressed datahash")
	}
	return capture.controlChecksum, nil
}
