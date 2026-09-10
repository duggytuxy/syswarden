//go:build !linux

package network

import (
	"fmt"
	"net"
)

func configureUDSProducerAccess(*net.UnixConn, string) (udsProducerIdentity, error) {
	return udsProducerIdentity{}, fmt.Errorf("authenticated UDS producers require Linux kernel credentials")
}

func newUDSCredentialsBuffer() []byte { return nil }

func authorizedUDSCredentials([]byte, int, []uint32) bool { return false }
