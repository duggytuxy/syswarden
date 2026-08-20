//go:build !linux

package network

import (
	"context"
	"fmt"
)

type secureWAAPLogFollower struct{}

func newSecureWAAPLogFollower(path string, _ bool) (*secureWAAPLogFollower, error) {
	return nil, fmt.Errorf("secure WAAP log following is unavailable on this platform for %q", path)
}

func (f *secureWAAPLogFollower) Next(context.Context) (string, error) {
	return "", fmt.Errorf("secure WAAP log following is unavailable on this platform")
}

func (f *secureWAAPLogFollower) Close() error {
	return nil
}
