//go:build linux

package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"syswarden-core/firewall"
)

const runtimeControlSocketPath = "/run/syswarden-control.sock"

type runtimeControlRequest struct {
	Version int    `json:"version"`
	Action  string `json:"action"`
	Entry   string `json:"entry"`
}

type runtimeControlResponse struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

type RuntimeControlServer struct {
	listener  *net.UnixListener
	root      *os.Root
	name      string
	identity  os.FileInfo
	ownerUID  int
	manager   firewall.Manager
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// StartRuntimeControlServer exposes a separate root-authenticated stream
// socket. The rsyslog datagram input can never submit operator commands.
func StartRuntimeControlServer(manager firewall.Manager) (*RuntimeControlServer, error) {
	return startRuntimeControlServerAt(runtimeControlSocketPath, 0, manager)
}

func startRuntimeControlServerAt(path string, ownerUID int, manager firewall.Manager) (*RuntimeControlServer, error) {
	if manager == nil || ownerUID < 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("invalid runtime control server configuration")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || owner != ownerUID || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("runtime control parent is not an owner-controlled real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, fmt.Errorf("runtime control directory changed while opening")
	}
	server := &RuntimeControlServer{root: root, name: filepath.Base(path), ownerUID: ownerUID, manager: manager}
	succeeded := false
	defer func() {
		if !succeeded {
			server.Stop()
		}
	}()
	if previous, err := root.Lstat(server.name); err == nil {
		if err := attestRuntimeControlSocket(previous, ownerUID); err != nil {
			return nil, err
		}
		connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("a live runtime control socket already exists")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("existing runtime control socket cannot be safely classified: %w", dialErr)
		}
		current, err := root.Lstat(server.name)
		if err != nil || !os.SameFile(previous, current) {
			return nil, fmt.Errorf("stale runtime control socket changed before removal")
		}
		if err := root.Remove(server.name); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	server.listener = listener
	identity, err := root.Lstat(server.name)
	if err != nil {
		return nil, err
	}
	server.identity = identity
	if err := root.Chmod(server.name, 0600); err != nil {
		return nil, err
	}
	identity, err = root.Lstat(server.name)
	if err != nil || !os.SameFile(server.identity, identity) {
		return nil, fmt.Errorf("runtime control socket changed after binding")
	}
	if err := attestRuntimeControlSocket(identity, ownerUID); err != nil {
		return nil, err
	}
	currentParent, err := os.Lstat(parent)
	if err != nil || !os.SameFile(info, currentParent) {
		return nil, fmt.Errorf("runtime control parent changed after binding")
	}
	server.identity = identity
	server.wg.Add(1)
	go server.serve()
	succeeded = true
	return server, nil
}

func attestRuntimeControlSocket(info os.FileInfo, ownerUID int) error {
	owner, err := haFenceOwnerUID(info)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || owner != ownerUID || !ok || stat.Nlink != 1 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return fmt.Errorf("runtime control socket must be a private single-link owner-owned socket")
	}
	return nil
}

func runtimeControlPeerUID(connection *net.UnixConn) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return -1, err
	}
	var credentials *syscall.Ucred
	var credentialErr error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, credentialErr = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credentialErr != nil || credentials == nil {
		return -1, fmt.Errorf("runtime control peer credentials are unavailable: %v", credentialErr)
	}
	return int(credentials.Uid), nil
}

func (server *RuntimeControlServer) serve() {
	defer server.wg.Done()
	slots := make(chan struct{}, 8)
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				defer func() { <-slots; _ = connection.Close() }()
				server.handle(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *RuntimeControlServer) handle(connection *net.UnixConn) {
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	uid, err := runtimeControlPeerUID(connection)
	if err != nil || uid != server.ownerUID {
		return
	}
	wire, err := io.ReadAll(io.LimitReader(connection, 2049))
	if err != nil || len(wire) > 2048 || len(wire) == 0 || rejectHADuplicateJSONKeys(wire) != nil {
		return
	}
	var request runtimeControlRequest
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return
	}
	if request.Version != 1 || !canonicalRuntimeLifecycleEntry(request.Entry) || request.Action != "unban" && request.Action != "preflight" {
		return
	}
	response := runtimeControlResponse{Version: 1}
	operation := func() error {
		if manager, ok := server.manager.(*runtimeLifecycleManager); ok {
			if request.Action == "preflight" {
				manager.mu.Lock()
				defer manager.mu.Unlock()
				model, pending, err := manager.store.load()
				if err != nil {
					return err
				}
				if pending != nil {
					return fmt.Errorf("runtime lifecycle recovery is pending")
				}
				return validateRuntimeLifecycleOverlap(model, request.Entry)
			}
			if manager.operatorUnban != nil {
				return manager.operatorUnban(request.Entry)
			}
			return manager.Unban(request.Entry)
		}
		if manager, ok := server.manager.(*haV2ReplicatedManager); ok {
			if request.Action == "preflight" {
				return manager.adapter.localMutationReadiness(manager.adapter.now())
			}
			return manager.Unban(request.Entry)
		}
		return fmt.Errorf("authoritative runtime lifecycle manager is unavailable")
	}
	if manager, ok := server.manager.(*runtimeLifecycleManager); ok {
		err = manager.withOperatorFence(operation)
	} else {
		err = operation()
	}

	response.OK = err == nil
	if err != nil {
		response.Error = err.Error()
		if len(response.Error) > 1024 {
			response.Error = "runtime operation failed; inspect the local core journal"
		}
	}
	_ = json.NewEncoder(connection).Encode(response)
}

func (server *RuntimeControlServer) Stop() {
	server.closeOnce.Do(func() {
		if server.listener != nil {
			_ = server.listener.Close()
		}
		server.wg.Wait()
		if server.root != nil {
			if current, err := server.root.Lstat(server.name); err == nil && server.identity != nil && os.SameFile(server.identity, current) {
				_ = server.root.Remove(server.name)
			}
			_ = server.root.Close()
		}
	})
}
