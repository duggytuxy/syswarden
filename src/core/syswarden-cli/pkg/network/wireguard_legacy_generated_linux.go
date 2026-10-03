//go:build linux

package network

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
)

// legacyWireGuardGeneratedState stays private. Only inode-bound digests of its
// files may enter a recovery plan. Filenames alone never establish provenance.
type legacyWireGuardGeneratedState struct {
	files []legacyWireGuardConfiguration
	input wireGuardRenderInput
}

func historicalWireGuardEgress(configuration []byte, iface string) (string, error) {
	const prefix = `nft 'add rule inet syswarden_wg postrouting oifname "`
	_, tail, found := strings.Cut(string(configuration), prefix)
	candidate, _, closed := strings.Cut(tail, `" masquerade'`)
	if !found || !closed || !wireGuardInterfaceName.MatchString(candidate) {
		return "", fmt.Errorf("historical WireGuard egress cannot be proved from the exact generated hook")
	}
	if err := validateHistoricalWireGuardConfiguration(configuration, iface, candidate); err != nil {
		return "", err
	}
	return candidate, nil
}

func legacyWireGuardPublicKey(private string) (string, error) {
	if _, err := canonicalWireGuardKey(private); err != nil {
		return "", err
	}
	wire, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return "", fmt.Errorf("decode canonical private key")
	}
	key, err := ecdh.X25519().NewPrivateKey(wire)
	if err != nil {
		return "", fmt.Errorf("derive historical public key")
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func inspectLegacyWireGuardGeneratedState(root string, uid, gid uint32) (legacyWireGuardGeneratedState, error) {
	var state legacyWireGuardGeneratedState
	for _, path := range wireguardstate.ArtifactPaths() {
		file, err := captureLegacyWireGuardConfiguration(root, path, uid, gid)
		if err != nil {
			return state, fmt.Errorf("cannot prove complete historical WireGuard generated state: %w", err)
		}
		file.evidence.Source = "exact-historical-generated-artifact"
		state.files = append(state.files, file)
	}
	return validateLegacyWireGuardGeneratedState(state)
}

func validateLegacyWireGuardGeneratedState(state legacyWireGuardGeneratedState) (legacyWireGuardGeneratedState, error) {
	server, client, forwarding := state.files[0].content, state.files[1].content, state.files[2].content
	egress, err := historicalWireGuardEgress(server, "wg-syswarden")
	if err != nil {
		return state, err
	}
	if !bytes.Equal(forwarding, []byte(wireGuardForwardingSetting)) {
		return state, fmt.Errorf("historical WireGuard forwarding artifact is not the exact generated setting")
	}
	serverLines := strings.Split(strings.TrimSuffix(string(server), "\n"), "\n")
	clientLines := strings.Split(strings.TrimSuffix(string(client), "\n"), "\n")
	if len(clientLines) != 12 || clientLines[0] != "[Interface]" || clientLines[3] != "MTU = 1360" ||
		clientLines[4] != "DNS = 1.1.1.1, 1.0.0.1" || clientLines[5] != "" || clientLines[6] != "[Peer]" ||
		clientLines[10] != "AllowedIPs = 0.0.0.0/0, ::/0" || clientLines[11] != "PersistentKeepalive = 25" ||
		!bytes.HasSuffix(client, []byte{'\n'}) || bytes.ContainsAny(client, "\x00\r") {
		return state, fmt.Errorf("historical WireGuard client structure is not exact")
	}
	value := func(line, name string) (string, error) { return exactLegacyWireGuardConfigurationValue(line, name) }
	serverPrivate, _ := value(serverLines[3], "PrivateKey")
	clientPublic, _ := value(serverLines[8], "PublicKey")
	psk, _ := value(serverLines[9], "PresharedKey")
	clientPrivate, err := value(clientLines[1], "PrivateKey")
	if err != nil {
		return state, err
	}
	serverPublic, err := value(clientLines[7], "PublicKey")
	if err != nil {
		return state, err
	}
	clientPSK, err := value(clientLines[8], "PresharedKey")
	if err != nil || clientPSK != psk {
		return state, fmt.Errorf("historical WireGuard server and client preshared keys do not match")
	}
	derivedServer, err := legacyWireGuardPublicKey(serverPrivate)
	if err != nil || derivedServer != serverPublic {
		return state, fmt.Errorf("historical WireGuard client does not bind the server key")
	}
	derivedClient, err := legacyWireGuardPublicKey(clientPrivate)
	if err != nil || derivedClient != clientPublic {
		return state, fmt.Errorf("historical WireGuard server does not bind the client key")
	}
	serverAddress, _ := value(serverLines[1], "Address")
	address, _ := netip.ParsePrefix(serverAddress) // Exact server parser already checked this value.
	clientAddress, err := value(clientLines[2], "Address")
	if err != nil || clientAddress != netip.PrefixFrom(address.Addr().Next(), address.Bits()).String() {
		return state, fmt.Errorf("historical WireGuard client address does not match the server peer")
	}
	endpoint, err := value(clientLines[9], "Endpoint")
	if err != nil {
		return state, err
	}
	host, port, err := net.SplitHostPort(endpoint)
	listenPort, _ := value(serverLines[2], "ListenPort")
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || ipErr != nil || ip.Zone() != "" || ip.Is4In6() || ip.String() != host ||
		port != listenPort || net.JoinHostPort(host, port) != endpoint {
		return state, fmt.Errorf("historical WireGuard client endpoint does not match an exact generated endpoint")
	}
	state.input = wireGuardRenderInput{
		Backend: "nftables", Subnet: address.Masked().String(), Port: port, ActiveIf: egress,
		EndpointIP: host, ServerPriv: serverPrivate, ServerPub: serverPublic,
		ClientPriv: clientPrivate, ClientPub: clientPublic, PresharedKey: psk,
	}
	return state, nil
}

func (state legacyWireGuardGeneratedState) evidence() []LegacyWireGuardFileEvidence {
	result := make([]LegacyWireGuardFileEvidence, 0, len(state.files))
	for _, file := range state.files {
		result = append(result, file.evidence)
	}
	return result
}
