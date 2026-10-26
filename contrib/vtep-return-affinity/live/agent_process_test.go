// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	testns "github.com/cilium/cilium/pkg/testutils/netns"
)

type agentProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error
	logPath string
	client  *http.Client
}

type agentVersion struct {
	Binary, Source string
}

func currentAgentVersion() agentVersion {
	return agentVersion{os.Getenv("VTEP_RETURN_AGENT_BINARY"), "/var/lib/cilium-source/bpf"}
}

func previousAgentVersion() agentVersion {
	return agentVersion{os.Getenv("VTEP_RETURN_PREVIOUS_AGENT_BINARY"), "/var/lib/cilium-previous/bpf"}
}

func agentDigest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Called only before initial startup or after the old process has exited.
// Keep the canonical source path constant across images; both separately
// supplied trees are fingerprinted by the VM runner. State/pins are untouched.
func stageAgentSource(t *testing.T, version agentVersion) {
	t.Helper()
	const destination = "/var/lib/cilium/bpf"
	if _, err := os.Stat(version.Source); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(destination, os.DirFS(version.Source)); err != nil {
		t.Fatal(err)
	}
}

func (a *agentProcess) request(method, path string, body any, out any) error {
	var input bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&input).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, "http://local/v1"+path, &input)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func agentLogTail(path string) string {
	b, _ := os.ReadFile(path)
	lines := strings.Split(string(b), "\n")
	if len(lines) > 60 {
		lines = lines[len(lines)-60:]
	}
	return strings.Join(lines, "\n")
}

func startRealAgent(t *testing.T, f *handoffFixture, run, pins string, enabled bool) *agentProcess {
	return startRealAgentVersion(t, f, run, pins, enabled, currentAgentVersion())
}

func startRealAgentVersion(t *testing.T, f *handoffFixture, run, pins string, enabled bool, version agentVersion) *agentProcess {
	t.Helper()
	if filepath.Base(version.Binary) != "cilium-agent" {
		t.Fatal("agent fixtures must preserve the cilium-agent executable name")
	}
	stageAgentSource(t, version)
	logPath := filepath.Join(run, filepath.Base(filepath.Dir(version.Source))+".log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	socket := "/run/vtep-agent.sock"
	args := []string{"--enable-k8s=false", "--enable-ipv4=true", "--enable-ipv6=false",
		"--debug=true",
		// Use Cilium's supported no-policy identity allocator: this fixture
		// has no Kubernetes/kvstore backend to synchronize during restore.
		"--enable-k8s-networkpolicy=false", "--enable-k8s-cluster-network-policy=false",
		"--enable-cilium-network-policy=false", "--enable-cilium-clusterwide-network-policy=false",
		"--disable-endpoint-crd=true", "--enable-cilium-endpoint-slice=false",
		"--kube-proxy-replacement=true", "--enable-host-legacy-routing=false", "--enable-tcx=true",
		"--enable-l7-proxy=false", "--enable-envoy-config=false", "--install-iptables-rules=true",
		"--enable-ipv4-masquerade=false", "--enable-bpf-masquerade=false", "--enable-hubble=false",
		"--enable-health-checking=false", "--enable-endpoint-health-checking=false", "--enable-policy=never",
		"--enable-monitor=false", "--auto-create-cilium-node-resource=false", "--ipam=kubernetes",
		"--ipv4-node=192.0.2.1", "--ipv4-range=198.51.100.0/24", "--routing-mode=tunnel", "--tunnel-protocol=vxlan",
		"--devices=h-peer0,h-peer1,h-native", "--direct-routing-device=h-peer0", "--enable-vtep=true",
		"--vtep-endpoint=192.0.2.2,192.0.2.6", "--vtep-cidr=203.0.113.0/24,203.0.113.0/24",
		"--vtep-mac=" + f.peerVTEP[0].Attrs().HardwareAddr.String() + "," + f.peerVTEP[1].Attrs().HardwareAddr.String(),
		"--enable-experimental-vtep-return-affinity=" + strconv.FormatBool(enabled),
		"--state-dir=" + run, "--bpf-root=" + pins, "--socket-path=" + socket}
	a := &agentProcess{cmd: exec.Command(version.Binary, args...), done: make(chan struct{}), logPath: logPath}
	a.cmd.Env = []string{"PATH=/bin", "GOMAXPROCS=2", "CILIUM_K8S_NODE_NAME=vtep-lab"}
	a.cmd.Stdout, a.cmd.Stderr = io.MultiWriter(log, os.Stdout), io.MultiWriter(log, os.Stdout)
	if err := f.router.Do(func() error { return a.cmd.Start() }); err != nil {
		log.Close()
		t.Fatal(err)
	}
	go func() { a.err = a.cmd.Wait(); log.Close(); close(a.done) }()
	f.cleanup(func() { a.cmd.Process.Kill(); <-a.done })
	// Full BPF recompilation is deliberately performed by the real daemon.
	// TCG guests can take several minutes for the base and endpoint programs.
	a.client = &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-a.done:
			t.Fatalf("real agent exited: %v\n%s", a.err, agentLogTail(logPath))
		default:
		}
		var health models.StatusResponse
		if err := a.request("GET", "/healthz", nil, &health); err == nil && health.Cilium != nil && strings.EqualFold(health.Cilium.State, "ok") {
			// The status API can answer before asynchronous base-datapath
			// initialization has created the actual tunnel device.
			if err := f.router.Do(func() error { _, err := netlink.LinkByName("cilium_vxlan"); return err }); err == nil {
				return a
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("real agent did not become ready\n%s", agentLogTail(logPath))
	return nil
}

func pinTestNamespace(t *testing.T, ns *netns.NetNS, path string, cleanup func(func())) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", ns.FD()), path, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	cleanup(func() { unix.Unmount(path, unix.MNT_DETACH); os.Remove(path) })
}

func createAgentEndpoint(t *testing.T, a *agentProcess, f *handoffFixture, path string) int64 {
	t.Helper()
	state := models.EndpointStateWaitingDashForDashIdentity
	r := models.EndpointChangeRequest{ContainerID: "synthetic-vtep-" + strconv.FormatUint(f.cookie, 10),
		ContainerInterfaceName: f.pod.remote.Attrs().Name, ContainerNetnsPath: path,
		InterfaceName: f.pod.host.Attrs().Name, InterfaceIndex: int64(f.pod.host.Attrs().Index),
		HostMac: mac.MAC(f.pod.host.Attrs().HardwareAddr), Mac: mac.MAC(f.pod.remote.Attrs().HardwareAddr),
		NetnsCookie: strconv.FormatUint(f.cookie, 10), Addressing: &models.AddressPair{IPv4: f.pod.ip.String()},
		State: &state, SyncBuildEndpoint: true}
	var ep models.Endpoint
	done := make(chan error, 1)
	go func() { done <- a.request("PUT", "/endpoint/cilium-local:0", &r, &ep) }()
	var requestErr error
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
wait:
	for {
		select {
		case requestErr = <-done:
			break wait
		case <-tick.C:
			dumpAgentWait(t, f)
		}
	}
	if err := requestErr; err != nil {
		t.Fatalf("CNI synchronous endpoint create: %v\n%s", err, agentLogTail(a.logPath))
	}
	if ep.ID == 0 {
		t.Fatal("agent returned no endpoint ID")
	}
	if err := f.podNS.Do(func() error {
		var err error
		f.listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: f.pod.ip, Port: 8080})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	listener := f.listener
	f.cleanup(func() { listener.Close() })
	return ep.ID
}

func dumpAgentWait(t *testing.T, f *handoffFixture) {
	t.Helper()
	var conn net.Conn
	if err := f.router.Do(func() error {
		var err error
		conn, err = net.DialTimeout("tcp4", "127.0.0.1:9890", time.Second)
		return err
	}); err != nil {
		t.Logf("gops diagnostic unavailable: %v", err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte{1})
	data, _ := io.ReadAll(conn)
	for _, stack := range strings.Split(string(data), "\n\n") {
		if strings.Contains(stack, "/datapath/loader") || strings.Contains(stack, "/pkg/endpoint.") || strings.Contains(stack, "returnaffinity") {
			fmt.Println("AGENT_WAIT_DIAGNOSTIC", stack)
		}
	}
}

func waitAgentEndpointReady(t *testing.T, a *agentProcess, id int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		var ep models.Endpoint
		if err := a.request("GET", fmt.Sprintf("/endpoint/cilium-local:%d", id), nil, &ep); err == nil &&
			ep.Status != nil && ep.Status.State != nil && *ep.Status.State == models.EndpointStateReady {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("restored endpoint did not finish actual datapath regeneration\n%s", agentLogTail(a.logPath))
}

func waitAgentHostReady(t *testing.T, a *agentProcess) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		var eps []*models.Endpoint
		if err := a.request("GET", "/endpoint", nil, &eps); err == nil {
			for _, ep := range eps {
				if ep.Status != nil && ep.Status.Networking != nil && ep.Status.Networking.InterfaceName == defaults.HostDevice &&
					ep.Status.State != nil && *ep.Status.State == models.EndpointStateReady {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("host datapath did not finish regeneration\n%s", agentLogTail(a.logPath))
}

func dumpAgentDatapath(t *testing.T, f *handoffFixture, pins string) {
	t.Helper()
	f.podNS.Do(func() error {
		data, _ := os.ReadFile("/proc/thread-self/net/tcp")
		t.Logf("pod TCP sockets: %s", data)
		return nil
	})
	filepath.WalkDir(pins, func(path string, d os.DirEntry, err error) error {
		if err != nil || (!strings.HasPrefix(d.Name(), "cilium_vtep_") && d.Name() != "cilium_metrics") || d.IsDir() {
			return nil
		}
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			return nil
		}
		defer m.Close()
		info, err := m.Info()
		if err != nil || info.Type == ebpf.SkStorage {
			return nil
		}
		it := m.Iterate()
		var key, value []byte
		if info.Type == ebpf.PerCPUHash {
			var values []struct{ Count, Bytes uint64 }
			for it.Next(&key, &values) {
				var count uint64
				for _, v := range values {
					count += v.Count
				}
				if count > 0 {
					t.Logf("map %s key=%x packets=%d", d.Name(), key, count)
				}
			}
		} else {
			for n := 0; n < 16 && it.Next(&key, &value); n++ {
				t.Logf("map %s key=%x value=%x", d.Name(), key, value)
			}
		}
		return nil
	})
}

func openAgentOwnerMap(t *testing.T, root string) *ebpf.Map {
	t.Helper()
	var pin string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == "cilium_vtep_sock4" {
			if pin != "" {
				return fmt.Errorf("duplicate canonical socket map pins")
			}
			pin = path
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if pin == "" {
		t.Fatal("actual agent did not pin socket ownership")
	}
	m, err := ebpf.LoadPinnedMap(pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func ownerFromMap(t *testing.T, m *ebpf.Map, conn *net.TCPConn) handoffOwner {
	t.Helper()
	var owner handoffOwner
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) { err = m.Lookup(uint32(fd), &owner) }); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func TestPrivilegedAgentPodNamespaceOutlivesStep(t *testing.T) {
	testutils.PrivilegedTest(t)
	f := newHandoffNetwork(t)
	path := filepath.Join(t.TempDir(), "pod-ns")
	pinTestNamespace(t, f.podNS, path, f.cleanup)
	t.Run("replace_pod", func(t *testing.T) {
		deleteAgentPodNetwork(t, f, path)
		replaceAgentPodNetwork(t, f, path)
	})
	ns, err := netns.OpenPinned(path)
	if err != nil {
		t.Fatalf("pod binding was removed at step exit: %v", err)
	}
	defer ns.Close()
	for _, handle := range []*netns.NetNS{ns, f.podNS} {
		if err := handle.Do(func() error {
			cookie, err := netns.GetNetNSCookie()
			if err == nil && cookie != f.cookie {
				return fmt.Errorf("pod incarnation changed")
			}
			return err
		}); err != nil {
			t.Fatalf("pod lifetime did not span steps: %v", err)
		}
	}
}

func TestPrivilegedRealAgentProcess(t *testing.T) {
	testutils.PrivilegedTest(t)
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" || os.Getenv("VTEP_RETURN_AGENT_BINARY") == "" {
		t.Skip("supply --full-agent in the isolated VM")
	}
	initial := currentAgentVersion()
	previous := previousAgentVersion()
	mode := os.Getenv("VTEP_RETURN_PREVIOUS_AGENT_MODE")
	if previous.Binary != "" {
		currentDigest, previousDigest := agentDigest(t, initial.Binary), agentDigest(t, previous.Binary)
		if currentDigest == previousDigest {
			t.Fatal("cross-version coverage requires distinct agent binaries")
		}
		t.Logf("current agent SHA256=%s; previous agent SHA256=%s; transition=%s", currentDigest, previousDigest, mode)
		if mode == "compatible" {
			initial = previous
		} else if mode != "missing-hashdance" {
			t.Fatal("unknown previous agent compatibility mode")
		}
	}
	runStep := func(name string, fn func(*testing.T)) {
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	f := newHandoffNetwork(t)
	if err := f.router.Do(func() error { return netlink.LinkDel(f.nodeVTEP) }); err != nil {
		t.Fatal(err)
	}
	run := t.TempDir()
	pins, err := os.MkdirTemp("/sys/fs/bpf", "real-vtep-agent-")
	if err != nil {
		t.Fatal(err)
	}
	f.cleanup(func() { os.RemoveAll(pins); unix.Unmount(pins, unix.MNT_DETACH); os.RemoveAll(pins) })
	defer func() {
		if t.Failed() {
			dumpAgentDatapath(t, f, pins)
		}
	}()
	if err := os.MkdirAll(defaults.NetNsPath, 0755); err != nil {
		t.Fatal(err)
	}
	nspath := filepath.Join(defaults.NetNsPath, "vtep-lab-pod")
	pinTestNamespace(t, f.podNS, nspath, f.cleanup)
	a := startRealAgentVersion(t, f, run, pins, true, initial)
	if err := f.router.Do(func() error { var err error; f.nodeVTEP, err = netlink.LinkByName("cilium_vxlan"); return err }); err != nil {
		t.Fatal(err)
	}
	for i, ns := range f.peerNS {
		if err := ns.Do(func() error {
			return netlink.NeighSet(&netlink.Neigh{LinkIndex: f.peerVTEP[i].Attrs().Index, IP: f.pod.ip, HardwareAddr: f.nodeVTEP.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT})
		}); err != nil {
			t.Fatal(err)
		}
	}
	id := createAgentEndpoint(t, a, f, nspath)
	waitAgentHostReady(t, a)
	clientA, serverA := f.connect(t, 0, 47000)
	clientB, serverB := f.connect(t, 1, 47001)
	m := openAgentOwnerMap(t, pins)
	beforeA, beforeB := ownerFromMap(t, m, serverA), ownerFromMap(t, m, serverB)
	if beforeA.Peer != wireIP(f.under[0].ip) || beforeB.Peer != wireIP(f.under[1].ip) {
		t.Fatal("actual agent assigned the wrong peers")
	}
	m.Close()
	transferHandoff(t, clientA, serverA, "real-agent-A")
	transferHandoff(t, clientB, serverB, "real-agent-B")
	graph := snapshotAgentAffinity(t, pins)
	tw := newAgentTimewait(t, f, pins)
	runStep("periodic_GC_preserves_TIMEWAIT_owner", tw.verifyPeriodicGC)
	tw.verify(t)

	runStep("native_owner_bypasses_overlapping_VTEP_prefix", func(t *testing.T) {
		// VTEP sync owns the aggregate /24 route via cilium_host. Native
		// ownership still needs an explicit direct BPF route for this client.
		if err := f.router.Do(func() error {
			return netlink.RouteReplace(&netlink.Route{LinkIndex: f.native.host.Attrs().Index,
				Dst: &net.IPNet{IP: f.native.ip, Mask: net.CIDRMask(32, 32)}, Scope: netlink.SCOPE_LINK})
		}); err != nil {
			t.Fatal(err)
		}
		client, server := f.connect(t, -1, 47002)
		defer client.Close()
		defer server.Close()
		m := openAgentOwnerMap(t, pins)
		defer m.Close()
		if owner := ownerFromMap(t, m, server); owner.Peer != 0 || owner.Origin != 1 {
			t.Fatalf("native TCP inherited VTEP ownership: %+v", owner)
		}
		transferHandoff(t, client, server, "real-agent-native-overlapping-prefix")
	})
	transition := func(t *testing.T, version agentVersion) {
		t.Helper()
		stopKeeper := tw.keepAlive(t)
		defer stopKeeper()
		a.cmd.Process.Kill()
		<-a.done
		transferHandoff(t, clientA, serverA, "while-agent-is-down")
		tw.verify(t)
		a = startRealAgentVersion(t, f, run, pins, true, version)
		waitAgentEndpointReady(t, a, id)
		waitAgentHostReady(t, a)
		m := openAgentOwnerMap(t, pins)
		defer m.Close()
		if ownerFromMap(t, m, serverA) != beforeA || ownerFromMap(t, m, serverB) != beforeB {
			t.Fatal("actual process restart changed socket owners")
		}
		transferHandoff(t, clientA, serverA, "after-real-agent-restart-A")
		transferHandoff(t, clientB, serverB, "after-real-agent-restart-B")
		assertAgentGraph(t, graph, snapshotAgentAffinity(t, pins))
		tw.verify(t)
	}
	if previous.Binary != "" && mode == "compatible" {
		runStep("upgrade_previous_to_current_preserves_live_connections", func(t *testing.T) {
			transition(t, currentAgentVersion())
		})
		runStep("rollback_current_to_previous_preserves_live_connections", func(t *testing.T) {
			transition(t, previous)
		})
	} else {
		runStep("SIGKILL_restart_preserves_live_connections", func(t *testing.T) {
			transition(t, currentAgentVersion())
		})
		if previous.Binary != "" {
			runStep("unsupported_previous_agent_refuses_without_replacing_live_graph", func(t *testing.T) {
				stopKeeper := tw.keepAlive(t)
				defer stopKeeper()
				a.cmd.Process.Kill()
				<-a.done
				refusePreviousAgent(t, f, a, previous)
				assertAgentGraph(t, graph, snapshotAgentAffinity(t, pins))
				transferHandoff(t, clientA, serverA, "after-unsupported-previous-agent")
				tw.verify(t)
				a = startRealAgent(t, f, run, pins, true)
				waitAgentEndpointReady(t, a, id)
				waitAgentHostReady(t, a)
				assertAgentGraph(t, graph, snapshotAgentAffinity(t, pins))
				m := openAgentOwnerMap(t, pins)
				defer m.Close()
				if ownerFromMap(t, m, serverA) != beforeA || ownerFromMap(t, m, serverB) != beforeB {
					t.Fatal("refused rollback or recovery changed socket owners")
				}
				transferHandoff(t, clientB, serverB, "after-current-agent-recovery")
				tw.verify(t)
			})
		}
	}
	runStep("retirement_prevents_legacy_fallthrough", func(t *testing.T) {
		if err := a.request("DELETE", fmt.Sprintf("/endpoint/cilium-local:%d", id), nil, nil); err != nil {
			t.Fatal(err)
		}
		// Cilium normally lowers the link during deletion. Re-raise it to
		// exercise the independent retirement guard rather than link-down.
		if err := f.router.Do(func() error { return netlink.LinkSetUp(f.pod.host) }); err != nil {
			t.Fatal(err)
		}
		serverA.SetWriteDeadline(time.Now().Add(time.Second))
		serverA.Write([]byte("retired-packet"))
		clientA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := clientA.Read(make([]byte, 64)); err == nil {
			t.Fatal("retired endpoint sent traffic after normal link removal")
		}
	})
	runStep("pod_replacement_with_reused_address_and_interface_name", func(t *testing.T) {
		clientA.Close()
		clientB.Close()
		serverA.Close()
		serverB.Close()
		f.listener.Close()
		deleteAgentPodNetwork(t, f, nspath)
		replaceAgentPodNetwork(t, f, nspath)
		id = createAgentEndpoint(t, a, f, nspath)
		clientA, serverA = f.connect(t, 0, 47100)
		clientB, serverB = f.connect(t, 1, 47101)
		m := openAgentOwnerMap(t, pins)
		defer m.Close()
		if ownerFromMap(t, m, serverA).Peer != wireIP(f.under[0].ip) || ownerFromMap(t, m, serverB).Peer != wireIP(f.under[1].ip) {
			t.Fatal("replacement inherited the wrong peer")
		}
		transferHandoff(t, clientA, serverA, "replacement-A")
		transferHandoff(t, clientB, serverB, "replacement-B")
	})
	runStep("disabled_agent_refuses_live_membership", func(t *testing.T) {
		a.cmd.Process.Kill()
		<-a.done
		refuseUnsafeDisable(t, f, a)
		transferHandoff(t, clientA, serverA, "after-refused-disable")
		a = startRealAgent(t, f, run, pins, true)
		waitAgentEndpointReady(t, a, id)
		transferHandoff(t, clientB, serverB, "after-recovery-from-refused-disable")
	})
	runStep("coordinated_drain_then_disabled_agent", func(t *testing.T) {
		if err := a.request("DELETE", fmt.Sprintf("/endpoint/cilium-local:%d", id), nil, nil); err != nil {
			t.Fatal(err)
		}
		clientA.Close()
		clientB.Close()
		serverA.Close()
		serverB.Close()
		f.listener.Close()
		deleteAgentPodNetwork(t, f, nspath)
		a.cmd.Process.Kill()
		<-a.done
		a = startRealAgent(t, f, run, pins, false)
		assertAgentGraphRemoved(t, graph)
		if err := filepath.WalkDir(pins, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Name() == "cilium_vtep_sock4" {
				return fmt.Errorf("disabled agent retained affinity storage")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		replaceAgentPodNetwork(t, f, nspath)
		createAgentEndpoint(t, a, f, nspath)
		waitAgentHostReady(t, a)
		var client *net.TCPConn
		if err := f.router.Do(func() error {
			var err error
			conn, dialErr := (&net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}}).Dial("tcp4", "198.51.100.10:8080")
			if dialErr == nil {
				client = conn.(*net.TCPConn)
			}
			err = dialErr
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		f.listener.SetDeadline(time.Now().Add(3 * time.Second))
		server, err := f.listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		transferHandoff(t, client, server, "ordinary-TCP-with-feature-disabled")
	})
}

func deleteAgentPodNetwork(t *testing.T, f *handoffFixture, path string) {
	t.Helper()
	if err := f.router.Do(func() error { return netlink.LinkDel(f.pod.host) }); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func replaceAgentPodNetwork(t *testing.T, f *handoffFixture, path string) {
	t.Helper()
	f.podNS = testns.NewNetNS(f.rootTest)
	if err := f.router.Do(func() error {
		var err error
		f.pod, err = makeLink("h-pod", "198.51.100.1/24", "198.51.100.10/24", f.podNS)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.podNS.Do(func() error {
		var err error
		f.cookie, err = netns.GetNetNSCookie()
		if err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: f.pod.remote.Attrs().Index, Gw: net.ParseIP("198.51.100.1")})
	}); err != nil {
		t.Fatal(err)
	}
	pinTestNamespace(t, f.podNS, path, f.cleanup)
}

func refuseUnsafeDisable(t *testing.T, f *handoffFixture, previous *agentProcess) {
	t.Helper()
	args := append([]string(nil), previous.cmd.Args[1:]...)
	for i, arg := range args {
		if strings.HasPrefix(arg, "--enable-experimental-vtep-return-affinity=") {
			args[i] = "--enable-experimental-vtep-return-affinity=false"
		}
	}
	runRefusedAgent(t, f, previous.cmd.Path, previous.cmd.Env, args,
		previous.logPath+".disable", 30*time.Second, "socket-affinity rollback requires draining")
}

func refusePreviousAgent(t *testing.T, f *handoffFixture, running *agentProcess, version agentVersion) {
	t.Helper()
	stageAgentSource(t, version)
	logPath := running.logPath + ".previous-refusal"
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(version.Binary, running.cmd.Args[1:]...)
	cmd.Env = running.cmd.Env
	cmd.Stdout, cmd.Stderr = io.MultiWriter(log, os.Stdout), io.MultiWriter(log, os.Stdout)
	if err := f.router.Do(func() error { return cmd.Start() }); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { cmd.Process.Kill(); <-done }()
	// Base-datapath initialization retries on failure; refusal need not exit
	// the daemon. Require the specific kernel error and explicit failed health.
	probe := *running
	probe.client = &http.Client{Timeout: 5 * time.Second, Transport: running.client.Transport}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "fentry inet_twsk_hashdance not supported") {
			var health models.StatusResponse
			if err := probe.request("GET", "/healthz", nil, &health); err == nil && health.Cilium != nil &&
				health.Cilium.State == models.StatusStateFailure && strings.Contains(health.Cilium.Msg, "return-affinity runtime is not ready") {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("previous agent did not reject initialization with failed readiness\n%s", agentLogTail(logPath))
}

func runRefusedAgent(t *testing.T, f *handoffFixture, binary string, env, args []string, logPath string, timeout time.Duration, reason string) {
	t.Helper()
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(binary, args...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = log, log
	if err := f.router.Do(func() error { return cmd.Start() }); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unsafe agent transition accepted live affinity endpoints")
		}
	case <-time.After(timeout):
		cmd.Process.Kill()
		<-done
		t.Fatalf("unsafe agent transition did not refuse live endpoints\n%s", agentLogTail(logPath))
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), reason) {
		t.Fatalf("agent failed for a different reason; expected %q\n%s", reason, agentLogTail(logPath))
	}
}
