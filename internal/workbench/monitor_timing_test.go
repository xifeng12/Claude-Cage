package workbench

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sylvinus/agent-vm/internal/cage"
	"github.com/sylvinus/agent-vm/internal/diagnostics"
)

func monitorTimingRecords(t *testing.T, s *Server, kind string) []map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(s.profile, "logs", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var records []map[string]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event diagnostics.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Source != "network-monitor" {
			continue
		}
		fields := make(map[string]string)
		for _, field := range strings.Fields(event.Message) {
			key, value, _ := strings.Cut(field, "=")
			fields[key] = value
		}
		if fields["monitor"] == kind {
			records = append(records, fields)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestNetworkMonitorRecordsRepeatedLockSkips(t *testing.T) {
	s := testServer(t)
	s.ready = true
	s.safety.VerifiedAt = time.Now().Add(-85 * time.Second)
	s.safety.Gate = &cage.GateStatus{Mode: cage.GateOpen, Until: time.Now().Add(5 * time.Second)}
	s.op.Lock()
	defer s.op.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5200*time.Millisecond)
	defer cancel()
	s.monitorNetwork(ctx)
	records := monitorTimingRecords(t, s, "network")
	if len(records) != 2 {
		t.Fatalf("expected both skipped ticks, got %v", records)
	}
	for i, record := range records {
		if record["result"] != "operation_lock_busy" || record["consecutive_lock_skips"] != strconv.Itoa(i+1) {
			t.Fatalf("missing lock skip evidence: %v", record)
		}
		age, _ := strconv.Atoi(record["verified_age_ms"])
		if age < 85000 {
			t.Fatalf("missing late verification age: %v", record)
		}
	}
}

func TestSafetyMonitorRunsWhileOperationLockIsHeld(t *testing.T) {
	s := testServer(t)
	s.ready = true
	s.safety.VerifiedAt = time.Now()
	s.op.Lock()
	s.startMonitors()
	deadline := time.Now().Add(2 * time.Second)
	var found bool
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(s.profile, "logs", "events.jsonl")); err == nil {
			for _, record := range monitorTimingRecords(t, s, "safety") {
				found = found || record["result"] == "not_due"
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.op.Unlock()
	s.closeBackground()
	if !found {
		t.Fatal("safety monitoring was blocked by an unrelated operation")
	}
}

func TestConcurrentSafetyMonitorKeepsManualPause(t *testing.T) {
	s, gate := grantedToolUpdateServer(t)
	s.setJobForTest(Job{})
	s.safety.VerifiedAt = time.Now().Add(-time.Minute)
	started := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		s.monitorSafetyWithProbe(func(ctx context.Context, _ cage.Config) (string, error) {
			close(started)
			<-ctx.Done()
			return "", ctx.Err()
		})
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("monitor did not start")
	}
	s.monitorSafetyWithProbe(func(context.Context, cage.Config) (string, error) {
		t.Error("overlapping monitor started a second probe")
		return "", nil
	})
	if err := s.pauseNetworkNow("user pause"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("paused monitor did not stop")
	}
	if gate.Status().Mode != cage.GateClosed {
		t.Fatal("monitor reopened networking after manual pause")
	}
}

func TestMonitorTimingAttributesSlowProbe(t *testing.T) {
	s, gate := grantedToolUpdateServer(t)
	s.setJobForTest(Job{})
	s.safety.VerifiedAt = time.Now().Add(-85 * time.Second)
	s.monitorSafetyWithProbe(func(context.Context, cage.Config) (string, error) {
		time.Sleep(30 * time.Millisecond)
		return "", errors.New("synthetic probe failed token=private-probe-secret")
	})
	if gate.Status().Mode != cage.GateClosed {
		t.Fatal("failed probe retained an open gate")
	}
	records := monitorTimingRecords(t, s, "safety")
	if len(records) != 1 {
		t.Fatalf("missing safety round: %v", records)
	}
	record := records[0]
	duration, err := strconv.Atoi(record["exit_ip_ms"])
	if err != nil || duration < 30 || record["result"] != "observation_failed" {
		t.Fatalf("slow probe was not attributed: %v", record)
	}
	if _, present := record["guest_settings_ms"]; present {
		t.Fatalf("recorded an unexecuted stage: %v", record)
	}
	data, err := os.ReadFile(filepath.Join(s.profile, "logs", "events.jsonl"))
	if err != nil || strings.Contains(string(data), "private-probe-secret") {
		t.Fatal("diagnostics could not be read or contained a probe secret")
	}
}

func TestMonitorTimingRecordsRenewalAndSkips(t *testing.T) {
	s, gate := grantedToolUpdateServer(t)
	client, err := s.gateClient()
	if err != nil {
		t.Fatal(err)
	}
	before := gate.Status()
	s.finishSafetyMonitor(context.Background(), client, before, "192.0.2.1", "")
	records := monitorTimingRecords(t, s, "renewal")
	if len(records) != 1 || records[0]["result"] != "renewed" || records[0]["gate_renew_ms"] == "" || records[0]["safety_lock_ms"] == "" {
		t.Fatalf("missing renewal timing: %v", records)
	}
	remaining, err := strconv.Atoi(records[0]["lease_remaining_end_ms"])
	if err != nil || remaining < 0 || remaining > int(cage.GateLease.Milliseconds()) {
		t.Fatalf("invalid old lease margin: %v", records[0])
	}
	s.monitorSafety()
	s.networkPaused = true
	s.monitorSafety()
	records = monitorTimingRecords(t, s, "safety")
	if len(records) != 2 || records[0]["result"] != "not_due" || records[1]["result"] != "network_paused" {
		t.Fatalf("skip reasons were lost: %v", records)
	}
}

func TestNetworkMonitorRecordsAllOuterStages(t *testing.T) {
	s := testServer(t)
	previous := physicalProxyInterface
	physicalProxyInterface = func(context.Context) (string, error) {
		time.Sleep(30 * time.Millisecond)
		return "en0", nil
	}
	defer func() { physicalProxyInterface = previous }()
	s.monitorNetworkTick()
	records := monitorTimingRecords(t, s, "network")
	if len(records) != 1 {
		t.Fatalf("missing network round: %v", records)
	}
	for _, stage := range []string{"physical_interface", "proxy_health", "safety", "recovery", "subscriptions"} {
		if records[0][stage+"_ms"] == "" {
			t.Fatalf("missing %s timing: %v", stage, records[0])
		}
	}
	duration, err := strconv.Atoi(records[0]["physical_interface_ms"])
	if err != nil || duration < 30 {
		t.Fatalf("slow interface check was not attributed: %v", records[0])
	}
}

// A slow physical adapter lookup must not keep a project-opening request
// from acquiring the shared lifecycle lock.
func TestNetworkMonitorProbesOutsideOperationLock(t *testing.T) {
	s := testServer(t)
	previous := physicalProxyInterface
	started := make(chan struct{})
	physicalProxyInterface = func(ctx context.Context) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	}
	defer func() { physicalProxyInterface = previous }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.monitorNetwork(ctx)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("physical adapter probe was not started")
	}
	if !s.op.TryLock() {
		t.Fatal("physical adapter probe held the project operation lock")
	}
	s.op.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("network monitor did not stop after cancellation")
	}
}
