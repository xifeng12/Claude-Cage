package workbench

import (
	"context"
	"path/filepath"

	"github.com/sylvinus/agent-vm/internal/managedproxy"
)

var physicalProxyInterface = managedproxy.PhysicalInterface

// The lifecycle lock is held by monitorNetwork. Schedule a regular job so a
// user stop can cancel recovery and pause can still revoke the gate immediately.
func (s *Server) monitorProxyInterface() {
	s.monitorProxyInterfaceWithProbe(physicalProxyInterface)
}

// The probe may be sampled outside the lifecycle lock; all decisions and
// mutations still run inside the existing serialized monitor operation.
func (s *Server) monitorProxyInterfaceWithProbe(probe func(context.Context) (string, error)) {
	if s.busy() {
		return
	}
	cfg, err := loadConfig(s.configPath)
	if err != nil || cfg.RequireManagedProxy(s.profile) != nil {
		return
	}
	name, err := probe(s.lifetimeContext())
	if err != nil {
		_ = s.closeProxyGate(err.Error())
		s.mu.Lock()
		s.safety.monitorError = err.Error()
		s.proxyNetworkLost = true
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	lost := s.proxyNetworkLost
	s.mu.Unlock()
	bound, err := managedproxy.BoundInterface(filepath.Join(managedproxy.Dir(s.profile), "config.yaml"))
	if err != nil || (bound == name && !lost) {
		return
	}
	// Revoke the previous report before the asynchronous recovery can start.
	if err := s.closeProxyGate("物理网卡已变化，正在重新绑定代理并检查出口"); err != nil {
		return
	}
	s.mu.Lock()
	s.proxyNetworkLost = false
	s.mu.Unlock()
	_, _ = s.submitJob("proxy-network", s.rebindProxyInterface)
}

func (s *Server) rebindProxyInterface() error {
	s.setMessage("正在识别物理网卡并重新绑定代理…")
	cfg, err := loadConfig(s.configPath)
	if err != nil {
		return err
	}
	p, err := managedproxy.Applied(s.profile, cfg.ProxyURL, cfg.ProxyRevision)
	if err != nil {
		return err
	}
	return s.applyProxy(p, cfg, nil, false)
}
