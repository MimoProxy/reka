//go:build windows

package main

import (
	"golang.org/x/sys/windows/svc"
)

var serviceStop = make(chan struct{})
var serviceReady = make(chan struct{}, 1)

func ready() {
	select {
	case serviceReady <- struct{}{}:
	default:
	}
}
func serve(run func() error) error {
	yes, e := svc.IsWindowsService()
	if e != nil {
		return e
	}
	if !yes {
		return run()
	}
	return svc.Run("Reka", serviceHandler{run})
}

type serviceHandler struct{ run func() error }

func (h serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- h.run() }()
	for {
		select {
		case <-serviceReady:
			changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
		case e := <-done:
			if e != nil {
				return true, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				changes <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(serviceStop)
				e := <-done
				if e != nil {
					return true, 1
				}
				return false, 0
			}
		}
	}
}
