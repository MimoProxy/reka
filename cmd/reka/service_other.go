//go:build !windows

package main

var serviceStop = make(chan struct{})

func serve(run func() error) error { return run() }
func ready()                       {}
