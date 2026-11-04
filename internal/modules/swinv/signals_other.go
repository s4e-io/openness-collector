//go:build !linux && !windows

package swinv

func hostRoots() []string                                          { return []string{"/"} }
func runningProcesses() []procInfo                                 { return nil }
func listeningTCPPorts() map[int][]int                             { return map[int][]int{} }
func registryHits(_ RegistrySignal) []registryHit                  { return nil }
func registryValue(_ registryHit, _ Reader) (string, string, bool) { return "", "", false }
func peVersion(_ string) (string, bool)                            { return "", false }
