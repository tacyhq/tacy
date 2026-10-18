package runner

// CloseConn drops a sandbox's connection without a destroy, as a crashed agentd would.
func CloseConn(s *Sandbox) { s.c.Close() }
