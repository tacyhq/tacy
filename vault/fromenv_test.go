package vault

import "os"

// FromEnv takes the granted secrets out of the environment and unsets them: the spike child's way to get its keys
// in these tests. vaultd itself never reads them from the environment: they arrive by push (secrets.go).
func FromEnv(grants []Grant) map[string][]byte {
	out := map[string][]byte{}
	for _, g := range grants {
		if v, ok := os.LookupEnv(g.Secret); ok {
			if v != "" {
				out[g.Secret] = []byte(v)
			}
			os.Unsetenv(g.Secret)
		}
	}
	return out
}
