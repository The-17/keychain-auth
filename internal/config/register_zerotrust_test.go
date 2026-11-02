package config

import "testing"

// TestRegisterResetsServicesOnHashChange proves that re-registering a path with a
// new hash does not silently carry the old binary's service grants over. Without
// this, a process could overwrite a trusted binary, re-register it, and inherit
// its access to secrets.
func TestRegisterResetsServicesOnHashChange(t *testing.T) {
	c := &Config{RegisteredBinaries: []RegisteredBinary{{
		Path:                 "/usr/local/bin/agentsecrets",
		Hash:                 "sha256:old",
		AllowedReadServices:  []string{"AgentSecrets"},
		AllowedWriteServices: []string{"AgentSecrets"},
		CanSearch:            true,
	}}}

	// Unchanged hash: idempotent, privileges preserved.
	if err := c.Register("/usr/local/bin/agentsecrets", "sha256:old"); err != nil {
		t.Fatal(err)
	}
	rb := c.RegisteredBinaries[0]
	if len(rb.AllowedReadServices) == 0 || !rb.CanSearch {
		t.Fatalf("same-hash register revoked privileges: %+v", rb)
	}

	// Changed hash: must reset to Zero Trust.
	if err := c.Register("/usr/local/bin/agentsecrets", "sha256:new"); err != nil {
		t.Fatal(err)
	}
	rb = c.RegisteredBinaries[0]
	if rb.Hash != "sha256:new" {
		t.Errorf("hash = %s, want sha256:new", rb.Hash)
	}
	if len(rb.AllowedReadServices) != 0 || len(rb.AllowedWriteServices) != 0 || rb.CanSearch {
		t.Errorf("changed hash kept privileges: %+v", rb)
	}
}
