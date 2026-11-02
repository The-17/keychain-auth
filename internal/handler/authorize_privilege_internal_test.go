package handler

import "testing"

// TestAuthorizePrivileged pins the trust boundary for the administrative
// authorize action. On a system store only root may authorize, so an
// adversarial agent running as the user cannot grant itself access. On a
// user-mode store the daemon's own user is the trust root. Unknown credentials
// always fail closed.
func TestAuthorizePrivileged(t *testing.T) {
	cases := []struct {
		name        string
		peerUID     uint32
		peerUIDOK   bool
		systemStore bool
		daemonUID   int
		want        bool
	}{
		{"system store, root peer", 0, true, true, 999, true},
		{"system store, unprivileged user peer", 1000, true, true, 999, false},
		{"system store, unknown credentials", 0, false, true, 999, false},
		{"user store, daemon owner", 1000, true, false, 1000, true},
		{"user store, different uid", 1001, true, false, 1000, false},
		{"user store, unknown credentials", 1000, false, false, 1000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizePrivileged(tc.peerUID, tc.peerUIDOK, tc.systemStore, tc.daemonUID); got != tc.want {
				t.Errorf("authorizePrivileged(uid=%d, ok=%v, system=%v, daemon=%d) = %v, want %v",
					tc.peerUID, tc.peerUIDOK, tc.systemStore, tc.daemonUID, got, tc.want)
			}
		})
	}
}
