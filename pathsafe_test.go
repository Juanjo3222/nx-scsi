package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// Le path traversal était : un sub de token / application_id forgé avec "../" sortait de
// dataDir via filepath.Join. Ce test fige le confinement.
func TestPathTraversalContained(t *testing.T) {
	bad := []string{"../../../../tmp/pwned", "..", "a/b", "a\b", "/etc/passwd", "x:y", "", strings.Repeat("a", 65)}
	for _, v := range bad {
		if safeIDComponent(v) {
			t.Errorf("composant DANGEREUX accepté: %q", v)
		}
		if pathComp(v) == v {
			t.Errorf("pathComp n'a pas neutralisé: %q", v)
		}
	}
	good := []string{"c481d0cfa1569241", "0100152000022000", "u-abcDEF123", "0000000000000000"}
	for _, v := range good {
		if !safeIDComponent(v) {
			t.Errorf("identifiant légitime refusé: %q", v)
		}
	}

	// Confinement réel : un NsaID/AppID piégé ne doit jamais sortir de dataDir.
	a := &Archive{NsaID: "../../../../tmp/pwned", ApplicationID: "../../etc", ID: 7}
	dir := filepath.Clean((&Store{}).archiveDir(a))
	root := filepath.Clean(dataDir)
	if dir != root && !strings.HasPrefix(dir, root+string(filepath.Separator)) {
		t.Fatalf("ÉVASION: archiveDir=%q sort de %q", dir, root)
	}
}
