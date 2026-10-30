package controller

import (
	ss "github.com/wyx2685/XrayR/common/corecompat/legacyss"
	"testing"
)

func TestDynamicCipherAliases(t *testing.T) {
	for _, s := range []string{"xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305"} {
		if cipherFromString(s) != ss.CipherType_XCHACHA20_POLY1305 {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"none", "plain"} {
		if cipherFromString(s) != ss.CipherType_NONE {
			t.Fatal(s)
		}
	}
}
