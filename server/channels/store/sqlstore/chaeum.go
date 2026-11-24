// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package sqlstore

// EncryptedContentMaxRunes is set by the encryption layer (channels/store/encryptlayer). When it is
// non-zero the message this store receives is ciphertext, which is longer than the plaintext the
// layer above already validated, so the store's own length checks use this limit instead.
var EncryptedContentMaxRunes int

func storedSizeLimit(plain int) int {
	if EncryptedContentMaxRunes > plain {
		return EncryptedContentMaxRunes
	}
	return plain
}
