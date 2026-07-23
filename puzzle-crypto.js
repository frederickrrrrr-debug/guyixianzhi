(function () {
    'use strict';

    // AES-GCM only requires the IV to be unique for a given key. Every puzzle
    // derives a different key by including its unique challenge ID.
    const FIXED_IV = new Uint8Array([
        71, 85, 89, 73, 88, 73, 65, 78, 90, 72, 73, 1
    ]);
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    function decodeBase64(value) {
        const binary = atob(value);
        return Uint8Array.from(binary, function (character) {
            return character.charCodeAt(0);
        });
    }

    async function deriveKey(challengeId, input) {
        const material = encoder.encode(challengeId + '\0' + input);
        const digest = await crypto.subtle.digest('SHA-256', material);

        return crypto.subtle.importKey(
            'raw',
            digest,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
    }

    async function decrypt(challengeId, input, ciphertext) {
        try {
            const key = await deriveKey(challengeId, input);
            const plaintext = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: FIXED_IV },
                key,
                decodeBase64(ciphertext)
            );
            return decoder.decode(plaintext);
        } catch (error) {
            return null;
        }
    }

    async function verify(challengeId, input, ciphertext) {
        return (await decrypt(challengeId, input, ciphertext)) !== null;
    }

    window.PuzzleCrypto = Object.freeze({
        decrypt: decrypt,
        verify: verify
    });
})();
