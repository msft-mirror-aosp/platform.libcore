/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.crypto.hpke;

import android.annotation.FlaggedApi;

import libcore.util.NonNull;
import libcore.util.Nullable;

import java.security.Provider;
import java.util.Objects;

/**
 * A class for sending HPKE messages.
 */
@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
public class Sender {
    private final Hpke parent;
    private final HpkeSpi spi;

    Sender(@NonNull Hpke parent, @NonNull HpkeSpi spi) {
        this.parent = parent;
        this.spi = spi;
    }

    /**
     * Returns the encapsulated ephemeral key created for this Sender.
     *
     * @return the encapsulated key
     */
    public @NonNull byte[] getEncapsulated() {
        return spi.getEncapsulated();
    }

    /**
     * Seals a message, using the internal key schedule maintained by this Sender.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption-2">
     *     Opening and sealing</a>
     * @param plaintext the plaintext
     * @param aad       optional additional authenticated data, may be null or empty
     * @return the ciphertext
     */
    public @NonNull byte[] seal(@NonNull byte[] plaintext, @Nullable byte[] aad) {
        Objects.requireNonNull(plaintext);
        return spi.engineSeal(plaintext, aad);
    }

    /**
     * Exports secret key material from this Sender as described in RFC 9180.
     *
     * @param length  expected output length
     * @param context optional exporter context string, may be null or empty
     * @return the exported value
     * @throws IllegalArgumentException if the length is not valid for the Sender's KDF
     */
    public @NonNull byte[] export(int length, @Nullable byte[] context) {
        return spi.engineExport(length, context);
    }

    /**
     * Returns the {@link HpkeSpi} being used by this Sender.
     *
     * @return the SPI
     */
    public @NonNull HpkeSpi getSpi() {
        return spi;
    }

    /**
     * Returns the {@link Provider} being used by this Sender.
     *
     * @return the Provider
     */
    public @NonNull Provider getProvider() {
        return parent.getProvider();
    }
}
