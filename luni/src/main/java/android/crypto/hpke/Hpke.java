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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Objects;

/**
 * Provides access to implementations of HPKE hybrid cryptography as per RFC 9180.
 * <p>
 * Provider and HPKE algorithm selection are done via the {@code getInstance}
 * methods, and then instances of senders and receivers can be created using
 * {@code newSender} or {newReceiver}.  Each sender and receiver is independent, i.e. does
 * not share any encapsulated state with other senders or receivers created via this
 * {@code Hpke}.
 */
@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
public class Hpke {
    private static final byte[] DEFAULT_PSK = new byte[0];
    private static final byte[] DEFAULT_PSK_ID = DEFAULT_PSK;
    private static final String SERVICE = "ConscryptHpke";
    private final Provider provider;
    private final Provider.Service service;

    private Hpke(@NonNull String algorithm, @NonNull Provider provider)
            throws NoSuchAlgorithmException {
        this.provider = provider;
        service = getService(provider, algorithm);
        if (service == null) {
            throw new NoSuchAlgorithmException("No such HPKE algorithm: " + algorithm);
        }
    }

    private static @NonNull Provider findFirstProvider(@NonNull String algorithm)
            throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            if (getService(provider, algorithm) != null) {
                return provider;
            }
        }
        throw new NoSuchAlgorithmException("No Provider found for: " + algorithm);
    }

    private static Provider.Service getService(Provider provider, String algorithm)
            throws NoSuchAlgorithmException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException();
        }
        return provider.getService(SERVICE, algorithm);
    }

    private @NonNull HpkeSpi findSpi() {
        Object instance;
        try {
            instance = service.newInstance(null);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Initialisation error", e);
        }
        if (instance instanceof HpkeSpi) {
            return (HpkeSpi) instance;
        } else {
            DuckTypedHpkeSpi spi = DuckTypedHpkeSpi.newInstance(instance);
            if (spi != null) {
                return spi;
            }
        }
        throw new IllegalStateException(
                String.format("Provider %s is incorrectly configured", provider.getName()));
    }

    /**
     * Returns the {@link Provider} being used by this Hpke instance.
     * <p>
     *
     * @return the Provider
     */
    public @NonNull Provider getProvider() {
        return provider;
    }

    /**
     * Returns an Hpke instance configured for the supplied HPKE algorithm, using the
     * highest priority Provider which implements it.
     *
     * @param algorithm the HPKE algorithm to use
     * @return an Hpke instance configured for the requested algorithm
     * @throws NoSuchAlgorithmException if no Providers can be found for the requested algorithm
     */
    public static @NonNull Hpke getInstance(@NonNull String algorithm)
            throws NoSuchAlgorithmException {
        return new Hpke(algorithm, findFirstProvider(algorithm));
    }

    /**
     * Returns an Hpke instance configured for the supplied HPKE algorithm, using the
     * requested Provider.
     *
     * @param algorithm    the HPKE algorithm to use
     * @param providerName the name of the provider to use
     * @return an Hpke instance configured for the requested algorithm and Provider
     * @throws NoSuchAlgorithmException if the named Provider does not implement this algorithm
     * @throws NoSuchProviderException  if no Provider with the requested name can be found
     * @throws IllegalArgumentException if providerName is null or empty
     */
    public static @NonNull Hpke getInstance(@NonNull String algorithm, @NonNull String providerName)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if (providerName == null || providerName.isEmpty()) {
            throw new IllegalArgumentException("Invalid Provider Name");
        }
        Provider provider = Security.getProvider(providerName);
        if (provider == null) {
            throw new NoSuchProviderException();
        }
        return new Hpke(algorithm, provider);
    }

    /**
     * Returns an Hpke instance configured for the supplied HPKE algorithm, using the
     * requested Provider.
     *
     * @param algorithm the HPKE algorithm to use
     * @param provider  the provider to use
     * @return an Hpke instance configured for the requested algorithm and Provider
     * @throws NoSuchAlgorithmException if the named Provider does not implement this algorithm
     * @throws IllegalArgumentException if provider is null
     */
    public static @NonNull Hpke getInstance(@NonNull String algorithm, @NonNull Provider provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider == null) {
            throw new IllegalArgumentException("Null Provider");
        }
        return new Hpke(algorithm, provider);
    }

    /**
     * Generates the HPKE suite algorithm name from the named parameter specifications of its
     * components.
     *
     * @param kem  the key encapsulation mechanism to use
     * @param kdf  the key derivation function to use
     * @param aead the AEAD cipher to use
     */
    public static @NonNull String getAlgorithmName(@NonNull KemParameterSpec kem,
            @NonNull KdfParameterSpec kdf, @NonNull AeadParameterSpec aead) {
        return kem.getName() + "/" + kdf.getName() + "/" + aead.getName();
    }

    /**
     * A builder for HPKE Sender objects.
     */
    @FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
    public class SenderBuilder {
        private final PublicKey recipientKey;
        private byte[] applicationInfo = null;
        private PrivateKey senderKey = null;
        private byte[] psk = DEFAULT_PSK;
        private byte[] pskId = DEFAULT_PSK_ID;

        /**
         * Creates the Builder.
         *
         * @param recipientKey public key of the recipient
         */
        private SenderBuilder(@NonNull PublicKey recipientKey) {
            Objects.requireNonNull(recipientKey);
            this.recipientKey = recipientKey;
        }

        /**
         * Adds optional application-related data which will be used during the key generation
         * process.
         *
         * @param applicationInfo application-specific information
         *
         * @return the Builder
         */
        public @NonNull SenderBuilder setApplicationInfo(@NonNull byte[] applicationInfo) {
            this.applicationInfo = applicationInfo;
            return this;
        }

        /**
         * Sets the sender key to be used by the recipient for message authentication.
         *
         * @param senderKey the sender's public key
         * @return the Builder
         */
        public @NonNull SenderBuilder setSenderKey(@NonNull PrivateKey senderKey) {
            this.senderKey = senderKey;
            return this;
        }

        /**
         * Sets pre-shared key information to be used for message authentication.
         *
         * @param psk          the pre-shared secret key
         * @param pskId       the id of the pre-shared key
         * @return the Builder
         */
        public @NonNull SenderBuilder setPsk(@NonNull byte[] psk, @NonNull byte[] pskId) {
            this.psk = psk;
            this.pskId = pskId;
            return this;
        }

        /**
         * Created the {@link Sender} object.
         *
         * @throws InvalidKeyException           if the sender or recipient key are unsupported
         * @throws UnsupportedOperationException if this Provider does not support the expected mode
         */
        public @NonNull Sender build() throws InvalidKeyException {
            HpkeSpi spi = findSpi();
            spi.engineInitSender(recipientKey, applicationInfo, senderKey, psk, pskId);
            return new Sender(Hpke.this, spi);
        }
    }

    /**
     * Creates a new {@link SenderBuilder} for this {@link Hpke} object.
     *
     * @param recipientKey public key of the recipient
     */
    public SenderBuilder newSender(@NonNull PublicKey recipientKey) {
        return new SenderBuilder(recipientKey);
    }

    /**
     * A builder for HPKE Recipient objects.
     */
    @FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
    public class RecipientBuilder {
        private final byte[] encapsulated ;
        private final PrivateKey recipientKey;
        private byte[] applicationInfo = null;
        private PublicKey senderKey = null;
        private byte[] psk = DEFAULT_PSK;
        private byte[] pskId = DEFAULT_PSK_ID;

        /**
         * Creates the builder.
         *
         * @param encapsulated encapsulated ephemeral key from an {@link Sender}
         * @param recipientKey private key of the recipient
         */
        private RecipientBuilder(@NonNull byte[] encapsulated, @NonNull PrivateKey recipientKey) {
            Objects.requireNonNull(encapsulated);
            Objects.requireNonNull(recipientKey);
            this.encapsulated = encapsulated;
            this.recipientKey = recipientKey;
        }

        /**
         * Adds optional application-related data which will be used during the key generation
         * process.
         *
         * @param applicationInfo application-specific information
         *
         * @return the Builder
         */
        public @NonNull RecipientBuilder setApplicationInfo(@NonNull byte[] applicationInfo) {
            Objects.requireNonNull(applicationInfo);
            this.applicationInfo = applicationInfo;
            return this;
        }

        /**
         * Sets the sender key to be used by the recipient for message authentication.
         *
         * @param senderKey the sender's public key
         * @return the Builder
         */
        public @NonNull RecipientBuilder setSenderKey(@NonNull PublicKey senderKey) {
            Objects.requireNonNull(senderKey);
            this.senderKey = senderKey;
            return this;
        }

        /**
         * Sets pre-shared key information to be used for message authentication.
         *
         * @param psk          the pre-shared secret key
         * @param pskId       the id of the pre-shared key
         * @return the Builder
         */
        public @NonNull RecipientBuilder setPsk(@NonNull byte[] psk, @NonNull byte[] pskId) {
            Objects.requireNonNull(psk);
            Objects.requireNonNull(pskId);
            this.psk = psk;
            this.pskId = pskId;
            return this;
        }

        /**
         * Builds the {@link Recipient}.
         *
         * @return the Recipient
         * @throws InvalidKeyException           if the sender or recipient key are unsupported
         * @throws UnsupportedOperationException if this Provider does not support the expected mode
         */
        public @NonNull Recipient build() throws InvalidKeyException {
            HpkeSpi spi = findSpi();
            spi.engineInitRecipient(encapsulated, recipientKey, applicationInfo, senderKey, psk,
                    pskId);
            return new Recipient(Hpke.this, spi);
        }
    }

    /**
     * Creates a new {@link RecipientBuilder} for this {@link Hpke} object.
     *
     * @param encapsulated encapsulated ephemeral key from an {@link Sender}
     * @param recipientKey private key of the recipient
     * @return the Builder
     */
    public RecipientBuilder newRecipient(
            @NonNull byte[] encapsulated, @NonNull PrivateKey recipientKey) {
        return new RecipientBuilder(encapsulated, recipientKey);
    }

    /**
     * One shot API to seal a single message using BASE mode (no authentication).
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption-2">
     *     Opening and sealing</a>
     * @param recipientKey public key of the recipient
     * @param info         additional application-supplied information, may be null or empty
     * @param plaintext    the message to send
     * @param aad          optional additional authenticated data, may be null or empty
     * @return a Message object containing the encapsulated key, ciphertext and aad
     * @throws InvalidKeyException      if recipientKey is null or an unsupported key format
     */
    public @NonNull Message seal(@NonNull PublicKey recipientKey, @Nullable byte[] info,
            @NonNull byte[] plaintext, @Nullable byte[] aad)
            throws InvalidKeyException {
        SenderBuilder senderBuilder = new SenderBuilder(recipientKey);
        if (info != null) {
            senderBuilder.setApplicationInfo(info);
        }
        Sender sender = senderBuilder.build();
        byte[] encapsulated = sender.getEncapsulated();
        byte[] ciphertext = sender.seal(plaintext, aad);
        return new Message(encapsulated, ciphertext);
    }

    /**
     * One shot API to open a single ciphertext using BASE mode (no authentication).
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption-2">
     *     Opening and sealing</a>
     * @param recipientKey private key of the recipient
     * @param info         application-supplied information, may be null or empty
     * @param message      the Message to open
     * @param aad          optional additional authenticated data, may be null or empty
     * @return decrypted plaintext
     * @throws InvalidKeyException      if recipientKey is null or an unsupported key format
     * @throws GeneralSecurityException if the decryption fails
     */
    public @NonNull byte[] open(
            @NonNull PrivateKey recipientKey, @Nullable byte[] info, @NonNull Message message,
            @Nullable byte[] aad)
            throws GeneralSecurityException, InvalidKeyException {
        RecipientBuilder recipientBuilder
                = new RecipientBuilder(message.getEncapsulated(), recipientKey);
        if (info != null) {
            recipientBuilder.setApplicationInfo(info);
        }
        return recipientBuilder.build().open(message.getCiphertext(), aad);
    }
}
