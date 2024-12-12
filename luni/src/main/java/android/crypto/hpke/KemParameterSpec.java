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

import java.security.spec.NamedParameterSpec;

@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
public class KemParameterSpec extends NamedParameterSpec {
    /**
     * @see NamedParameterSpec
     */
    public KemParameterSpec(@NonNull String stdName) {
        super(stdName);
    }

    public static final KemParameterSpec DHKEM_X25519_HKDF_SHA256
            = new KemParameterSpec("DHKEM_X25519_HKDF_SHA256");

    public static final KemParameterSpec DHKEM_P256_HKDF_SHA256
            = new KemParameterSpec("DHKEM_P256_HKDF_SHA256");
}
