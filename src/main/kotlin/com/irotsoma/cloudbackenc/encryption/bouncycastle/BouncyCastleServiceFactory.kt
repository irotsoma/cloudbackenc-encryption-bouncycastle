/*
 * Copyright (C) 2016-2019  Irotsoma, LLC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
/*
 * Created by irotsoma on 8/25/2016.
 */
package com.irotsoma.cloudbackenc.encryption.bouncycastle

import com.irotsoma.cloudbackenc.common.encryption.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Bouncy Castle Encryption Service Factory
 */
class BouncyCastleServiceFactory: EncryptionFactory() {
    override val supportedPBKDFAlgorithms = arrayOf(EncryptionPBKDFAlgorithms.PBKDF2WithHmacSHA1)
    override val supportedSymmetricKeyAlgorithms = arrayOf(
            EncryptionSymmetricKeyAlgorithms.AES,
            EncryptionSymmetricKeyAlgorithms.Blowfish,
            EncryptionSymmetricKeyAlgorithms.SKIPJACK,
            EncryptionSymmetricKeyAlgorithms.Twofish)
    override val supportedSymmetricEncryptionAlgorithms = arrayOf(
            EncryptionSymmetricEncryptionAlgorithms.AES,
            EncryptionSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding,
            EncryptionSymmetricEncryptionAlgorithms.AES_ECB_WithCTS,
            EncryptionSymmetricEncryptionAlgorithms.Blowfish_CBC_PKCS5Padding,
            EncryptionSymmetricEncryptionAlgorithms.SKIPJACK_ECB_PKCS7Padding,
            EncryptionSymmetricEncryptionAlgorithms.Twofish_CBC_PKCS5Padding)
    override val supportedAsymmetricEncryptionAlgorithms = arrayOf(
            EncryptionAsymmetricEncryptionAlgorithms.RSA,
            EncryptionAsymmetricEncryptionAlgorithms.RSA_ECB_OAEPWithSHA1AndMGF1Padding,
            EncryptionAsymmetricEncryptionAlgorithms.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
    override val supportedAsymmetricKeyAlgorithms = arrayOf(EncryptionAsymmetricKeyAlgorithms.RSA)
    override val encryptionFileService = BouncyCastleFileService()
    override val encryptionKeyService = BouncyCastleKeyService()
    override val encryptionStringService = BouncyCastleStringService()
    init{
        Security.addProvider(BouncyCastleProvider())
    }
}