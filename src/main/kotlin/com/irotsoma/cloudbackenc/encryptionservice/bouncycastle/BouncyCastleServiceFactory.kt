/*
 * Copyright (C) 2016-2017  Irotsoma, LLC
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
package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.encryptionserviceinterface.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Bouncy Castle Encryption Service Factory
 */
class BouncyCastleServiceFactory: EncryptionServiceFactory {
    override val supportedPBKDFAlgorithms = arrayOf(EncryptionServicePBKDFAlgorithms.PBKDF2WithHmacSHA1)
    override val supportedSymmetricKeyAlgorithms = arrayOf(
            EncryptionServiceSymmetricKeyAlgorithms.AES,
            EncryptionServiceSymmetricKeyAlgorithms.Blowfish,
            EncryptionServiceSymmetricKeyAlgorithms.SKIPJACK,
            EncryptionServiceSymmetricKeyAlgorithms.Twofish)
    override val supportedSymmetricEncryptionAlgorithms = arrayOf(
            EncryptionServiceSymmetricEncryptionAlgorithms.AES,
            EncryptionServiceSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding,
            EncryptionServiceSymmetricEncryptionAlgorithms.AES_ECB_WithCTS,
            EncryptionServiceSymmetricEncryptionAlgorithms.Blowfish_CBC_PKCS5Padding,
            EncryptionServiceSymmetricEncryptionAlgorithms.SKIPJACK_ECB_PKCS7Padding,
            EncryptionServiceSymmetricEncryptionAlgorithms.Twofish_CBC_PKCS5Padding)
    override val supportedAsymmetricEncryptionAlgorithms = emptyArray<EncryptionServiceAsymmetricEncryptionAlgorithms>()
    override val supportedAsymmetricKeyAlgorithms = emptyArray<EncryptionServiceAsymmetricKeyAlgorithms>()
    override val encryptionServiceFileService = BouncyCastleFileService()
    override val encryptionServiceKeyService = BouncyCastleKeyService()
    override val encryptionServiceStringService = BouncyCastleStringService()
    init{
        Security.addProvider(BouncyCastleProvider())
    }
}