/*
 * Copyright (C) 2016  Irotsoma, LLC
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
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.encryptionservice.EncryptionServiceEncryptionAlgorithms
import com.irotsoma.cloudbackenc.common.encryptionservice.EncryptionServiceFactory
import com.irotsoma.cloudbackenc.common.encryptionservice.EncryptionServiceKeyAlgorithms
import com.irotsoma.cloudbackenc.common.encryptionservice.EncryptionServicePBKDFAlgorithms
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Created by irotsoma on 8/25/2016.
 *
 * Bouncy Castle Encryption Service Factory
 */
class BouncyCastleServiceFactory: EncryptionServiceFactory {
    override val supportedPBKDFAlgorithms = arrayOf(EncryptionServicePBKDFAlgorithms.PBKDF2WithHmacSHA1)
    override val supportedKeyAlgorithms = arrayOf(
            EncryptionServiceKeyAlgorithms.AES,
            EncryptionServiceKeyAlgorithms.Blowfish,
            EncryptionServiceKeyAlgorithms.DES,
            EncryptionServiceKeyAlgorithms.SKIPJACK,
            EncryptionServiceKeyAlgorithms.Twofish)
    override val supportedEncryptionAlgorithms = arrayOf(
            EncryptionServiceEncryptionAlgorithms.AES,
            EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding,
            EncryptionServiceEncryptionAlgorithms.AES_ECB_WithCTS,
            EncryptionServiceEncryptionAlgorithms.Blowfish_CBC_PKCS5Padding,
            EncryptionServiceEncryptionAlgorithms.DES_CBC_PKCS5Padding,
            EncryptionServiceEncryptionAlgorithms.DES_ECB_WithCTS,
            EncryptionServiceEncryptionAlgorithms.SKIPJACK_ECB_PKCS7Padding,
            EncryptionServiceEncryptionAlgorithms.Twofish_CBC_PKCS5Padding)
    override val encryptionServiceFileService = BouncyCastleFileService()
    override val encryptionServiceKeyService = BouncyCastleKeyService()
    override val encryptionServiceStringService = BouncyCastleStringService()
    init{
        Security.addProvider(BouncyCastleProvider())
    }
}