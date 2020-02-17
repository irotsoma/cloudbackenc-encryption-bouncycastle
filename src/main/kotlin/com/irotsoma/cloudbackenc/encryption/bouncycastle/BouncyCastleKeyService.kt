/*
 * Copyright (C) 2016-2020  Irotsoma, LLC
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

import com.irotsoma.cloudbackenc.common.encryption.EncryptionAsymmetricKeyAlgorithms
import com.irotsoma.cloudbackenc.common.encryption.EncryptionKeyService
import com.irotsoma.cloudbackenc.common.encryption.EncryptionPBKDFEncryptionAlgorithms
import com.irotsoma.cloudbackenc.common.encryption.EncryptionSymmetricKeyAlgorithms
import mu.KLogging
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 *
 * Bouncy Castle implementation of encryption key generation services
 */
class BouncyCastleKeyService: EncryptionKeyService {
    private companion object: KLogging() {
        const val DEFAULT_PBKDF_ITERATIONS = 64000
    }

    override fun generatePasswordBasedKey(password:String, salt: ByteArray): SecretKey? {
        return generatePasswordBasedKey(password, salt, EncryptionPBKDFEncryptionAlgorithms.PBKDF2WITHHMACSHA1, 128, DEFAULT_PBKDF_ITERATIONS)
    }

    override fun generatePasswordBasedKey(password:String, salt: ByteArray, algorithm: EncryptionPBKDFEncryptionAlgorithms, keySize: Int, iterations: Int): SecretKey? {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, iterations, keySize)
        val keyFactory = SecretKeyFactory.getInstance(algorithm.value, "BC")
        return keyFactory.generateSecret(keySpec)
    }

    override fun generateSymmetricKey(): SecretKey? {
        return generateSymmetricKey(EncryptionSymmetricKeyAlgorithms.AES, 128, SecureRandom.getInstanceStrong())
    }
    override fun generateSymmetricKey(algorithm: EncryptionSymmetricKeyAlgorithms, keySize: Int): SecretKey? {
        return generateSymmetricKey(algorithm, keySize, SecureRandom.getInstanceStrong())
    }
    override fun generateSymmetricKey(algorithm: EncryptionSymmetricKeyAlgorithms, keySize: Int, secureRandom: SecureRandom): SecretKey? {
        try {
            val keyGen = KeyGenerator.getInstance(algorithm.value, "BC")
            keyGen.init(keySize, secureRandom)
            return keyGen.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            logger.error("Unsupported algorithm: $algorithm, size: $keySize", e)
            return null
        }
    }

    override fun generateAsymmetricKeys(): KeyPair? {
        return generateAsymmetricKeys(EncryptionAsymmetricKeyAlgorithms.RSA, 4096, SecureRandom.getInstanceStrong())
    }
    override fun generateAsymmetricKeys(algorithm: EncryptionAsymmetricKeyAlgorithms, keySize: Int): KeyPair? {
        return generateAsymmetricKeys(algorithm, keySize, SecureRandom.getInstanceStrong())
    }

    override fun generateAsymmetricKeys(algorithm: EncryptionAsymmetricKeyAlgorithms, keySize: Int, secureRandom: SecureRandom): KeyPair? {
        try{
            val keyGen = KeyPairGenerator.getInstance(algorithm.value,"BC")
            keyGen.initialize(keySize, secureRandom)
            return keyGen.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            logger.error("Unsupported algorithm: $algorithm, size: $keySize", e)
            return null
        }
    }

}