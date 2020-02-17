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

import com.irotsoma.cloudbackenc.common.encryption.EncryptionAsymmetricEncryptionAlgorithms
import com.irotsoma.cloudbackenc.common.encryption.EncryptionException
import com.irotsoma.cloudbackenc.common.encryption.EncryptionStreamService
import com.irotsoma.cloudbackenc.common.encryption.EncryptionSymmetricEncryptionAlgorithms
import mu.KLogging
import java.io.InputStream
import java.io.OutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * Bouncy Castle implementation of encryption and decryption algorithms for files.
 */
class BouncyCastleStreamService : EncryptionStreamService() {
    /** kotlin-logging implementation*/
    private companion object: KLogging()
    /**
     * Decrypt data streams using symmetric (secret key) encryption.
     *
     * @param inputStream Input stream for the data to be decrypted.
     * @param outputStream Output stream for the data after decryption
     * @param key Secret key to be used to decrypt the data
     * @param algorithm Algorithm from EncryptionSymmetricEncryptionAlgorithms to be used to decrypt the data.
     * @param ivParameterSpec An instance of IvParameterSpec that contains the initialization vector for encryption algorithms that require it.  Use null if not required by the algorithm.
     * @param secureRandom An instance of a SecureRandom random number generator.  If not sent, a new one will be generated using the default Java algorithm.  If encrypting or decrypting lots of files or strings, it is recommended to generate the SecureRandom once rather than once per call as it can be a resource intensive operation.
     */
    override fun decrypt(inputStream: InputStream, outputStream: OutputStream, key: SecretKey, algorithm: EncryptionSymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?) {
        val decryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec, secureRandom)
        val cipherInputStream = CipherInputStream(inputStream, decryptionCipher)
        copy(cipherInputStream, outputStream, decryptionCipher.blockSize)
    }
    /**
     * Encrypt dta streams using symmetric (secret key) encryption.
     *
     * @param inputStream Input stream for the data to be encrypted.
     * @param outputStream Output stream for the data after encryption
     * @param key Secret key to be used to encrypt the data
     * @param algorithm Algorithm from EncryptionSymmetricEncryptionAlgorithms to be used to encrypt the data.
     * @param ivParameterSpec An instance of IvParameterSpec that contains the initialization vector for encryption algorithms that require it.  Use null if not required by the algorithm.
     * @param secureRandom An instance of a SecureRandom random number generator.  If not sent, a new one will be generated using the default Java algorithm.  If encrypting or decrypting lots of files or strings, it is recommended to generate the SecureRandom once rather than once per call as it can be a resource intensive operation.
     */
    override fun encrypt(inputStream: InputStream, outputStream: OutputStream, key: SecretKey, algorithm: EncryptionSymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?) {
        val encryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec, secureRandom)
        val cipherOutputStream = CipherOutputStream(outputStream, encryptionCipher)
        copy(inputStream,cipherOutputStream, encryptionCipher.blockSize)
    }

    /**
     * Simple function to copy streams.
     *
     * @param inputStream An InputStream of the data to be copied.
     * @param outputStream An OutputStream for the destination of the data.
     * @param blockSize The block size to be used for copying data.
     */
    private fun copy(inputStream: InputStream, outputStream: OutputStream, blockSize: Int) {
        try {
            val byteArray = ByteArray(blockSize)
            var inputLength = inputStream.read(byteArray)
            while (inputLength != -1) {
                outputStream.write(byteArray, 0, inputLength)
                inputLength = inputStream.read(byteArray)
            }
            inputStream.close()
            outputStream.flush()
            outputStream.close()
        } catch (ex: Exception) {
            logger.error{ex.message}
            throw EncryptionException(ex.message, ex)
        }
    }
    /**
     * Decrypt data streams using asymmetric (public key) encryption.
     *
     * @param inputStream Input stream for the data to be decrypted.
     * @param outputStream Output stream for the data after decryption
     * @param key Secret key to be used to decrypt the data
     * @param algorithm Algorithm from EncryptionAsymmetricEncryptionAlgorithms to be used to decrypt the data.
     * @param secureRandom An instance of a SecureRandom random number generator.  If not sent, a new one will be generated using the default Java algorithm.  If encrypting or decrypting lots of files or strings, it is recommended to generate the SecureRandom once rather than once per call as it can be a resource intensive operation.
     */
    override fun decrypt(inputStream: InputStream, outputStream: OutputStream, key: PrivateKey, algorithm: EncryptionAsymmetricEncryptionAlgorithms, secureRandom: SecureRandom?) {
        val decryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, secureRandom)
        val cipherInputStream = CipherInputStream(inputStream, decryptionCipher)
        copy(cipherInputStream, outputStream, decryptionCipher.blockSize)
    }
    /**
     * Encrypt data streams using asymmetric (public key) encryption.
     *
     * @param inputStream Input stream for the data to be encrypted.
     * @param outputStream Output stream for the data after encryption
     * @param key Public key to be used to encrypt the data
     * @param algorithm Algorithm from EncryptionAsymmetricEncryptionAlgorithms to be used to encrypt the data.
     * @param secureRandom An instance of a SecureRandom random number generator.  If not sent, a new one will be generated using the default Java algorithm.  If encrypting or decrypting lots of files or strings, it is recommended to generate the SecureRandom once rather than once per call as it can be a resource intensive operation.
     */
    override fun encrypt(inputStream: InputStream, outputStream: OutputStream, key: PublicKey, algorithm: EncryptionAsymmetricEncryptionAlgorithms, secureRandom: SecureRandom?) {
        val encryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key, secureRandom)
        val cipherOutputStream = CipherOutputStream(outputStream, encryptionCipher)
        copy(inputStream,cipherOutputStream, encryptionCipher.blockSize)
    }
}