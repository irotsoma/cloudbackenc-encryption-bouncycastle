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
/*
 * Created by irotsoma on 8/25/2016.
 */
package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.encryptionserviceinterface.EncryptionServiceAsymmetricEncryptionAlgorithms
import com.irotsoma.cloudbackenc.common.encryptionserviceinterface.EncryptionServiceException
import com.irotsoma.cloudbackenc.common.encryptionserviceinterface.EncryptionServiceFileService
import com.irotsoma.cloudbackenc.common.encryptionserviceinterface.EncryptionServiceSymmetricEncryptionAlgorithms
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
class BouncyCastleFileService : EncryptionServiceFileService() {
    /** kotlin-logging implementation*/
    companion object: KLogging()
    override fun decrypt(inputStream: InputStream, outputStream: OutputStream, key: SecretKey, algorithm: EncryptionServiceSymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?) {
        val decryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec, secureRandom)
        val cipherInputStream = CipherInputStream(inputStream, decryptionCipher)
        copy(cipherInputStream, outputStream)
    }

    override fun encrypt(inputStream: InputStream, outputStream: OutputStream, key: SecretKey, algorithm: EncryptionServiceSymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?) {
        val encryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec, secureRandom)
        val cipherOutputStream = CipherOutputStream(outputStream, encryptionCipher)
        copy(inputStream,cipherOutputStream)
    }

    private fun copy(inputStream: InputStream, outputStream: OutputStream) {
        try {
            val byteArray = ByteArray(1024)
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
            throw EncryptionServiceException(ex.message, ex)
        }
    }

    override fun decrypt(inputStream: InputStream, outputStream: OutputStream, key: PrivateKey, algorithm: EncryptionServiceAsymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?) {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encrypt(inputStream: InputStream, outputStream: OutputStream, key: PublicKey, algorithm: EncryptionServiceAsymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?) {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}