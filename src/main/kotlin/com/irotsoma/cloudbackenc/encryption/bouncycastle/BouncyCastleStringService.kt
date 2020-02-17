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
import com.irotsoma.cloudbackenc.common.encryption.EncryptionStringService
import com.irotsoma.cloudbackenc.common.encryption.EncryptionSymmetricEncryptionAlgorithms
import org.bouncycastle.util.encoders.Base64
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec


/**
 * Bouncy Castle implementation of String encryption and decryption services
 */



class BouncyCastleStringService: EncryptionStringService {

    override fun decrypt(input: String, key: PrivateKey, algorithm: EncryptionAsymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?): String {
        throw UnsupportedOperationException("not implemented")
    }

    override fun decrypt(input: String, key: SecretKey, algorithm: EncryptionSymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?): String {
        val decryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec, secureRandom)
        val inputBytes = Base64.decode(input.toByteArray(Charsets.UTF_8))
        val result = decryptionCipher.doFinal(inputBytes)
        return String(result)
    }

    override fun encrypt(input: String, key: PublicKey, algorithm: EncryptionAsymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?): String {
        throw UnsupportedOperationException("not implemented")

    }

    override fun encrypt(input: String, key: SecretKey, algorithm: EncryptionSymmetricEncryptionAlgorithms, ivParameterSpec: IvParameterSpec?, secureRandom: SecureRandom?): String {
        val encryptionCipher = Cipher.getInstance(algorithm.value, "BC")
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec, secureRandom)
        val result = encryptionCipher.doFinal(input.toByteArray(Charsets.UTF_8))
        return String(Base64.encode(result))
    }


}