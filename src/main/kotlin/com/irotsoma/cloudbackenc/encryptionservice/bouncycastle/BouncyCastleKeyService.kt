package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.logger
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceKeyAlgorithms
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceKeyService
import java.security.KeyPair
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Created by irotsoma on 8/25/2016.
 *
 * Bouncy Castle implementation of encryption key generation services
 */
class BouncyCastleKeyService: EncryptionServiceKeyService {


    companion object { val LOG by logger() }
    override fun generateSymmetricKey(): SecretKey? {
        return generateSymmetricKey(EncryptionServiceKeyAlgorithms.AES, 128, SecureRandom.getInstanceStrong())
    }
    override fun generateSymmetricKey(algorithm: EncryptionServiceKeyAlgorithms, keySize: Int): SecretKey? {
        return generateSymmetricKey(algorithm, keySize, SecureRandom.getInstanceStrong())
    }
    override fun generateSymmetricKey(algorithm: EncryptionServiceKeyAlgorithms, keySize: Int, secureRandom: SecureRandom): SecretKey? {
        try {
            val keyGen = KeyGenerator.getInstance(algorithm.value, "BC")
            keyGen.init(keySize, secureRandom)
            return keyGen.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            LOG.error("Unsupported algorithm: $algorithm, size: $keySize", e)
            return null
        }
    }





    override fun generateAsymmetricKeys(): KeyPair {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun generateAsymmetricKeys(algorithm: EncryptionServiceKeyAlgorithms, keySize: Int): KeyPair {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun generateAsymmetricKeys(algorithm: EncryptionServiceKeyAlgorithms, keySize: Int, secureRandom: SecureRandom): KeyPair {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}