package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.logger
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceSymmetricKeyService
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Created by irotsoma on 8/25/2016.
 */
class BouncyCastleKeyService: EncryptionServiceSymmetricKeyService {

    companion object { val LOG by logger() }
    override fun generateSymmetricKey(): SecretKey? {
        return generateSymmetricKey("AES", 128, SecureRandom.getInstanceStrong())
    }
    override fun generateSymmetricKey(algorithm: String, keySize: Int): SecretKey? {
        return generateSymmetricKey(algorithm, keySize, SecureRandom.getInstanceStrong())
    }
    override fun generateSymmetricKey(algorithm: String, keySize: Int, secureRandom: SecureRandom): SecretKey? {
        try {
            val keyGen = KeyGenerator.getInstance(algorithm, "BC")
            keyGen.init(keySize, secureRandom)
            return keyGen.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            LOG.error("Unsupported algorithm: $algorithm, size: $keySize", e)
            return null
        }

    }
}