package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceEncryptionAlgorithms
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceFactory
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceKeyAlgorithms
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Created by irotsoma on 8/25/2016.
 *
 * Bouncy Castle Encryption Service Factory
 */
class BouncyCastleServiceFactory: EncryptionServiceFactory {
    override val supportedKeyAlgorithms = arrayOf(EncryptionServiceKeyAlgorithms.AES)
    override val supportedEncryptionAlgorithms = arrayOf(EncryptionServiceEncryptionAlgorithms.AES, EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding)
    override val encryptionServiceFileService = BouncyCastleFileService()
    override val encryptionServiceKeyService = BouncyCastleKeyService()
    override val encryptionServiceStringService = BouncyCastleStringService()
    init{
        Security.addProvider(BouncyCastleProvider())
    }
}