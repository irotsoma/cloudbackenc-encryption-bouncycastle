package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Created by irotsoma on 8/25/2016.
 */
class BouncyCastleServiceFactory: EncryptionServiceFactory {
    init{
        Security.addProvider(BouncyCastleProvider())
    }
    override val encryptionServiceFileService = BouncyCastleFileService()
    override val encryptionServiceKeyService = BouncyCastleKeyService()
    override val encryptionServiceStringService = BouncyCastleStringService()
}