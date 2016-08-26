package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.logger
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceException
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceFileService
import org.bouncycastle.crypto.CryptoException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Created by irotsoma on 8/25/2016.
 */
class BouncyCastleFileService : EncryptionServiceFileService {
    companion object { val LOG by logger() }
    //TODO: works with AES as algorithm but issue when using AES/CBC/PKCS5Padding.  java.security.InvalidKeyException: no IV set when one expected.  Seems to need an IV in order to decrypt, but when this is added, the first 16 bytes of the decrypted file are different from the original.  Likely needs to be the same as the one used to encrypt, also seems to need to use the same block size as the iv?  Needs more research.
    override fun decrypt(inputStream: InputStream, outputStream: OutputStream, key: SecretKey, algorithm: String) {
        val decryptionCipher = Cipher.getInstance(algorithm, "BC")
        decryptionCipher.init(Cipher.DECRYPT_MODE, key)
        transform(inputStream, outputStream, decryptionCipher)
    }

    override fun encrypt(inputStream: InputStream, outputStream: OutputStream, key: SecretKey, algorithm: String) {
        val encryptionCipher = Cipher.getInstance(algorithm, "BC")
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key)
        transform(inputStream, outputStream, encryptionCipher)
    }

    fun transform(inputStream: InputStream, outputStream: OutputStream, cipher: Cipher){
        val inBlockSize = 16
        val outBlockSize = cipher.getOutputSize(inBlockSize)

        val inBlock = ByteArray(inBlockSize)
        val outBlock = ByteArray(outBlockSize)

        try {
            var inLength = inputStream.read(inBlock, 0, inBlockSize)
            var outLength: Int
            while (inLength > 0) {
                outLength = cipher.update(inBlock, 0, inLength, outBlock, 0)
                if (outLength > 0) {
                    outputStream.write(outBlock, 0, outLength)
                }
                inLength = inputStream.read(inBlock, 0, inBlockSize)
            }
            try {
                outLength = cipher.doFinal(outBlock, 0)
                if (outLength > 0) {
                    outputStream.write(outBlock, 0, outLength)
                }
            } catch (ce: CryptoException) {
                LOG.error(ce.message)
                throw EncryptionServiceException(ce.message,ce)
            }
            inputStream.close()
            outputStream.close()
        } catch (ioe: IOException) {
            LOG.error(ioe.message)
            throw EncryptionServiceException(ioe.message, ioe)
        }

    }










    override fun decrypt(inputStream: InputStream, outputStream: OutputStream, key: PrivateKey, algorithm: String) {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encrypt(inputStream: InputStream, outputStream: OutputStream, key: PublicKey, algorithm: String) {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}