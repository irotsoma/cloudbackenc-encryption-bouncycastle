package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceEncryptionAlgorithms
import com.irotsoma.cloudbackenc.encryptionservice.EncryptionServiceKeyAlgorithms
import org.bouncycastle.util.encoders.Hex
import org.junit.Test
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec

/**
 * Created by irotsoma on 8/25/2016.
 */
class BCEncryptionTest {

    val secureRandom: SecureRandom = SecureRandom.getInstanceStrong()
    val testKey = BouncyCastleServiceFactory().encryptionServiceKeyService.generateSymmetricKey(EncryptionServiceKeyAlgorithms.AES,128, secureRandom)
    val expectedHash = "c766cb139cfa7e9048e6a4d20aecdd875fb4fae7"


    @Test
    fun TestGenerateKey(){
        assert(testKey != null)
    }
    //TODO: test with some other algorithms.
    @Test
    fun TestEncryptDecryptFile(){
        val messageDigest = MessageDigest.getInstance("SHA1")
        val testFilePath = javaClass.classLoader.getResource("TestEncryptFile.dat").path
        val encryptedFile = File.createTempFile("encryptedfile_",".dat")
        val encryptionFactory = BouncyCastleServiceFactory()
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val ivParameterSpec = IvParameterSpec(byteArray)
        encryptionFactory.encryptionServiceFileService.encrypt(FileInputStream(testFilePath), encryptedFile.outputStream(), testKey!!, EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedFile = File.createTempFile("decryptedfile_",".dat")
        encryptionFactory.encryptionServiceFileService.decrypt(encryptedFile.inputStream(), decryptedFile.outputStream(), testKey!!, EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedFileInputStream = decryptedFile.inputStream()
        val dataBytes = ByteArray(1024)
        var readBytes = decryptedFileInputStream.read(dataBytes)
        while (readBytes > -1){
            messageDigest.update(dataBytes,0,readBytes)
            readBytes = decryptedFileInputStream.read(dataBytes)
        }
        val outputBytes: ByteArray = messageDigest.digest()

        val hashString = Hex.toHexString(outputBytes)
        //encryptedFile.deleteOnExit()
        //decryptedFile.deleteOnExit()
        assert(hashString == expectedHash)
    }

}