package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import org.bouncycastle.util.encoders.Hex
import org.junit.Test
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * Created by irotsoma on 8/25/2016.
 */
class BCEncryptionTest {

    val testKey = BouncyCastleServiceFactory().encryptionServiceKeyService.generateSymmetricKey("AES",128)
    val expectedHash = "c766cb139cfa7e9048e6a4d20aecdd875fb4fae7"


    @Test
    fun TestGenerateKey(){
        assert(testKey != null)
    }
    //TODO: test with some other algorithms than AES.
    @Test
    fun TestEncryptDecryptFile(){
        val messageDigest = MessageDigest.getInstance("SHA1")
        val testFilePath = javaClass.classLoader.getResource("TestEncryptFile.dat").path
        val encryptedFile = File.createTempFile("encryptedfile",".dat")
        val encryptionFactory = BouncyCastleServiceFactory()
        encryptionFactory.encryptionServiceFileService.encrypt(FileInputStream(testFilePath), encryptedFile.outputStream(), testKey!!, "AES/CBC/PKCS5Padding")
        val decryptedFile = File.createTempFile("decryptedfile",".dat")
        encryptionFactory.encryptionServiceFileService.decrypt(encryptedFile.inputStream(), decryptedFile.outputStream(), testKey!!, "AES/CBC/PKCS5Padding")
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