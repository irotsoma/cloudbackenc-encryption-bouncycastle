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

package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.encryptionservice.EncryptionServiceEncryptionAlgorithms
import com.irotsoma.cloudbackenc.common.encryptionservice.EncryptionServiceKeyAlgorithms
import com.irotsoma.cloudbackenc.common.encryptionservice.EncryptionServicePBKDFAlgorithms
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
class BCEncryptionTests {

    val secureRandom: SecureRandom = SecureRandom.getInstanceStrong()
    val testString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ /0123456789abcdefghijklmnopqrstuvwxyz £©µÀÆÖÞßéöÿ–—‘“”„†•…‰™œŠŸž€ ΑΒΓΔΩαβγδω АБВГДабвгд∀∂∈ℝ∧∪≡∞ ↑↗↨↻⇣ ┐┼╔╘░►☺♀ ﬁ�⑀₂ἠḂӥẄɐː⍎אԱა"
    val testPassword = "ThisIsMyPassword"
    val testSalt = "randomvalue"

    //TODO: test with some other algorithms.
    @Test
    fun TestEncryptDecryptFileWithSymmetricKey(){

        val testFilePath = javaClass.classLoader.getResource("TestEncryptFile.dat").path
        val expectedHash = hashFile(File(testFilePath))
        val encryptionFactory = BouncyCastleServiceFactory()

        RunFileTestWithSymmetricKey(testFilePath,expectedHash,encryptionFactory,EncryptionServiceKeyAlgorithms.AES, 128, 16, EncryptionServiceEncryptionAlgorithms.AES)
        RunFileTestWithSymmetricKey(testFilePath,expectedHash,encryptionFactory,EncryptionServiceKeyAlgorithms.AES, 128, 16, EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding)
        RunFileTestWithSymmetricKey(testFilePath,expectedHash,encryptionFactory,EncryptionServiceKeyAlgorithms.AES, 128, -1, EncryptionServiceEncryptionAlgorithms.AES_ECB_WithCTS)
        RunFileTestWithSymmetricKey(testFilePath,expectedHash,encryptionFactory,EncryptionServiceKeyAlgorithms.SKIPJACK, 128, -1, EncryptionServiceEncryptionAlgorithms.SKIPJACK_ECB_PKCS7Padding)
        RunFileTestWithSymmetricKey(testFilePath,expectedHash,encryptionFactory,EncryptionServiceKeyAlgorithms.Twofish, 128, 16, EncryptionServiceEncryptionAlgorithms.Twofish_CBC_PKCS5Padding)
        RunFileTestWithSymmetricKey(testFilePath,expectedHash,encryptionFactory,EncryptionServiceKeyAlgorithms.Blowfish, 128, 8, EncryptionServiceEncryptionAlgorithms.Blowfish_CBC_PKCS5Padding)

    }

    fun RunFileTestWithSymmetricKey(testFilePath: String, expectedHash: String, encryptionFactory:BouncyCastleServiceFactory, keyAlgorithm: EncryptionServiceKeyAlgorithms, keySize:Int, ivBlockSize: Int, encryptionAlgorithm: EncryptionServiceEncryptionAlgorithms ){
        val testKey = BouncyCastleServiceFactory().encryptionServiceKeyService.generateSymmetricKey(keyAlgorithm, keySize, secureRandom)
        val encryptedFile = File.createTempFile("encryptedfile_",".dat")
        var ivParameterSpec: IvParameterSpec? = null
        if (ivBlockSize != -1){
            val byteArray = ByteArray(ivBlockSize)
            secureRandom.nextBytes(byteArray)
            ivParameterSpec =  IvParameterSpec(byteArray)
        }
        encryptionFactory.encryptionServiceFileService.encrypt(FileInputStream(testFilePath), encryptedFile.outputStream(), testKey!!, encryptionAlgorithm, ivParameterSpec, secureRandom)
        val decryptedFile = File.createTempFile("decryptedfile_",".dat")
        encryptionFactory.encryptionServiceFileService.decrypt(encryptedFile.inputStream(), decryptedFile.outputStream(), testKey!!, encryptionAlgorithm, ivParameterSpec, secureRandom)
        val hashString = hashFile(decryptedFile)
        encryptedFile.deleteOnExit()
        decryptedFile.deleteOnExit()
        assert(hashString == expectedHash)
    }

    fun hashFile(file: File): String{
        val messageDigest = MessageDigest.getInstance("SHA1")
        val decryptedFileInputStream = file.inputStream()
        val dataBytes = ByteArray(1024)
        var readBytes = decryptedFileInputStream.read(dataBytes)
        while (readBytes > -1){
            messageDigest.update(dataBytes,0,readBytes)
            readBytes = decryptedFileInputStream.read(dataBytes)
        }
        val outputBytes: ByteArray = messageDigest.digest()
        return Hex.toHexString(outputBytes)
    }

    @Test
    fun TestEncryptDecryptStringWithSymmetricKey(){
        val testKey = BouncyCastleServiceFactory().encryptionServiceKeyService.generateSymmetricKey(EncryptionServiceKeyAlgorithms.AES, 128, secureRandom)
        val encryptionFactory = BouncyCastleServiceFactory()
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val ivParameterSpec = IvParameterSpec(byteArray)
        val encryptedString = encryptionFactory.encryptionServiceStringService.encrypt(testString,testKey!!,EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedString = encryptionFactory.encryptionServiceStringService.decrypt(encryptedString,testKey!!,EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        assert(testString == decryptedString)
    }

    @Test
    fun TestEncryptDecryptStringWithPasswordBasedKey(){
        val encryptionFactory = BouncyCastleServiceFactory()
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val ivParameterSpec = IvParameterSpec(byteArray)
        val pbKey = encryptionFactory.encryptionServiceKeyService.generatePasswordBasedKey(testPassword,testSalt.toByteArray(Charsets.UTF_8),EncryptionServicePBKDFAlgorithms.PBKDF2WithHmacSHA1,128, 128000)
        val encryptedString = encryptionFactory.encryptionServiceStringService.encrypt(testString,pbKey!!,EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedString = encryptionFactory.encryptionServiceStringService.decrypt(encryptedString,pbKey!!,EncryptionServiceEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        assert(testString == decryptedString)
    }

}