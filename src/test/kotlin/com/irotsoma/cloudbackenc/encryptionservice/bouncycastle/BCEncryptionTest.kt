/*
 * Copyright (C) 2016-2017  Irotsoma, LLC
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
package com.irotsoma.cloudbackenc.encryptionservice.bouncycastle

import com.irotsoma.cloudbackenc.common.encryptionserviceinterface.*
import org.bouncycastle.util.encoders.Hex
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.spec.IvParameterSpec

class BCEncryptionTests {

    val secureRandom: SecureRandom = SecureRandom()
    val testString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ /0123456789abcdefghijklmnopqrstuvwxyz £©µÀÆÖÞßéöÿ–—‘“”„†•…‰™œŠŸž€ ΑΒΓΔΩαβγδω АБВГДабвгд∀∂∈ℝ∧∪≡∞ ↑↗↨↻⇣ ┐┼╔╘░►☺♀ ﬁ�⑀₂ἠḂӥẄɐː⍎אԱა"
    val testPassword = "ThisIsMyPassword"
    val testSalt = "randomvalue"

    @Test
    fun TestEncryptDecryptFileWithSymmetricKey(){

        val testFilePath = javaClass.classLoader.getResource("TestEncryptFile.dat").path
        val expectedHash = hashFile(File(testFilePath))
        val encryptionFactory = BouncyCastleServiceFactory()

        RunFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionServiceSymmetricKeyAlgorithms.AES, 128, 16, EncryptionServiceSymmetricEncryptionAlgorithms.AES)
        RunFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionServiceSymmetricKeyAlgorithms.AES, 128, 16, EncryptionServiceSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding)
        RunFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionServiceSymmetricKeyAlgorithms.AES, 128, -1, EncryptionServiceSymmetricEncryptionAlgorithms.AES_ECB_WithCTS)
        RunFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionServiceSymmetricKeyAlgorithms.SKIPJACK, 128, -1, EncryptionServiceSymmetricEncryptionAlgorithms.SKIPJACK_ECB_PKCS7Padding)
        RunFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionServiceSymmetricKeyAlgorithms.Twofish, 128, 16, EncryptionServiceSymmetricEncryptionAlgorithms.Twofish_CBC_PKCS5Padding)
        RunFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionServiceSymmetricKeyAlgorithms.Blowfish, 128, 8, EncryptionServiceSymmetricEncryptionAlgorithms.Blowfish_CBC_PKCS5Padding)

    }

    fun RunFileTestWithSymmetricKey(testFilePath: String, expectedHash: String, encryptionFactory:BouncyCastleServiceFactory, keyAlgorithm: EncryptionServiceSymmetricKeyAlgorithms, keySize:Int, ivBlockSize: Int, encryptionAlgorithm: EncryptionServiceSymmetricEncryptionAlgorithms ){
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
        encryptionFactory.encryptionServiceFileService.decrypt(encryptedFile.inputStream(), decryptedFile.outputStream(), testKey, encryptionAlgorithm, ivParameterSpec, secureRandom)
        val hashString = hashFile(decryptedFile)
        encryptedFile.deleteOnExit()
        decryptedFile.deleteOnExit()
        assert(hashString == expectedHash)
    }

    @Test
    fun TestEncryptDecryptDataWithAsymmetricKey(){
        val encryptionFactory = BouncyCastleServiceFactory()
        RunTestWithAsymmetricKey(encryptionFactory,EncryptionServiceAsymmetricKeyAlgorithms.RSA,1024,EncryptionServiceAsymmetricEncryptionAlgorithms.RSA)
        RunTestWithAsymmetricKey(encryptionFactory,EncryptionServiceAsymmetricKeyAlgorithms.RSA,4096,EncryptionServiceAsymmetricEncryptionAlgorithms.RSA_ECB_OAEPWithSHA1AndMGF1Padding)
        RunTestWithAsymmetricKey(encryptionFactory,EncryptionServiceAsymmetricKeyAlgorithms.RSA,2048,EncryptionServiceAsymmetricEncryptionAlgorithms.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
    }

    fun RunTestWithAsymmetricKey(encryptionFactory:BouncyCastleServiceFactory, keyAlgorithm: EncryptionServiceAsymmetricKeyAlgorithms, keySize:Int, encryptionAlgorithm: EncryptionServiceAsymmetricEncryptionAlgorithms){
        val testKeys = BouncyCastleServiceFactory().encryptionServiceKeyService.generateAsymmetricKeys(keyAlgorithm, keySize, secureRandom)
        val testBytes = ByteArray(encryptionAlgorithm.maxDataSize()[keySize]!!)
        secureRandom.nextBytes(testBytes)
        val encryptedDataStream = ByteArrayOutputStream()
        encryptionFactory.encryptionServiceFileService.encrypt(testBytes.inputStream(), encryptedDataStream, testKeys!!.public, encryptionAlgorithm, secureRandom)
        val encryptedData = encryptedDataStream.toByteArray()
        val decryptedDataStream = ByteArrayOutputStream()
        encryptionFactory.encryptionServiceFileService.decrypt(encryptedData.inputStream(), decryptedDataStream, testKeys.private, encryptionAlgorithm, secureRandom)
        assert(Arrays.equals(testBytes, decryptedDataStream.toByteArray()))
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
        val testKey = BouncyCastleServiceFactory().encryptionServiceKeyService.generateSymmetricKey(EncryptionServiceSymmetricKeyAlgorithms.AES, 128, secureRandom)
        val encryptionFactory = BouncyCastleServiceFactory()
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val ivParameterSpec = IvParameterSpec(byteArray)
        val encryptedString = encryptionFactory.encryptionServiceStringService.encrypt(testString,testKey!!,EncryptionServiceSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedString = encryptionFactory.encryptionServiceStringService.decrypt(encryptedString,testKey!!,EncryptionServiceSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        assert(testString == decryptedString)
    }

    @Test
    fun TestEncryptDecryptStringWithPasswordBasedKey(){
        val encryptionFactory = BouncyCastleServiceFactory()
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val ivParameterSpec = IvParameterSpec(byteArray)
        val pbKey = encryptionFactory.encryptionServiceKeyService.generatePasswordBasedKey(testPassword,testSalt.toByteArray(Charsets.UTF_8),EncryptionServicePBKDFAlgorithms.PBKDF2WithHmacSHA1,128, 128000)
        val encryptedString = encryptionFactory.encryptionServiceStringService.encrypt(testString,pbKey!!,EncryptionServiceSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedString = encryptionFactory.encryptionServiceStringService.decrypt(encryptedString,pbKey!!,EncryptionServiceSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        assert(testString == decryptedString)
    }

}