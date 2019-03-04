/*
 * Copyright (C) 2016-2019  Irotsoma, LLC
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

import com.irotsoma.cloudbackenc.common.Utilities.hashFile
import com.irotsoma.cloudbackenc.common.encryption.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.security.SecureRandom
import java.util.*
import javax.crypto.spec.IvParameterSpec

class BCEncryptionTests {

    private val secureRandom: SecureRandom = SecureRandom()
    private val testString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ /0123456789abcdefghijklmnopqrstuvwxyz £©µÀÆÖÞßéöÿ–—‘“”„†•…‰™œŠŸž€ ΑΒΓΔΩαβγδω АБВГДабвгд∀∂∈ℝ∧∪≡∞ ↑↗↨↻⇣ ┐┼╔╘░►☺♀ ﬁ�⑀₂ἠḂӥẄɐː⍎אԱა"
    private val testPassword = "ThisIsMyPassword"
    private val testSalt = "randomvalue"

    @Test
    fun testEncryptDecryptFileWithSymmetricKey(){

        val testFilePath = javaClass.classLoader.getResource("TestEncryptFile.dat").path
        val expectedHash = hashFile(File(testFilePath))
        val encryptionFactory = BouncyCastleServiceFactory()

        runFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionSymmetricKeyAlgorithms.AES, 128, 16, EncryptionSymmetricEncryptionAlgorithms.AES)
        runFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionSymmetricKeyAlgorithms.AES, 128, 16, EncryptionSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding)
        runFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionSymmetricKeyAlgorithms.AES, 128, -1, EncryptionSymmetricEncryptionAlgorithms.AES_ECB_WithCTS)
        runFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionSymmetricKeyAlgorithms.SKIPJACK, 128, -1, EncryptionSymmetricEncryptionAlgorithms.SKIPJACK_ECB_PKCS7Padding)
        runFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionSymmetricKeyAlgorithms.Twofish, 128, 16, EncryptionSymmetricEncryptionAlgorithms.Twofish_CBC_PKCS5Padding)
        runFileTestWithSymmetricKey(testFilePath, expectedHash, encryptionFactory, EncryptionSymmetricKeyAlgorithms.Blowfish, 128, 8, EncryptionSymmetricEncryptionAlgorithms.Blowfish_CBC_PKCS5Padding)

    }

    private fun runFileTestWithSymmetricKey(testFilePath: String, expectedHash: String, encryptionFactory: BouncyCastleServiceFactory, keyAlgorithm: EncryptionSymmetricKeyAlgorithms, keySize:Int, ivBlockSize: Int, encryptionAlgorithm: EncryptionSymmetricEncryptionAlgorithms ){
        val testKey = BouncyCastleServiceFactory().encryptionKeyService.generateSymmetricKey(keyAlgorithm, keySize, secureRandom)
        val encryptedFile = File.createTempFile("encryptedfile_",".dat")
        var ivParameterSpec: IvParameterSpec? = null
        if (ivBlockSize != -1){
            val byteArray = ByteArray(ivBlockSize)
            secureRandom.nextBytes(byteArray)
            ivParameterSpec =  IvParameterSpec(byteArray)
        }
        encryptionFactory.encryptionFileService.encrypt(FileInputStream(testFilePath), encryptedFile.outputStream(), testKey!!, encryptionAlgorithm, ivParameterSpec, secureRandom)
        val decryptedFile = File.createTempFile("decryptedfile_",".dat")
        encryptionFactory.encryptionFileService.decrypt(encryptedFile.inputStream(), decryptedFile.outputStream(), testKey, encryptionAlgorithm, ivParameterSpec, secureRandom)
        val hashString = hashFile(decryptedFile)
        encryptedFile.deleteOnExit()
        decryptedFile.deleteOnExit()
        assert(hashString == expectedHash)
    }

    @Test
    fun testEncryptDecryptDataWithAsymmetricKey(){
        val encryptionFactory = BouncyCastleServiceFactory()
        runTestWithAsymmetricKey(encryptionFactory,EncryptionAsymmetricKeyAlgorithms.RSA,1024,EncryptionAsymmetricEncryptionAlgorithms.RSA)
        runTestWithAsymmetricKey(encryptionFactory,EncryptionAsymmetricKeyAlgorithms.RSA,4096,EncryptionAsymmetricEncryptionAlgorithms.RSA_ECB_OAEPWithSHA1AndMGF1Padding)
        runTestWithAsymmetricKey(encryptionFactory,EncryptionAsymmetricKeyAlgorithms.RSA,2048,EncryptionAsymmetricEncryptionAlgorithms.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
    }

    private fun runTestWithAsymmetricKey(encryptionFactory: BouncyCastleServiceFactory, keyAlgorithm: EncryptionAsymmetricKeyAlgorithms, keySize:Int, encryptionAlgorithm: EncryptionAsymmetricEncryptionAlgorithms){
        val testKeys = BouncyCastleServiceFactory().encryptionKeyService.generateAsymmetricKeys(keyAlgorithm, keySize, secureRandom)
        val testBytes = ByteArray(encryptionAlgorithm.maxDataSize()[keySize]!!)
        secureRandom.nextBytes(testBytes)
        val encryptedDataStream = ByteArrayOutputStream()
        encryptionFactory.encryptionFileService.encrypt(testBytes.inputStream(), encryptedDataStream, testKeys!!.public, encryptionAlgorithm, secureRandom)
        val encryptedData = encryptedDataStream.toByteArray()
        val decryptedDataStream = ByteArrayOutputStream()
        encryptionFactory.encryptionFileService.decrypt(encryptedData.inputStream(), decryptedDataStream, testKeys.private, encryptionAlgorithm, secureRandom)
        assert(Arrays.equals(testBytes, decryptedDataStream.toByteArray()))
    }


    @Test
    fun testEncryptDecryptStringWithSymmetricKey(){
        val testKey = BouncyCastleServiceFactory().encryptionKeyService.generateSymmetricKey(EncryptionSymmetricKeyAlgorithms.AES, 128, secureRandom)
        val encryptionFactory = BouncyCastleServiceFactory()
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val ivParameterSpec = IvParameterSpec(byteArray)
        val encryptedString = encryptionFactory.encryptionStringService.encrypt(testString,testKey!!,EncryptionSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedString = encryptionFactory.encryptionStringService.decrypt(encryptedString,testKey!!,EncryptionSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        assert(testString == decryptedString)
    }

    @Test
    fun testEncryptDecryptStringWithPasswordBasedKey(){
        val encryptionFactory = BouncyCastleServiceFactory()
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val ivParameterSpec = IvParameterSpec(byteArray)
        val pbKey = encryptionFactory.encryptionKeyService.generatePasswordBasedKey(testPassword,testSalt.toByteArray(Charsets.UTF_8),EncryptionPBKDFAlgorithms.PBKDF2WithHmacSHA1,128, 128000)
        val encryptedString = encryptionFactory.encryptionStringService.encrypt(testString,pbKey!!,EncryptionSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        val decryptedString = encryptionFactory.encryptionStringService.decrypt(encryptedString,pbKey!!,EncryptionSymmetricEncryptionAlgorithms.AES_CBC_PKCS5Padding, ivParameterSpec, secureRandom)
        assert(testString == decryptedString)
    }

}