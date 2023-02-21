package com.earr.koteciesapp

import android.os.Bundle
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val button = findViewById<Button>(R.id.btnAction)

        button.setOnClickListener{
            letsGo()
        }
    }

    private fun letsGo() {
        /*// Add BouncyCastle
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())

        // Key Pair Generation
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")

        keyPairGenerator.initialize(ECGenParameterSpec("secp521r1"))
        val keyPair = keyPairGenerator.generateKeyPair()*/

        /*Security.removeProvider("BC")

        Security.addProvider(BouncyCastleProvider())

        val privateKeyString = "MEAwEAYHKoZIzj0CAQYFK4EEAAEDLAAEA6txn7CCae0d9AiGj3Rk5m9XflTCB81oe1fKZi4F4oipSF2u79k8TD5J";

        val privateKeyBytes = Base64.decode(privateKeyString, Base64.DEFAULT)

        val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)

        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)

        val privateKey = keyFactory.generatePrivate(keySpec)
*/


        // ========= HELLO
        Security.removeProvider("BC")
        /*Security.addProvider(BouncyCastleProvider())
        val base64EncodedPrivateKey = "MFICAQEEFNfflqz2oOd9WpxuMZ9wJTFO1sjgoAcGBSuBBAABoS4DLAAEA6txn7CCae0d9AiGj3Rk5m9XflTCB81oe1fKZi4F4oipSF2u79k8TD5J"
        val decodedKey = Base64.decode(base64EncodedPrivateKey, Base64.DEFAULT)
        val keySpec = X509EncodedKeySpec(decodedKey)
        val kf = KeyFactory.getInstance("EC", BouncyCastleProvider().name)
        val privateKey = kf.generatePrivate(keySpec)*/

        Security.addProvider(BouncyCastleProvider())
        val privateKeyString =
            "MDllOTFkYjMxZTNiNTYwMzdkOTVlOGQxYmEyYjQ3NzhjN2M5MGNlODE4YWI0MDE4NWE2YTZiNTQ1MTRmOGM1Zg=="
        val kf = KeyFactory.getInstance("EC", BouncyCastleProvider().name)
        val keySpec = PKCS8EncodedKeySpec(privateKeyString.toByteArray())
        val privateKey = kf.generatePrivate(keySpec)

        print("Result... $privateKey")
        // ========= GOODBYE


        /*
        *
        * trying to create my private key from string
        *
        * */

        /*val ownPrivateKey = "MFICAQEEFNfflqz2oOd9WpxuMZ9wJTFO1sjgoAcGBSuBBAABoS4DLAAEA6txn7CCae0d9AiGj3Rk5m9XflTCB81oe1fKZi4F4oipSF2u79k8TD5J"
        val data = Base64.decode(ownPrivateKey.toByteArray(), Base64.DEFAULT)
        val spec = X509EncodedKeySpec(data)
        val fact = KeyFactory.getInstance("EC")
        // TODO: CRASH APP
        fact.generatePublic(spec)
        fact.generatePrivate(spec)*/

        /*
        *
        * trying to crete my private key from string
        *
        * */


        /*// Encryption
        val plaintext = "BLACKPINK in your area".toByteArray(StandardCharsets.UTF_8)
        val cipherEnc = Cipher.getInstance("ECIES")
        cipherEnc.init(
            Cipher.ENCRYPT_MODE,
            keyPair.public
        ) // In practice, the public key of the recipient side is used
        val ciphertext = cipherEnc.doFinal(plaintext)
        println("JUANITO *** ${String(ciphertext, StandardCharsets.UTF_8)}")

        // Decryption
        val cipherDec = Cipher.getInstance("ECIES")
        cipherDec.init(Cipher.DECRYPT_MODE, keyPair.private)
        val decrypted = cipherDec.doFinal(ciphertext)
        println("JUANITO --- ${String(decrypted, StandardCharsets.UTF_8)}")*/
    }
}
