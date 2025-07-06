package org.passkey

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.client.BasicWebAuthnClient
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import java.nio.charset.StandardCharsets
import kotlin.random.Random

class MainActivity : AppCompatActivity() {

    private lateinit var yubiKitManager: YubiKitManager
    private lateinit var rawId: String
    private lateinit var infoView: TextView

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        infoView = TextView(this).apply {
            text = "Insert or tap your YubiKey to register a passkey..."
            textSize = 16f
            setPadding(32, 300, 32, 32)
        }
        setContentView(infoView)

        yubiKitManager = YubiKitManager(this)

        try {
            yubiKitManager.startNfcDiscovery(
                NfcConfiguration(), this
            ) { device: NfcYubiKeyDevice ->
                runOnUiThread {
                    Toast.makeText(this, "YubiKey detected via NFC", Toast.LENGTH_SHORT).show()
                }

                device.requestConnection(SmartCardConnection::class.java) { result ->
                    try {
                        val connection = result.value  // May throw IOException
                        registerWithYubiKey(connection)
                    } catch (e: Exception) {
                        e.printStackTrace()
                        runOnUiThread {
                            Toast.makeText(
                                this, "Connection failed: ${e.message}", Toast.LENGTH_LONG
                            ).show()
                        }
                    }
                }

                /*
                device.requestConnection(SmartCardConnection::class.java) { result ->
                    try {
                        val connection = result.value
                        authenticateWithYubiKey(connection)
                    } catch (e: Exception) {
                        e.printStackTrace()
                        runOnUiThread {
                            Toast.makeText(this, "Connection failed: ${e.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }
                */
            }
        } catch (e: Exception) {
            e.printStackTrace()
            runOnUiThread {
                Toast.makeText(this, "NFC setup failed: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }


    }


    private fun registerWithYubiKey(connection: SmartCardConnection) {
        try {
            val session = Ctap2Session(connection)
            val client = BasicWebAuthnClient(session)

            val origin = "https://example.com"
            val challenge = ByteArray(32).apply { Random.nextBytes(this) }
            val challengeB64 = Base64.encodeToString(
                challenge, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )

            val createJson = """
                {
                        "rp": { "name": "Example RP", "id": "example.com" },
                        "user": {
                            "id": "${
                Base64.encodeToString(
                    "user123".toByteArray(), Base64.NO_WRAP
                )
            }",
                            "name": "user@example.com",
                            "displayName": "Example User"
                        },
                        "challenge": "$challengeB64",
                        "pubKeyCredParams": [
                            { "type": "public-key", "alg": -7 }
                        ],
                        
                        "authenticatorSelection": {
                            "residentKey": "required",
                            "userVerification": "required"
                        },
                        "extensions": {"prf": {}, "largeBlob": {}},
                        "timeout": 60000,
                        "attestation": "none"
                }
            """.trimIndent()

            val optionsJson = JSONObject(createJson)
            val options = PublicKeyCredentialCreationOptions.fromMap(optionsJson.toMap())
            val clientData = buildClientData("webauthn.create", origin, challengeB64)

            val credential: PublicKeyCredential = client.makeCredential(
                clientData, options, URL(origin).host, "1234".toCharArray(), null, null
            )

            rawId = JSONObject(credential.toMap()).getString("rawId")
            val resultJson = JSONObject(credential.toMap()).toString(2)
            runOnUiThread {
                infoView.text = "Passkey created:\n\n$resultJson"
            }
            Log.i("Passkey", "Passkey created: $resultJson")


        } catch (e: Exception) {
            e.printStackTrace()
            runOnUiThread {
                Toast.makeText(
                    this, "Passkey registration failed:\n${e.message}", Toast.LENGTH_LONG
                ).show()
            }
        }
    }


    private fun authenticateWithYubiKey(connection: SmartCardConnection) {
        try {
            val session = Ctap2Session(connection)
            val client = BasicWebAuthnClient(session)

            val origin = "https://example.com"
            val challenge = ByteArray(32).apply { Random.nextBytes(this) }
            val challengeB64 = Base64.encodeToString(
                challenge, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )

            //"largeBlob": {"write": "LARGE_BLOB "}
            val requestJson = """
                {
                  "challenge": "$challengeB64",
                  "timeout": 60000,
                  "rpId": "example.com",
                  "userVerification": "required",
                  "extensions": {
                  "prf": {"eval": {"first": "SEED"}},
                  "largeBlob": {"read": true}
                  }
                }
        """.trimIndent()

            //Log.i("Passkey", "Passkey Login Request: $requestJson")
            val optionsJson = JSONObject(requestJson)
            val options = PublicKeyCredentialRequestOptions.fromMap(optionsJson.toMap())
            val clientData = buildClientData("webauthn.get", origin, challengeB64)

            val credential: PublicKeyCredential = client.getAssertion(
                clientData, options, URL(origin).host, "1234".toCharArray(), null
            )

            val resultJson = JSONObject(credential.toMap()).toString(2)
            runOnUiThread {
                infoView.text = "Passkey Login Successful:\n\n$resultJson"
            }
            Log.i("Passkey", "Passkey authenticated: $resultJson")

        } catch (e: Exception) {
            e.printStackTrace()
            runOnUiThread {
                Toast.makeText(this, "Authentication failed:\n${e.message}", Toast.LENGTH_LONG)
                    .show()
            }
        }
    }


    private fun buildClientData(type: String, origin: String, challengeB64: String): ByteArray {
        val clientDataJson = """
            {
                "type": "$type",
                "challenge": "$challengeB64",
                "origin": "$origin"
            }
        """.trimIndent()
        return clientDataJson.toByteArray(StandardCharsets.UTF_8)
    }

    override fun onDestroy() {
        yubiKitManager.stopNfcDiscovery(this)
        super.onDestroy()
    }

    private fun JSONObject.toMap(): Map<String, Any?> {
        return keys().asSequence().associateWith {
            when (val value = this[it]) {
                is JSONObject -> value.toMap()
                is JSONArray -> value.toList()
                JSONObject.NULL -> null
                else -> value
            }
        }
    }

    private fun JSONArray.toList(): List<Any?> {
        val list = mutableListOf<Any?>()
        for (i in 0 until length()) {
            val value = get(i)
            list.add(
                when (value) {
                    is JSONObject -> value.toMap()
                    is JSONArray -> value.toList()
                    JSONObject.NULL -> null
                    else -> value
                }
            )
        }
        return list
    }
}
