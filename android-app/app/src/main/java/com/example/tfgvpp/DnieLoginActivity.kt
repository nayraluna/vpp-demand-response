package com.example.tfgvpp

import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.core.widget.doAfterTextChanged
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.tfgvpp.data.security.DnieAuth
import de.tsenger.androsmex.iso7816.command.exception.AuthenticationModeLockedException
import es.gob.fnmt.dniedroid.gui.PasswordUI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DnieLoginActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    companion object {
        /** ActivityResult extra: holder's full name as read from the card. */
        const val EXTRA_HOLDER = "com.example.tfgvpp.dnie.HOLDER"

        /** ActivityResult extra: DNI as read from the card. */
        const val EXTRA_DNI = "com.example.tfgvpp.dnie.DNI"
    }

    private lateinit var canInput: EditText
    private lateinit var canCells: List<TextView>
    private lateinit var status: TextView
    private lateinit var log: TextView
    private lateinit var btnUseIdentity: Button

    private lateinit var dnieAuth: DnieAuth
    private var nfcAdapter: NfcAdapter? = null

    // Kept after a successful login so "use this identity" can hand it to the
    // registration step (the CSR's CN becomes the holder's DNI).
    private var lastResult: DnieAuth.Result? = null

    // onTagDiscovered runs on a binder thread, so the CAN is mirrored here instead
    // of being read off the EditText from a background thread.
    @Volatile private var can: String = ""
    @Volatile private var busy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_dnie_login)

        canInput = findViewById(R.id.canInput)
        val cellRow = findViewById<android.widget.LinearLayout>(R.id.canCells)
        canCells = (0 until cellRow.childCount).map { cellRow.getChildAt(it) as TextView }
        status = findViewById(R.id.status)
        log = findViewById(R.id.log)
        btnUseIdentity = findViewById(R.id.btnUseIdentity)
        btnUseIdentity.setOnClickListener {
            lastResult?.let { r ->
                setResult(RESULT_OK, Intent()
                    .putExtra(EXTRA_HOLDER, r.holderName)
                    .putExtra(EXTRA_DNI, r.dni))
                finish()
            }
        }

        // The invisible EditText owns the input; the six cells just render it.
        canInput.doAfterTextChanged { text ->
            val digits = text?.toString()?.trim().orEmpty()
            can = digits
            canCells.forEachIndexed { i, cell ->
                cell.text = digits.getOrNull(i)?.toString() ?: ""
            }
        }

        dnieAuth = DnieAuth(resources.openRawResource(R.raw.ac_raiz_dnie2))

        // The SDK shows its own PIN dialog; it needs a context to attach to.
        PasswordUI.setAppContext(this)
        PasswordUI.setPasswordDialog(null) // null = the SDK's default dialog

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            setStatus("This device has no NFC: DNIe sign-in is not available here.")
        }
    }

    override fun onResume() {
        super.onResume()
        val adapter = nfcAdapter ?: return

        // Having NFC hardware is not enough: with NFC switched OFF in system
        // settings, reader mode silently never fires onTagDiscovered -- the
        // classic "I type the CAN and nothing happens". Detect it and offer
        // the settings screen; coming back re-runs this check.
        if (!adapter.isEnabled) {
            setStatus("NFC is OFF — tap here to open settings and enable it.")
            status.setOnClickListener { startActivity(Intent(Settings.ACTION_NFC_SETTINGS)) }
            return
        }
        status.setOnClickListener(null)
        setStatus(getString(R.string.dnie_status_initial))

        adapter.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
                NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B,
            Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000) },
        )
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    /** Called by the NFC stack on a binder thread — never on the main thread. */
    override fun onTagDiscovered(tag: Tag) {
        val can = this.can
        if (can.length != 6) {
            setStatus("Enter the 6-digit CAN first, then tap the card again.")
            return
        }
        if (busy) return
        busy = true

        lifecycleScope.launch {
            setStatus("Reading the DNIe… keep the card still")
            try {
                // Card I/O and the blocking PIN dialog must not run on the main thread.
                // The certificate block is shown as soon as it is read (CAN only);
                // the PIN is only needed afterwards, for the proof of possession.
                val r = withContext(Dispatchers.IO) {
                    dnieAuth.authenticate(tag, can) { info -> showCardInfo(info) }
                }
                showPossession(r)
            } catch (e: AuthenticationModeLockedException) {
                setStatus("DNIe LOCKED")
                append("PIN attempt limit reached: unlock the card at a DNIe update point.")
            } catch (e: Exception) {
                // "Tag ... is out of date" = the card lost RF contact mid-operation
                // (typically while typing the PIN); the stale handle is unusable.
                // No PIN attempt is consumed: the PIN never reached the card.
                val tagLost = generateSequence<Throwable>(e) { it.cause }.any {
                    it is android.nfc.TagLostException ||
                        it.message?.contains("out of date") == true
                }
                if (tagLost) {
                    setStatus("The card lost contact with the antenna")
                    append("Lay the card flat, phone on top, and keep both still.")
                    append("No PIN attempt was used. Tap the card again.")
                } else {
                    setStatus("Possession proof not completed")
                    append("ERROR: ${e.javaClass.simpleName}: ${e.message}")
                }
            } finally {
                busy = false
            }
        }
    }

    /** First block: everything knowable WITHOUT the PIN (read via CAN/PACE). */
    private fun showCardInfo(i: DnieAuth.CardInfo) {
        setStatus("Certificate read — enter the PIN to prove possession")
        append("Holder:  ${i.holderName}")
        append("DNI:     ${i.dni}")
        append("  genuine (chains to AC RAIZ DNIE 2): ${mark(i.chainsToDnieRoot)}")
        append("  not expired: ${mark(i.notExpired)}")
    }

    /** Second block: what required the PIN (signature with the card's private key). */
    private fun showPossession(r: DnieAuth.Result) {
        setStatus(if (r.allPassed) "SIGNED IN — ${r.holderName}" else "SIGN-IN FAILED")
        append("  possession proof (signature): ${mark(r.proofOfPossession)}")
        append("  tampered nonce rejected:      ${mark(r.tamperRejected)}")
        r.diagnostic?.lines()?.forEach { append(it) }
        if (r.allPassed) {
            lastResult = r
            runOnUiThread { btnUseIdentity.visibility = View.VISIBLE }
        }
    }

    private fun mark(b: Boolean) = if (b) "PASS" else "FAIL"

    private fun setStatus(s: String) = runOnUiThread { status.text = s }
    private fun append(s: String) = runOnUiThread { log.append("$s\n") }
}
