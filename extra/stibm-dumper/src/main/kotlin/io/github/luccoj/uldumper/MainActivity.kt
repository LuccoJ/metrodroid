package io.github.luccoj.uldumper

import android.app.Activity
import android.content.ContentValues
import android.content.Context
import android.graphics.Typeface
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.NfcA
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.text.InputType
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Reads any MIFARE Ultralight (EV1) ticket held to the phone while this screen is open and saves a
 * Metrodroid-compatible JSON dump to Download/STIBM-dumps/, plus the extra chip data Metrodroid
 * doesn't read (one-way counters, tearing flags, originality signature).
 *
 * Read-only: this app never writes to the ticket.
 */
class MainActivity : Activity(), NfcAdapter.ReaderCallback {
    private var nfc: NfcAdapter? = null
    private lateinit var log: TextView
    private lateinit var note: EditText
    private lateinit var scroll: ScrollView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        nfc = NfcAdapter.getDefaultAdapter(this)

        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        root.addView(TextView(this).apply {
            text = "Hold a ticket to the phone. Each read is saved to Download/STIBM-dumps/.\n" +
                    "Optional note for the NEXT read (e.g. \"before validation\", \"after tap, Cadorna\"):"
        })
        note = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            hint = "note (cleared after each read)"
        }
        root.addView(note)
        log = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setTextIsSelectable(true)
        }
        scroll = ScrollView(this).apply { addView(log) }
        root.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)

        when {
            nfc == null -> append("This phone has no NFC.")
            nfc?.isEnabled != true -> append("NFC is turned off: enable it in Settings.")
            else -> append("Ready.")
        }
    }

    override fun onResume() {
        super.onResume()
        nfc?.enableReaderMode(this, this,
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null)
    }

    override fun onPause() {
        super.onPause()
        nfc?.disableReaderMode(this)
    }

    private fun append(s: String) = runOnUiThread {
        log.append(s + "\n")
        scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    // ---- Reading -------------------------------------------------------------------------------

    private class Dump(
            val uid: ByteArray,
            val version: ByteArray?,
            val pages: List<ByteArray>,
            val counters: List<Int?>,
            val tearing: List<Int?>,
            val signature: ByteArray?,
            val errors: List<String>)

    /**
     * Sends a command; returns null on NAK or I/O error, after re-selecting the tag.
     * A NAK is a single 4-bit reply, so replies shorter than [minLen] bytes count as one.
     */
    private fun cmd(a: NfcA, vararg bytes: Int, minLen: Int = 2): ByteArray? {
        try {
            val r = a.transceive(ByteArray(bytes.size) { bytes[it].toByte() })
            val isNak = r != null && r.size == 1 && (r[0].toInt() and 0xf0) == 0
            if (r != null && r.size >= minLen && !isNak) return r
        } catch (_: IOException) {
        }
        // A NAK halts the tag: reconnect so that later commands still work.
        try { a.close() } catch (_: IOException) {}
        try { a.connect() } catch (_: IOException) {}
        return null
    }

    private fun pageCountFor(version: ByteArray?): Int? = when (version?.getOrNull(6)?.toInt()) {
        0x0b -> 20   // MF0UL11
        0x0e -> 41   // MF0UL21
        0x0f -> 45   // NTAG213
        0x11 -> 135  // NTAG215
        0x13 -> 231  // NTAG216
        else -> null
    }

    private fun modelFor(version: ByteArray?): String {
        if (version == null || version.size < 8) return ""
        val type = version[2].toInt()
        return when (version[6].toInt()) {
            0x0b -> if (type == 0x03) "EV1_MF0UL11" else ""
            0x0e -> if (type == 0x03) "EV1_MF0UL21" else ""
            0x0f -> if (type == 0x04) "NTAG213" else ""
            0x11 -> if (type == 0x04) "NTAG215" else ""
            0x13 -> if (type == 0x04) "NTAG216" else ""
            else -> ""
        }
    }

    private fun read(tag: Tag): Dump {
        val a = NfcA.get(tag) ?: throw IOException("not an ISO 14443-A tag")
        val errors = mutableListOf<String>()
        a.connect()
        try {
            a.timeout = 500
            val version = cmd(a, 0x60)
            if (version == null) errors += "GET_VERSION not supported (not an EV1?)"
            val count = pageCountFor(version) ?: 256

            val pages = mutableListOf<ByteArray>()
            var p = 0
            while (p < count) {
                val r = cmd(a, 0x30, p)
                if (r == null || r.size < 16) {
                    if (pageCountFor(version) != null) errors += "READ failed at page $p"
                    break
                }
                for (i in 0 until minOf(4, count - p)) pages += r.copyOfRange(i * 4, i * 4 + 4)
                p += 4
            }

            val isEv1 = modelFor(version).startsWith("EV1")
            val counters = (0..2).map { i ->
                if (!isEv1) null else cmd(a, 0x39, i)?.let {
                    (it[0].toInt() and 0xff) or ((it[1].toInt() and 0xff) shl 8) or ((it[2].toInt() and 0xff) shl 16)
                }
            }
            val tearing = (0..2).map { i -> if (!isEv1) null else cmd(a, 0x3e, i, minLen = 1)?.let { it[0].toInt() and 0xff } }
            val signature = cmd(a, 0x3c, 0x00)
            return Dump(tag.id, version, pages, counters, tearing, signature, errors)
        } finally {
            try { a.close() } catch (_: IOException) {}
        }
    }

    // ---- Saving --------------------------------------------------------------------------------

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    private fun toJson(d: Dump, now: Long, noteText: String): JSONObject {
        val tz = TimeZone.getDefault()
        val mfu = JSONObject()
                .put("cardModel", modelFor(d.version))
                .put("pages", JSONArray(d.pages.map { JSONObject().put("data", it.hex()) }))
        if (d.version != null) mfu.put("cardRawModel", JSONObject().put("versionCmd", d.version.hex()))
        val extra = JSONObject()
                .put("app", "UL Dumper 1.1")
                .put("localTime", SimpleDateFormat("yyyy-MM-dd HH:mm:ss zzz", Locale.ROOT).format(Date(now)))
                .put("note", noteText)
                .put("counters", JSONArray(d.counters.map { it ?: JSONObject.NULL }))
                .put("tearingFlags", JSONArray(d.tearing.map { it?.let { v -> "%02x".format(v) } ?: JSONObject.NULL }))
                .put("signature", d.signature?.hex() ?: JSONObject.NULL)
                .put("errors", JSONArray(d.errors))
        return JSONObject()
                .put("tagId", d.uid.hex())
                .put("scannedAt", JSONObject().put("timeInMillis", now).put("tz", tz.id))
                .put("mifareUltralight", mfu)
                .put("ulDumper", extra)
    }

    /** Saves to Download/STIBM-dumps/ and returns a human-readable location. */
    private fun save(name: String, text: String): String {
        val bytes = text.toByteArray()
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "application/json")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/STIBM-dumps")
            }
            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: throw IOException("could not create file in Downloads")
            contentResolver.openOutputStream(uri)!!.use { it.write(bytes) }
            return "Download/STIBM-dumps/$name"
        }
        val dir = File(getExternalFilesDir(null), "STIBM-dumps").apply { mkdirs() }
        File(dir, name).writeBytes(bytes)
        return File(dir, name).path
    }

    // ---- Diff against the previous read of the same ticket ---------------------------------------

    private fun ranges(idx: List<Int>): String {
        if (idx.isEmpty()) return "none"
        val out = mutableListOf<String>()
        var start = idx[0]
        var prev = idx[0]
        for (i in idx.drop(1) + listOf(Int.MIN_VALUE)) {
            if (i == prev + 1) { prev = i; continue }
            out += if (start == prev) "$start" else "$start-$prev"
            start = i; prev = i
        }
        return out.joinToString(", ")
    }

    private fun diff(d: Dump): String {
        val prefs = getSharedPreferences("last", Context.MODE_PRIVATE)
        val key = d.uid.hex()
        val pagesNow = d.pages.joinToString(",") { it.hex() }
        val countersNow = d.counters.joinToString(",") { it?.toString() ?: "-" }
        val before = prefs.getString("p_$key", null)
        val countersBefore = prefs.getString("c_$key", null)
        // Don't let an incomplete read (ticket moved away) become the reference for the next diff.
        if (d.errors.none { it.startsWith("READ failed") })
            prefs.edit().putString("p_$key", pagesNow).putString("c_$key", countersNow).apply()
        if (before == null) return "first read of this ticket"
        val a = before.split(","); val b = d.pages.map { it.hex() }
        val changed = (0 until maxOf(a.size, b.size)).filter { a.getOrNull(it) != b.getOrNull(it) }
        val counterNote = if (countersBefore != countersNow) "; counters $countersBefore -> $countersNow" else ""
        return "changed pages since last read: ${ranges(changed)}$counterNote"
    }

    // ---- Callback ------------------------------------------------------------------------------

    override fun onTagDiscovered(tag: Tag) {
        val now = System.currentTimeMillis()
        try {
            val d = read(tag)
            var noteText = ""
            val latch = java.util.concurrent.CountDownLatch(1)
            runOnUiThread { noteText = note.text.toString().trim(); note.setText(""); latch.countDown() }
            latch.await()
            val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(Date(now))
            val name = "${stamp}_${d.uid.hex()}.json"
            val where = save(name, toJson(d, now, noteText).toString(4))
            val time = SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(Date(now))
            append("\n[$time] ${d.uid.hex()} ${modelFor(d.version).ifEmpty { "unknown model" }}, " +
                    "${d.pages.size} pages" + (if (noteText.isNotEmpty()) " — \"$noteText\"" else ""))
            append("  counters: ${d.counters.joinToString(" ") { it?.toString() ?: "-" }}")
            append("  ${diff(d)}")
            d.errors.forEach { append("  warning: $it") }
            append("  saved: $where")
        } catch (e: Exception) {
            append("\nRead failed (${e.javaClass.simpleName}: ${e.message}). Hold the ticket still and retry.")
        }
    }
}
