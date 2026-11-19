/*
 * MilanUltralightTransitData.kt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package au.id.micolous.metrodroid.transit.milan

import au.id.micolous.metrodroid.card.ultralight.UltralightCard
import au.id.micolous.metrodroid.card.ultralight.UltralightCardTransitFactory
import au.id.micolous.metrodroid.multi.Parcelable
import au.id.micolous.metrodroid.multi.Parcelize
import au.id.micolous.metrodroid.transit.TransitData
import au.id.micolous.metrodroid.transit.TransitIdentity
import au.id.micolous.metrodroid.ui.HeaderListItem
import au.id.micolous.metrodroid.ui.ListItem
import au.id.micolous.metrodroid.ui.ListItemInterface
import au.id.micolous.metrodroid.util.ImmutableByteArray

/*
 * Milan (STIBM: ATM, Trenord, ...) disposable / reloadable paper tickets on MIFARE Ultralight EV1
 * (MF0UL21).
 *
 * EXPERIMENTAL. The field meanings are not decoded yet. This parser only recognises the
 * ticket and splits user memory into the regions seen in the sample dumps, so that changes
 * between scans (purchase, validation, transfer, expiry) are easy to spot.
 *
 * Layout observed so far (page numbers in decimal):
 *
 *   0-1    UID; printed on the ticket as "01-" + UID bytes reversed, in decimal
 *   4      86 08 00 00   constant on every sample: used for detection
 *   5      00 00 00 00
 *   6-9    16 bytes, random-looking, differs per ticket (authenticator / signature?)
 *   10-16  record slot 1 (5 pages of data + 2 zero pages); empty on a used-up ticket
 *   17-23  record slot 2; every record seen starts with 38 07 12 03 e5 d7 e1
 *   24-28  area A; data only on the used-up ticket
 *   29     flag A (0 or 1)
 *   30-34  area B; data on both loaded tickets, empty on the used-up one
 *   35     flag B (0 or 1)
 *
 * Two different tickets carried a byte-identical record, so records are not encrypted
 * with a per-card key.
 */

private const val NAME = "Milano STIBM (Ultralight)"

private const val HEADER_PAGE = 4
private const val HEADER_MAGIC = 0x86080000.toInt()

@Parcelize
data class MilanUltralightRegion(
        val name: String,
        val firstPage: Int,
        val data: ImmutableByteArray,
        val flag: Int?
) : Parcelable {
    val isEmpty: Boolean get() = data.isAllZero()

    val lastPage: Int get() = firstPage + data.size / 4 - 1

    /** Page-by-page hex, so values can be compared directly with the raw dump. */
    val pagesHex: String
        get() = (0 until data.size / 4).joinToString(" ") { data.sliceOffLen(it * 4, 4).toHexString() }

    fun listItems(): List<ListItemInterface> {
        val title = "$name (pages $firstPage–$lastPage)"
        val items = mutableListOf<ListItemInterface>(
                ListItem(title, if (isEmpty) "empty" else pagesHex))
        if (flag != null)
            items += ListItem("$name flag", flag.toString())
        return items
    }
}

@Parcelize
data class MilanUltralightTransitData(
        val authenticator: ImmutableByteArray,
        val regions: List<MilanUltralightRegion>,
        private val serial: Long
) : TransitData() {
    /** Matches the number printed on the ticket (after its "01-" prefix). */
    override val serialNumber: String get() = serial.toString()

    override val cardName get() = NAME

    override val warning: String
        get() = "Experimental: the Milan ticket format is not decoded yet. " +
                "Raw regions are shown to help reverse-engineer it."

    val recordSlots: List<MilanUltralightRegion>
        get() = regions.filter { it.name.startsWith("Record") }

    override val info: List<ListItemInterface>
        get() = listOf(
                HeaderListItem("Records"),
                ListItem("Non-empty record slots",
                        "${recordSlots.count { !it.isEmpty }} of ${recordSlots.size}")
        ) + recordSlots.flatMap { it.listItems() } +
                listOf(HeaderListItem("Other areas")) +
                regions.filter { it !in recordSlots }.flatMap { it.listItems() } +
                listOf(ListItem("Authenticator? (pages 6–9)", authenticator.toHexString()))

    companion object {
        internal fun parse(card: UltralightCard): MilanUltralightTransitData {
            fun flag(page: Int) = card.getPage(page).data.byteArrayToInt()
            return MilanUltralightTransitData(
                    serial = getSerial(card),
                    authenticator = card.readPages(6, 4),
                    regions = listOf(
                            MilanUltralightRegion("Record slot 1", 10, card.readPages(10, 7), null),
                            MilanUltralightRegion("Record slot 2", 17, card.readPages(17, 7), null),
                            MilanUltralightRegion("Area A", 24, card.readPages(24, 5), flag(29)),
                            MilanUltralightRegion("Area B", 30, card.readPages(30, 5), flag(35))
                    )
            )
        }
    }
}

/** The 7-byte UID in reverse byte order, as decimal: this is what is printed on the ticket. */
private fun getSerial(card: UltralightCard) =
        (card.getPage(0).data.sliceOffLen(0, 3) + card.getPage(1).data).byteArrayToLongReversed()

object MilanUltralightTransitFactory : UltralightCardTransitFactory {
    override fun check(card: UltralightCard): Boolean {
        if (card.pages.size < 36)
            return false
        return card.getPage(HEADER_PAGE).data.byteArrayToInt() == HEADER_MAGIC &&
                card.getPage(HEADER_PAGE + 1).data.isAllZero()
    }

    override fun parseTransitData(card: UltralightCard) = MilanUltralightTransitData.parse(card)

    override fun parseTransitIdentity(card: UltralightCard) = TransitIdentity(NAME, getSerial(card).toString())
}
