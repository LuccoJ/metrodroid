/*
 * MilanUltralightTest.kt
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

package au.id.micolous.metrodroid.test

import au.id.micolous.metrodroid.serializers.JsonKotlinFormat
import au.id.micolous.metrodroid.transit.milan.MilanUltralightTransitData
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class MilanUltralightTest : BaseInstrumentedTest() {
    private fun load(name: String): MilanUltralightTransitData {
        val card = JsonKotlinFormat.readCard(loadAsset("milan/$name.json"))
        val parsed = card.parseTransitData()
        assertNotNull(parsed, "milan/$name.json was not recognised")
        assertTrue(parsed is MilanUltralightTransitData,
                "milan/$name.json parsed as ${parsed::class.simpleName}")
        assertEquals("Milano STIBM (Ultralight)", card.parseTransitIdentity()?.name)
        return parsed
    }

    private fun MilanUltralightTransitData.emptiness() = regions.map { it.isEmpty }

    @Test
    fun testLoadedMi1Mi3() {
        val d = load("mi1m3_loaded")
        // slot 1, slot 2, area A, area B
        assertEquals(listOf(false, false, true, false), d.emptiness())
        assertEquals(listOf(1, 0), d.regions.mapNotNull { it.flag })
    }

    @Test
    fun testLoadedMiMi3() {
        val d = load("mimi3_loaded")
        assertEquals(listOf(false, false, true, false), d.emptiness())
        assertEquals(listOf(0, 1), d.regions.mapNotNull { it.flag })
    }

    @Test
    fun testEmpty() {
        val d = load("empty")
        assertEquals(listOf(true, false, false, true), d.emptiness())
        assertEquals(listOf(1, 1), d.regions.mapNotNull { it.flag })
    }

    @Test
    fun testTopUp() {
        // Same ticket as "empty", read with UL Dumper just before and after a top-up at a machine.
        // The extra "ulDumper" JSON object must not stop Metrodroid from importing the file.
        val before = load("used_before_topup")
        assertEquals(listOf(true, false, false, true), before.emptiness())
        assertEquals(listOf(1, 1), before.regions.mapNotNull { it.flag })
        // The new product goes into the other record slot; the old slot, both areas and both
        // flags are cleared.
        val after = load("used_after_topup")
        assertEquals(listOf(false, true, true, true), after.emptiness())
        assertEquals(listOf(0, 0), after.regions.mapNotNull { it.flag })
    }

    @Test
    fun testSerialMatchesPrintedNumber() {
        // Printed on the (real) ticket as "01-54542119393739012".
        assertEquals("54542119393739012", load("empty").serialNumber)
    }

    @Test
    fun testSharedRecord() {
        // Two different tickets carry a byte-identical record: records are not keyed per card.
        val a = load("mi1m3_loaded").regions[1].data
        val b = load("mimi3_loaded").regions[0].data
        assertEquals(a, b)
    }
}
