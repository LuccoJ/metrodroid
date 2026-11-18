# UL Dumper

Tiny standalone Android app used to collect MIFARE Ultralight ticket dumps (Milan STIBM tickets) for
reverse-engineering the format.

While the app is open, every ticket held to the phone is read (never written) and saved to
`Download/STIBM-dumps/YYYYMMDD-HHMMSS_<tagId>.json`. The files are Metrodroid-compatible JSON, with
an extra `ulDumper` object holding what Metrodroid does not read: the three one-way counters, the
tearing flags, the originality signature, and an optional note typed before the scan. The screen
also lists which pages and counters changed since the previous read of the same ticket.

Build (needs the Android SDK):

    gradle assembleDebug

This is a separate Gradle project and is not part of the Metrodroid build.
