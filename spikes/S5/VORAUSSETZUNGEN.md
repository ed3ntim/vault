# S5 — Voraussetzungen für die Messung

Was beschafft, eingerichtet und **gebaut** sein muss, damit die Messkampagne
nach `MESSPROTOKOLL.md` starten kann. Am Ende (§5) steht ungeschminkt, woran
die Messung heute tatsächlich hängt.

Zeichen: ✅ vorhanden/erledigt · ⬜ zu beschaffen oder einzurichten · ❌ **existiert heute nicht**

---

## 1. Geräte

| # | Anforderung | Quelle | Status |
|---|---|---|---|
| G-1 | Android-Gerät der **Mittelklasse, 3–4 Jahre alt** (Kaufjahr ≈ 2022–2023) | `phase0-spikeplan.md` §2, S5 | ⬜ |
| G-2 | **Mindestens 2 verschiedene Modelle**: eines AOSP-nah (z. B. Pixel-a-Reihe), eines mit aggressivem OEM-Energiemanagement (z. B. Samsung/Xiaomi). Letzteres ist der realistische Schlechtfall für einen Foreground-Service. | `MESSPROTOKOLL.md` §8.3 | ⬜ |
| G-3 | **4 baugleiche Einheiten je Modell**, wenn die Timebox von 8 T gehalten werden soll (Rechnung in `MESSPROTOKOLL.md` §8.4). Mit 1 Einheit je Modell dauert die Kampagne ~4 Wochen. | §8.4 | ⬜ |
| G-4 | Vergleichbarer Akkuzustand innerhalb eines Modells (Ladezyklen/Gesundheit dokumentiert, keine ausgetauschten Akkus mischen) | Methodik | ⬜ |
| G-5 | Identische Android-Version **und** Patchlevel je Modell; keine Updates während der Kampagne | `MESSPROTOKOLL.md` §4.4 | ⬜ |
| G-6 | **Beacon-Gegenstelle** für R4: ein weiteres Gerät mit derselben App, als Kontakt eingerichtet, sendet im 30-s-Raster in ~2 m Abstand | `MESSPROTOKOLL.md` §4.5 | ⬜ |
| G-7 | Gerät für den Referenz-Messenger-Lauf R5 (kann dieselbe Einheit sein, dann Vault deinstalliert) | `phase0-spikeplan.md` §2 | ⬜ |
| G-8 | Ruhiger Messplatz mit stabiler Temperatur (20–25 °C, Schwankung < 5 K), definierter WLAN-Abdeckung und wenig fremdem BLE-Verkehr; R4-Geräte dürfen sich nicht gegenseitig sehen | `MESSPROTOKOLL.md` §4.5, §4.7 | ⬜ |

**Android-Version:** mindestens **Android 10** (ab da liefert `dumpsys
thermalservice` den Thermal-Status; ohne ihn ist Kriterium 3 nicht messbar).
Praktisch sinnvoll: Android 12–14, weil das der Zielbereich für 3–4 Jahre alte
Geräte ist. Für Android ≥ 12 ist zu prüfen, ob `batterystats --checkin` auf dem
Gerät noch die erwarteten `pwi`-Zeilen liefert oder ob `--proto` nötig wird
(siehe §4, Werkzeug-Vorbehalt).

Nicht nötig: externes Leistungsmessgerät (Monsoon, Otii). Der interne
Coulomb-Zähler reicht für Differenzen in %/24 h. Wenn eines vorhanden ist,
schadet es nicht — dann bitte parallel mitschreiben.

---

## 2. Werkzeuge auf dem Messrechner

| # | Werkzeug | Zweck | Status |
|---|---|---|---|
| W-1 | **adb** (Android Platform-Tools ≥ 34) im PATH | alle Skripte | ⬜ |
| W-2 | **POSIX-Shell + awk** (Linux/macOS, Windows: Git Bash) | `tools/collect/*.sh` | ✅ |
| W-3 | **Rust-Toolchain** (stable, ≥ 1.75) | Bau von `s5-eval`, keine weiteren Abhängigkeiten | ✅ |
| W-4 | **Battery Historian 3.0** lokal (Docker-Image `gcr.io/android-battery-historian/stable:3.0`), nur für die visuelle Nachschau auffälliger Läufe | optional | ⬜ |
| W-5 | Ausreichend Plattenplatz für Bugreports (~50–200 MB je Lauf), falls `S5_BUGREPORT=1` genutzt wird | optional | ⬜ |

Battery Historian wird **lokal** betrieben. Ein Upload von Bugreports zu einem
fremden Dienst ist ausgeschlossen (CLAUDE.md, ADR-14).

---

## 3. Geräteeinstellungen vor der Kampagne

| # | Einstellung | Warum | Status |
|---|---|---|---|
| E-1 | Entwickleroptionen aktiv | Voraussetzung für alles Weitere | ⬜ |
| E-2 | **Wireless Debugging** (WLAN-adb) eingerichtet und gekoppelt | USB lädt und verfälscht jede Messung (`MESSPROTOKOLL.md` §5) | ⬜ |
| E-3 | „Aktiv lassen" (Stay awake) **aus** | Display muss aus bleiben | ⬜ |
| E-4 | Battery Saver aus, automatischer Battery Saver aus | verändert Scheduling | ⬜ |
| E-5 | Adaptive Battery / App-Standby-Optimierung aus | sonst geräteabhängige Willkür | ⬜ |
| E-6 | Play-Store-Auto-Update aus, Play-Protect-Scan aus, Konten-Sync aus | Fremdlast | ⬜ |
| E-7 | Automatische Systemupdates aus | Fremdlast, Vergleichbarkeit | ⬜ |
| E-8 | Always-On-Display, Hotword-Erkennung, Standortdienste aus — **Ausnahme:** wenn der BLE-Scan Standortdienste verlangt, dann für **alle** Reihen an | Fremdlast, aber gleiche Bedingungen | ⬜ |
| E-9 | Akkuoptimierung für die App genau so gesetzt, wie das Produkt sie später anfordert, und dokumentiert | Messung soll den Auslieferungszustand abbilden | ⬜ |
| E-10 | SIM entnommen oder Mobilfunkdaten aus (WLAN ist die normative Bedingung) | `MESSPROTOKOLL.md` §4.3 | ⬜ |
| E-11 | Wegwerf-Identität ohne echte Kontakte auf allen Messgeräten | Datenhygiene, `MESSPROTOKOLL.md` §11 | ⬜ |

---

## 4. Was von der App vorhanden sein muss — und was davon existiert

Das ist der harte Teil. Die Messreihen aus der Spec setzen einen Messgegenstand
voraus, den es im Repository heute nicht gibt.

| # | Bestandteil | Gebraucht für | Spec-Verweis | Status |
|---|---|---|---|---|
| A-1 | Android-App, die installierbar ist und den Prozess dauerhaft hält (**Foreground-Service**) | alle Reihen R1–R4 | `gesamtkonzept.md` §2.6, §2.12; Backlog DL-6 | ❌ |
| A-2 | **Tor-Onion-Service mit Client-Auth**, dauerhaft publiziert (Arti oder C-tor sandboxed) | R1 | §2.2, §2.5; ADR-02, ADR-03; abhängig von **S1** | ❌ |
| A-3 | **Snowflake/meek** als Transport zuschaltbar | R2 | §2.5; Backlog TR-2 | ❌ |
| A-4 | **Traffic-Shaping** (Padding-Größenklassen, Alltags-Sendemuster, session-gebunden) | R3 | §2.5; Backlog TR-4 | ❌ |
| A-5 | **BLE-PSI-Beacons** im 30-s-Raster inkl. Empfangs-/Prüfpfad (Bloom-Filter) | R4 | `protokoll-spec.md` §13; Backlog ME-1/ME-2 | ❌ |
| A-6 | **Sync-Fenster-Logik** (stündliches Raster mit Offset je Kontaktpaar) — bestimmt, wie oft das Gerät aufwacht | R1–R4 | `protokoll-spec.md` §10 | ❌ |
| A-7 | Persistente Sendequeue + E2E-ACK (erzeugt Verbindungsversuche im Leerlauf) | R1–R4 | §2.6; Backlog DL-1/DL-5 | ❌ |
| A-8 | Schaltbarkeit der Bestandteile **ohne Codeänderung** (Build-Varianten oder Debug-Schalter), damit R1→R2→R3→R4 sauber trennbar sind | Reihentrennung | Methodik | ❌ |
| A-9 | Reproduzierbarer App-Zustands-Snapshot (2 Kompartimente, 5 Kontakte, leere Queue) zum Zurückspielen zwischen Läufen | Vergleichbarkeit | `MESSPROTOKOLL.md` §4.6 | ❌ |

**Stand des Repositories (geprüft):**

- `core/` enthält 9 Crates mit zusammen ~1.240 Zeilen Rust, überwiegend
  Fehlertypen, Modul-Gerüste und ein CBOR-Modul. `core/vault-transport/src/tor/mod.rs`
  und `.../mesh/mod.rs` sind je 6–7 Zeilen Doc-Kommentar mit dem Vermerk
  „Status: Geruest".
- Ein `app/`-Verzeichnis (Flutter, `platform/` mit Foreground-Service) existiert
  nicht — obwohl `spec/engineering-setup.md` §2 es vorsieht.
- Damit gibt es **keinen Messgegenstand**. Nichts von A-1 bis A-9 ist vorhanden.

**Abhängigkeit von anderen Spikes:**

- **S1 blockiert S5.** Ohne entschiedenen Tor-Stack (Arti vs. C-tor sandboxed)
  ist unklar, was überhaupt gemessen wird — der Verbrauch der beiden Stacks kann
  sich deutlich unterscheiden. `phase0-spikeplan.md` §1 nennt den kritischen
  Pfad ausdrücklich: **S1 → S5 → S2**.
- **S4** liefert die Publikations-/Jitter-Parameter, die im Leerlauf mitlaufen und
  damit Verbrauch erzeugen. GATE-3 speist sich aus S4 **und** S5.

**Werkzeug-Vorbehalt (betrifft nicht die App, sondern die Auswertung):**
Die Parser für `dumpsys batterystats --history`, `--checkin` und
`dumpsys thermalservice` sind nach der dokumentierten AOSP-Ausgabe gebaut und
gegen synthetische Beispiele getestet — **nicht gegen ein echtes Gerät**. Beim
ersten realen Dump ist deshalb zu prüfen:

```sh
adb shell dumpsys batterystats --history | head -40      # Zeitangaben kumulativ?
s5-eval history <datei> --series R0 --device DEV-A       # Zeilenzahl plausibel?
s5-eval batterystats <datei>                             # "Erkannte pwi/pws-Zeilen" > 0?
s5-eval thermal <datei>                                  # Statuszeilen > 0?
```

Alle drei Werkzeuge melden ihre Trefferzahl und brechen bei unplausibler
Ausbeute ab, statt still falsche Zahlen zu liefern. Wenn das Format abweicht,
ist der Parser anzupassen — nicht das Ergebnis zu glauben.

---

## 5. Woran die Messung heute hängt

In dieser Reihenfolge:

1. **Es gibt keine App.** Kein Foreground-Service, kein Onion-Betrieb, kein
   Shaping, keine Beacons (§4, A-1 bis A-9). Ohne Messgegenstand ist keine
   einzige Reihe außer R0 (Baseline) und R5 (Referenz-Messenger) durchführbar.
2. **S1 ist nicht entschieden.** Der Tor-Stack steht nicht fest; er bestimmt den
   größten Einzelposten der Messung.
3. **Es gibt keine Referenzgeräte.** Mindestens 2 Modelle, für die Timebox 4
   Einheiten je Modell (§1).
4. **Die Auslegungsfrage zu „< 8 %/24 h" ist offen** (`MESSPROTOKOLL.md` §2).
   Sie entscheidet mit, ob dieselben Daten bestehen oder reißen.
5. **Das Referenzprofil (Kontakt-/Kompartimentzahl) ist eine Annahme**, keine
   Spec-Vorgabe (`MESSPROTOKOLL.md` §4.6), und muss bestätigt werden.

Was **jetzt schon** geht, ohne dass A-1…A-9 existieren:

- **R0-Läufe** (Baseline) auf beschafften Geräten. Sie sind ohnehin nötig und
  liefern nebenbei die Streuung der Baseline — die Größe, die über die nötige
  Laufzahl entscheidet (`MESSPROTOKOLL.md` §8.2).
- **R5-Läufe** (Referenz-Messenger) — vollständig unabhängig von Vault.
- **K1/K3-Kontrollläufe** (Flugmodus ohne App; Eigenverbrauch des Mitschnitts).
- Damit lässt sich die Messkette vollständig gegen echte Geräte verifizieren,
  bevor die App existiert. Das ist der sinnvollste nächste Schritt, sobald
  Geräte da sind.
