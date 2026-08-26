# Keep it up! — so bringst du es online (ohne irgendwas zu installieren)

Kein Terminal, kein Code, kein "Node installieren". Nur klicken. Dauert ca. 10 Minuten,
danach hast du zwei echte Web-Adressen: eine für die Website, eine für den Server dahinter.

Diese Anleitung nutzt zwei kostenlose Dienste:
- **GitHub** — dort liegt der Code (nur als Ablage, du musst nichts damit programmieren)
- **Render** — dort läuft die Website und der Server tatsächlich, live im Internet

---

## Schritt 1 — GitHub-Konto (falls noch nicht vorhanden)

1. Geh auf **github.com** → "Sign up" → E-Mail, Passwort, Name eingeben, Konto bestätigen.
2. Fertig, das war's für diesen Schritt.

## Schritt 2 — Ein neues Repository anlegen

1. Oben rechts auf das **+** klicken → "New repository"
2. Name eingeben, z. B. `keep-it-up` (egal, wie du's nennst)
3. Auf **"Create repository"** klicken (Standardeinstellungen sind ok)

## Schritt 3 — Die Dateien hochladen (per Drag & Drop, kein Git nötig)

1. Auf der leeren Repo-Seite siehst du einen Link **"uploading an existing file"** — klicken
2. Zieh den **kompletten Ordnerinhalt**, den ich dir gegeben habe, in das Browser-Fenster:
   - `render.yaml`
   - den ganzen Ordner `server` (mit `server.js`, `db.js`, `auth.js`, `package.json`)
   - den ganzen Ordner `public` (mit `index.html`)
3. Ganz unten auf **"Commit changes"** klicken

   Die Ordnerstruktur muss danach genau so aussehen:
   ```
   dein-repo/
     render.yaml
     server/
       server.js
       db.js
       auth.js
       package.json
     public/
       index.html
   ```
   (GitHub erhält die Ordnerstruktur beim Drag & Drop automatisch, solange du die ganzen
   Ordner reinziehst und nicht nur einzelne Dateien.)

## Schritt 4 — Render-Konto + Deployment

1. Geh auf **render.com** → "Get Started" → am einfachsten mit deinem GitHub-Konto anmelden
   (keine Kreditkarte nötig für den kostenlosen Start)
2. Im Dashboard oben auf **"New +"** → **"Blueprint"**
3. Render fragt nach einem Repository — wähle das Repo, das du gerade angelegt hast
   (ggf. musst du Render einmal kurz Zugriff auf GitHub erlauben — normaler Bestätigungsdialog)
4. Render liest automatisch die `render.yaml` und zeigt dir **zwei** Dienste an:
   - `keepitup-api` (der Server)
   - `keepitup-web` (die Website)
5. Auf **"Apply"** klicken. Render baut jetzt beides — das dauert ein paar Minuten.

## Schritt 5 — Server und Website miteinander verbinden (keine Datei bearbeiten!)

Keine Code-Änderung nötig, kein GitHub-Editor. Nur einmal eine Adresse im Browser öffnen:

1. Wenn `keepitup-api` fertig gebaut ist, zeigt Render dir oben eine Adresse wie
   `https://keepitup-api-xxxx.onrender.com` — die kopierst du.
2. Wenn `keepitup-web` fertig gebaut ist, zeigt Render dir eine zweite Adresse wie
   `https://keepitup-web-xxxx.onrender.com` — die ist deine eigentliche Website.
3. Öffne genau **einmal** diese Kombination im Browser (API-Adresse hinten dranhängen):
   ```
   https://keepitup-web-xxxx.onrender.com/?api=https://keepitup-api-xxxx.onrender.com
   ```
   (Beide Adressen aus Schritt 1+2 einsetzen, `?api=` bleibt genauso stehen.)
4. Die Seite merkt sich das automatisch in diesem Browser und räumt die Adresszeile
   danach von selbst wieder auf. Ab jetzt reicht die normale Adresse ohne `?api=...`.
5. Das war's — kein Commit, keine Datei, kein Editor.

⚠️ Diesen einen Aufruf mit `?api=...` musst du **einmal pro Gerät/Browser** machen, von
dem aus du hostest (z. B. einmal auf deinem Laptop, einmal auf dem Handy, falls du von
beiden aus streamen willst). Fans, die nur beitreten, brauchen das nicht — die nutzen
einen anderen Link ohne `?api=`.

## Fertig

Deine Website läuft jetzt live unter der Adresse, die Render dir für `keepitup-web` zeigt
(etwas wie `https://keepitup-web-xxxx.onrender.com`). Die kannst du an echte Leute schicken.

---

## Neu eingebaut: Bracket Wars

Der dritte Warteschlangen-Modus ("Bracket Wars" — K.-o.-Turnier statt normaler Reihenfolge) läuft
jetzt komplett über den Server: Turnierbaum, automatisches Freilos bei ungerader Teilnehmerzahl,
Rundenaufstieg und Champion-Ermittlung. In den Show Controls unter "Order type" einfach auf das
Pokal-Symbol klicken, sobald mindestens 2 Leute in der Warteschlange sind.

## Neu eingebaut: Passwort-Reset

Login-Screen → "Forgot password?" → E-Mail eingeben → fertig. Ohne echten E-Mail-Versand
eingerichtet, landet der Reset-Link stattdessen in den **Server-Logs** bei Render (unter
"Logs" bei `keepitup-api`) — so kannst du den ganzen Ablauf selbst durchklicken, auch ohne
E-Mail-Dienst.

**Um echte E-Mails zu verschicken** (später, wenn's ernst wird):
1. Kostenloses Konto bei [resend.com](https://resend.com) anlegen (kein eigener Mailserver nötig)
2. Einen API-Key erzeugen
3. Bei Render unter `keepitup-api` → "Environment" → neue Variable `RESEND_API_KEY` mit dem Key eintragen
4. Optional: `RESEND_FROM` setzen (z. B. `"Keep it up! <noreply@deinedomain.de>"`), sonst wird eine Resend-Testadresse benutzt
5. Fertig — ab dann verschickt der Server echte E-Mails statt nur zu loggen

Der Reset-Link zeigt automatisch auf die richtige Adresse deiner Website — dafür musst du
nichts einstellen.

## Neu eingebaut: Sicherheit & Wachhalten

- **Brute-Force-Schutz:** `/api/login` erlaubt max. 10 Versuche pro 15 Minuten pro Besucher,
  `/api/signup` max. 5 neue Konten pro Stunde. Danach kommt kurz eine "Too many attempts"-Meldung
  statt endlos weiterzuprobieren.
- **`/health`** — ein simpler Endpunkt, der nur `{"ok":true}` zurückgibt. Nützlich, um den Server
  mit einem kostenlosen Ping-Dienst (z. B. UptimeRobot, cron-job.org) alle 10 Minuten aufzuwecken,
  damit er vorm Stream nicht gerade eingeschlafen ist. Einfach `https://deine-api.onrender.com/health`
  dort als URL eintragen.
- **CORS einschränkbar:** Im Render-Dashboard bei `keepitup-api` unter "Environment" kannst du
  eine Variable `CORS_ORIGIN` mit deiner echten Website-Adresse setzen (z. B.
  `https://keepitup-web-xxxx.onrender.com`), damit nur noch deine eigene Seite die API ansprechen
  darf. Ohne diese Variable ist es offen für alle — zum Testen völlig ok, für den Ernstfall würde
  ich sie setzen.

## Wichtig zu wissen

- **Kostenloser Tarif = Einschlafen bei Nichtnutzung.** Ruft niemand die Seite 15 Minuten lang
  auf, "schläft" der Server ein. Der nächste Aufruf dauert dann ~30–60 Sekunden zum Aufwachen.
  Für Tests völlig ok, für einen laufenden Stream solltest du kurz vorher einmal die Seite
  aufrufen, damit sie wach ist.
- **Die Datenbank wird bei jedem neuen Deploy zurückgesetzt**, weil dauerhafter Speicher auf
  dem Gratis-Tarif nicht dabei ist. Für "richtig scharf mit echten Nutzern über Wochen" brauchst
  du irgendwann Render's bezahlten Tarif (aktuell ~7 $/Monat) mit einer angehängten Festplatte —
  aber zum Ausprobieren und Zeigen reicht das Gratis-Setup komplett.
- Willst du später etwas am Code ändern: einfach die Datei in GitHub im Browser öffnen, den
  Stift anklicken, Text ändern, "Commit changes" — Render baut automatisch neu. Kein Editor,
  kein Terminal nötig.
