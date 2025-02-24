# Fitness App – Offline nutzbar mit Templates, Rollen und Beschreibungen

Dies ist ein **komplettes** Flask‑Projekt zum Verwalten von Trainingsplänen, Übungen, Sessions und Vorlagen („Templates“). Die Anwendung ist als Progressive Web App (PWA) konzipiert und kann auch **offline** genutzt werden. Darüber hinaus bietet sie Rollenverwaltung (Admin, Trainer, Standardbenutzer), die Möglichkeit, **Sichtbarkeit** für Vorlagen zu steuern und **Beschreibungen** bei Übungen hinzuzufügen.

## Funktionen

1. **User-Management**  
   - Registrierung (mit optionalem reCAPTCHA)  
   - Erster registrierter Benutzer wird automatisch Admin  
   - Login & Logout (Optionales „Angemeldet bleiben“ via Cookies)  
   - Admin kann andere Benutzer löschen oder deren Passwörter ändern  
   - Admin kann anderen Benutzern den Trainer‑Rang geben oder entziehen

2. **Trainingspläne & Übungen**  
   - Jeder Benutzer kann eigene Trainingspläne erstellen  
   - Zu jedem Plan lassen sich Übungen (mit **Name** und **Beschreibung**) hinzufügen  
   - Für jede Übung können **Sessions** (Sätze) mit Gewicht und Wiederholungen erfasst werden  
   - Übersicht des Verlaufs in Tabellenform & **interaktiver Chart** (Chart.js)  
   - Löschen von Trainingsplänen, Übungen und Sessions

3. **Vorlagen (Template Trainingspläne)**  
   - Admins und Trainer können Template Trainingspläne (mit Übungen + Beschreibung) anlegen, editieren, löschen  
   - Template-Übungen unterstützen ebenfalls eine **Beschreibung**  
   - Sichtbarkeit der Vorlagen steuerbar (`is_visible`)  
   - Alle Benutzer (auch Standardnutzer) können sich **sichtbare** Vorlagen anschauen und diese in ihren Account übernehmen (Übungen werden kopiert)

4. **Offline-Funktionalität (PWA)**  
   - Service Worker (sw.js) und Manifest (manifest.json) ermöglichen das Caching statischer Ressourcen  
   - Offline erstellte Daten (Sessions) können lokal gespeichert und bei Online‑Wiederkehr synchronisiert werden

5. **Rollen**  
   - **Admin**: uneingeschränkte Rechte (Benutzerverwaltung, Trainer‑Rang setzen/entziehen, Templates erstellen, Sichtbarkeit umschalten …)  
   - **Trainer**: ähnliche Rechte wie Admin für Templates (Erstellen, Editieren, Löschen, Sichtbarkeit …)  
   - **Standardbenutzer**: kann eigene Pläne verwalten und Vorlagen übernehmen, sieht jedoch nur sichtbare Vorlagen

## License

This project is licensed under the PolyForm Noncommercial License
Der Autor mrchaos behält sich das Recht vor, dieses Werk für kommerzielle Zwecke zu nutzen oder Lizenzen für kommerzielle Nutzungen zu vergeben.
