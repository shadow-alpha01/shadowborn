# Shadowborn — punkt wejścia

Repozytorium zawiera nowy moduł przygotowywania serwera WireGuard oraz zachowany
klient Shadow Mist. Nowy CLI generuje konfigurację serwera, zarządza urządzeniami
przed wdrożeniem i przygotowuje chronione kopie. Nie uruchamia automatycznie VPN.

Instrukcje techniczne są po angielsku: [serwer](installation-server.md),
[klient](client-enrollment.md), [odzyskiwanie](admin-recovery.md),
[polityka bez historii aktywności](no-logs-policy.md), [testy](validation.md).
Tryb strict, automatyczny rollback sieci i obsługa urządzeń na działającym serwerze
pozostają niewdrożone. To nie jest gotowe wydanie produkcyjne ani gwarancja
anonimowości. Dotychczasowy klient ma osobny [poradnik Shadow Mist](legacy/README.md).
