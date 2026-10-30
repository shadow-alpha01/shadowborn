# Shadow Mist — instrukcja

To działający prototyp usługi w Rust, z audytem, CLI, demonem, konfiguracją TOML
i dziennikiem przywracania. Pełna walidacja zmian DNS/MAC na osobnej maszynie
wirtualnej jest nadal wymagana; nie jest to zatwierdzone wydanie produkcyjne.

```bash
cargo build --locked --release --workspace
./target/release/shadowmist doctor
./target/release/shadowmist audit --json
./scripts/install.sh --check
./scripts/install.sh --dry-run
sudo ./scripts/install.sh --profile balanced
sudo systemctl enable --now shadowmist-recover shadowmist
```

W `/etc/shadowmist/config.toml` wskaż UUID własnych profili w
`general.enrolled_profiles`. DNS wymaga dodatkowo zgody na odpytywanie 2–4 domen
w `dns.health_domains` oraz zgodnego, aktywnego systemd-resolved. Usługa nie
przejmuje automatycznie kontroli nad istniejącym resolverem.

```bash
sudo shadowmist config validate
sudo shadowmist apply --dry-run --verbose
sudo shadowmist apply
shadowmist status --json
```

MAC/IPv6 zmieniają ustawienia przyszłej aktywacji profilu. Natychmiastowa rotacja
przerywa połączenie i wymaga `--reconnect --acknowledge-disconnect`; po wykryciu
zdalnej administracji dodatkowo `--force-remote`.

```bash
sudo shadowmist identity rotate --interface wlan0 --reconnect --acknowledge-disconnect
sudo shadowmist restore --dry-run
sudo shadowmist restore
sudo ./scripts/uninstall.sh --restore
```

Zatrzymanie usługi nie przywraca ustawień. `DEGRADED` oznacza m.in. cofnięcie DNS;
poprzedni, potencjalnie nieszyfrowany DNS może działać. Konflikty ze zmianami
administratora pozostają do ręcznego rozstrzygnięcia.

To ochrona prywatności lokalnego łącza i systemowego DNS, nie anonimowość.
Publiczny IP, metadane operatora, konta i odcisk przeglądarki pozostają poza jej
zakresem. Nie ma VPN, skanowania cudzych hostów ani telemetrii.
Zobacz [wyniki testów](validation.md) i [procedury naprawcze](recovery.md).
