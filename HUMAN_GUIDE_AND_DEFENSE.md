# Guardian Protocol: vodič za predstavljanje i odbranu projekta

Ovaj dokument je namenjen osobi koja prvi put vidi projekat, članu žirija koji
želi da proveri bezbednosnu logiku i timu koji treba da izvede demonstraciju bez
čitanja Rust koda. Tehnički detalji mrežnih endpointa i formata poruka nalaze se
u `NETWORK_GUIDE.md`. Ovde je ista mreža objašnjena jezikom kojim može da se
predstavi uživo.

Autoritativna specifikacija projekta ostaje `MASTER_PROMPT.md`. Ako ovaj vodič
ikada odstupi od nje, specifikacija ima prednost.

## Šta pokušavamo da rešimo

Običan backup rešava gubitak diska tako što napravi još jednu kopiju. To otvara
novo pitanje: ko može da otključa tu kopiju ako vlasnik izgubi sve uređaje i
ključeve?

Najjednostavnija rešenja obično imaju jednu slabu tačku. Recovery ključ može da
bude izgubljen ili ukraden. Jedan cloud provajder može da postane konačni
autoritet. Jedna osoba od poverenja može da izgubi svoj deo ili da ga preda
napadaču. Kopiranje celog tajnog sadržaja na više mesta povećava broj meta.

Guardian Protocol raspoređuje dve različite odgovornosti:

- signeri odlučuju da li je konkretan zahtev za oporavak odobren;
- guardiani čuvaju delove već šifrovanog sadržaja i delove ključa potrebnog za
  njegovo otključavanje;
- novi recovery uređaj jedini spaja dovoljno ispravnih doprinosa i dobija
  plaintext.

Nijedan signer, guardian, relay ili config store samostalno nema ceo put do
tajne.

## Objašnjenje u jednoj rečenici

Guardian Protocol je decentralizovani sistem za oporavak tajne u kome grupa
signera mora da odobri tačno određeni novi uređaj, grupa guardiana mora da
oslobodi dovoljno šifrovanih delova posle obaveznog čekanja, a tajna se sklapa
samo na tom novom uređaju.

## Verzija za prvih 30 sekundi prezentacije

"Zamislite da ste izgubili svaki uređaj na kome se nalazila važna tajna. Ne
želimo rezervnu kopiju koju može da otključa jedna kompanija ili jedna osoba.
Zato odvajamo odobrenje od čuvanja. Dva od tri izabrana signera odobravaju baš
ovaj recovery uređaj. Pet od osam nezavisnih guardiana kasnije šalje svoje
šifrovane delove. Između te dve faze postoji period čekanja i mogućnost trajnog
otkazivanja zahteva. Tek novi uređaj sklapa ključ i dešifruje sadržaj. Mrežni
čvorovi nikada ne dobijaju plaintext."

## Mentalni model: dve odvojene brave

Poređenje sa dve brave je korisno dok se pamti gde prestaje analogija.

Prva brava je autorizacija. Njeno ime u protokolu je `A`. Ključ `A` je podeljen
među signerima. Potreban je prag, podrazumevano 2 od 3 signera, da bi recovery
klijent ponovo sastavio `A`.

Druga brava je custody, odnosno pristup čuvanom materijalu. Sadržaj se šifruje
posebnim ključem `DEK`. `DEK` je podeljen među guardianima, podrazumevano 5 od
8. Čak ni ti delovi nisu kod guardiana u otvorenom obliku. Svaki je dodatno
šifrovan ključem izvedenim iz `A`.

To znači da signer prag dobija autorizacioni ključ, ali nema guardian materijal.
Guardian prag ima potreban materijal, ali su delovi `DEK` zaključani pod `A`.
Tek recovery klijent koji prođe obe strane može da sastavi plaintext.

```text
2 od 3 signera
      |
      v
rekonstrukcija A -> otvaranje privatnog Recovery Descriptora
      |                         |
      |                         v
      |                  pronalazak guardiana
      |                         |
      v                         v
otvaranje DEK delova <- 5 od 8 guardian doprinosa
      |
      v
DEK + ciphertext -> plaintext samo na recovery klijentu
```

## Zašto bi neko koristio ovu mrežu

Ovaj pristup ima smisla kada korisnik ne želi da oporavak zavisi od jednog
uređaja, jedne osobe ili jednog servera. Mreža daje četiri praktične osobine:

1. Gubitak nekoliko učesnika ne mora da uništi backup. Prag 2 od 3 signera i 5
   od 8 guardiana dozvoljava da deo čvorova bude nedostupan.
2. Jedan kompromitovan učesnik nije dovoljan. Materijal je raspoređen, a
   autorizacija i custody su razdvojeni.
3. Pokušaj oporavka ne daje rezultat odmah. Period čekanja ostavlja vreme za
   cancellation ako je zahtev sumnjiv.
4. Javni bootstrap podatak ne objavljuje spisak guardiana. Taj spisak postaje
   dostupan tek nakon signer praga.

Ovo nije opravdanje da se prototip danas koristi za vredne produkcione tajne.
Trenutna verzija dokazuje protokol i stvarno mrežno izvršavanje. Produkcioni
deployment još zahteva TLS ili privatnu overlay mrežu, upravljanje tajnama,
šifrovanje diskova, sigurnosni audit i ozbiljniji anonymity transport.

## Ko učestvuje u mreži

| Učesnik | Šta radi | Šta zna | Šta nema |
|---|---|---|---|
| Owner/setup klijent | Pravi konfiguraciju i distribuira materijal | Originalnu tajnu tokom setupa, `A`, `DEK` i celu konfiguraciju | Ne ostaje stalni recovery autoritet nakon distribucije |
| Owner control | Čuva per-config cancellation privatni ključ i može samo da zabrani tačan recovery | Privatni cancellation ključ i request koji bira da otkaže | `A`, `DEK` i pravo da odobri ili izvrši recovery |
| Signer | Proverava zahtev i daje svoj deo autorizacije | Da je zamoljen da odobri neki pseudonimni recovery zahtev | Plaintext, `DEK`, guardian fragmente i, kao pojedinačni signer, guardian roster |
| Guardian | Čuva jedan fragment ciphertexta i jedan šifrovan deo `DEK` | Da se pristupa jednom njegovom opaque slotu | Identitet vlasnika, plaintext, `A`, otvoreni `DEK` deo i ceo guardian roster |
| Relay | Prosleđuje opaque šifrovane poruke | Mailbox koji je kontaktiran, sledeći interni node, vreme i veličinu saobraćaja | Sadržaj protokolskih poruka i tajne ključeve |
| Config store | Objavljuje Config Capsule po nasumičnom `config_id` | Pseudonimnu konfiguraciju, pragove, commitment vrednosti i šifrovani descriptor | Plaintext, `A`, `DEK` i otvoreni guardian roster |
| Recovery Card | Omogućava novom uređaju da pronađe početne podatke | Config locatore, relay baze, opaque signer mailboxes i owner cancellation javni ključ | Cancellation privatni ključ, ključ za dešifrovanje, guardian roster i tajni sadržaj |
| Recovery klijent | Vodi recovery i lokalno sklapa rezultat | Na kraju saznaje `A`, `DEK`, guardian roster i plaintext | Na početku nema nijedan originalni tajni ključ |

## Kriptografski predmeti bez magije

### `A`, autorizacioni ključ

`A` je nasumični 256-bitni ključ. Shamir ga deli među signerima. On ima dve
uloge:

- omogućava recovery klijentu da otvori privatni Recovery Descriptor;
- iz njega se za svakog guardiana izvodi poseban ključ kojim se dešifruje taj
  guardianov deo `DEK`.

`A` ne dešifruje sam payload.

### `DEK`, ključ podataka

`DEK` je drugi, nezavisno generisan 256-bitni ključ. XChaCha20-Poly1305 njime
šifruje originalni sadržaj. Shamir zatim deli `DEK` među guardianima.

Odvajanje `A` i `DEK` sprečava da signer autorizacioni materijal istovremeno
bude i kompletan ključ sadržaja.

### Ciphertext fragmenti

Tek nakon šifrovanja payload prolazi kroz Reed-Solomon erasure coding. Zato
guardiani čuvaju fragmente ciphertexta, a ne fragmente plaintexta. Bilo kojih
`k` ispravnih fragmenata može da rekonstruiše ciphertext.

Reed-Solomon rešava dostupnost. Ne dokazuje integritet. Merkle commitment i
AEAD autentikacija otkrivaju izmenjen fragment.

### Enkriptovani delovi `DEK`

Svaki guardianov Shamir deo `D_i` šifruje se posebnim ključem `K_i` izvedenim
iz `A`, `config_id`, verzije konfiguracije i indeksa guardiana. Guardian čuva
`E_i`, nikada otvoreni `D_i`.

Zbog vezivanja konteksta, deo iz jedne konfiguracije ili sa jednog guardian
indeksa ne može samo da se prebaci u drugi kontekst.

### Merkle commitmenti

Pri setupu klijent pravi commitment nad tačnim fragmentom i šifrovanim delom
`DEK` za svakog guardiana. Kasnije guardian uz svoj doprinos šalje Merkle proof.
Recovery klijent može da proveri da li je dobio baš ono što je bilo committed
pri setupu.

Sličan commitment postoji za signer skup. Guardian zato proverava da svaki
potpis za Begin ili Release pripada signer skupu koji je konfiguracija
prihvatila. Owner hard cancel proverava odvojeno, prema per-config javnom ključu
pinovanom tokom setupa.

### X-Wing transport i Ed25519 potpisi

X-Wing kombinuje X25519 i ML-KEM-768 za uspostavljanje transportnog ključa.
XChaCha20-Poly1305 zatim štiti sadržaj poruke i njen protokolski kontekst.

Potpisi su Ed25519. Oni su klasični, ne post-kvantni. Zato je tačan opis
projekta "post-quantum-skewed", a ne "fully post-quantum".

Enkripcija i potpis rešavaju različite probleme. Enkripcija skriva sadržaj od
relaya. Potpis pokazuje ko je potpisao tačan canonical transcript i otkriva
izmenu poruke.

## Setup: šta se dešava od tajne do mreže

Setup se izvršava na owner klijentu. To je jedini trenutak pre recoveryja kada
plaintext postoji u protokolu.

1. Klijent pravi nasumični `config_id`, početnu verziju, `A`, `DEK`, nezavisan
   per-config owner cancellation keypair, potpise, opaque mailbox
   identifikatore i slot identifikatore.
2. `A` se deli Shamir algoritmom među signerima prema pragu `s-of-m`.
3. Originalna tajna se šifruje sa `DEK`, uz associated data koja vezuje
   ciphertext za odgovarajući protokolski kontekst.
4. Ciphertext se deli Reed-Solomon kodiranjem na `n` fragmenata. Potrebno je
   `k` validnih fragmenata za rekonstrukciju.
5. `DEK` se Shamir algoritmom deli na `n` guardian delova, opet sa pragom `k`.
6. Svaki `D_i` se šifruje posebnim ključem izvedenim iz `A` i identiteta
   konfiguracije. Rezultat je `E_i`.
7. Klijent pravi Merkle commitment nad guardian materijalom i commitment nad
   signer skupom.
8. Klijent pravi Recovery Descriptor. U njemu su guardian mailboxes, opaque
   slotovi, indeksi, integrity podaci i parametri rekonstrukcije. Descriptor se
   šifruje ključem izvedenim iz `A`.
9. Svaki signer i guardian prvo objavljuje svoj statički X-Wing javni transport
   ključ kroz `GET /v1/node-info`.
10. Owner šalje svakom čvoru njegov provisioning zapis kroz direktni
    `POST /v1/provision`. Telo je zapečaćeno za X-Wing ključ tog čvora, a zahtev
    traži administratorski bearer token.
11. Owner registruje svaki nasumični mailbox kod svakog relay replica procesa.
    Svaki pamti isti mailbox, interni URL čvora i njegov transportni javni
    ključ. Duplikat ne može da pregazi postojeću rutu.
12. Isti Config Capsule se upisuje u svaki config-store replica proces. Capsule sadrži pragove,
    commitment vrednosti i šifrovani Recovery Descriptor, ali nema otvoreni
    guardian roster.
13. Owner lokalno čuva Recovery Card sa config locatorima, relay bazama, opaque
    signer mailbox adresama i javnim owner cancellation ključem.
14. Poseban `owner-control.json` sa mode `0600` čuva cancellation privatni ključ
    i guardian rute. Taj fajl nije deo Recovery Carda i ne šalje se mrežnim
    nodeovima.

Nakon setupa jedan guardian na disku ima samo svoj `F_i`, svoj `E_i`, proof,
opaque slot i minimalnu pseudonimnu policy konfiguraciju. Signer ima samo svoj
deo `A`, nezavisan potpisni ključ, membership proof i replay stanje.

## Kako poruka putuje kroz stvarnu mrežu

Recovery poruke ne idu kao čitljiv JSON od klijenta do signera ili guardiana.
Put izgleda ovako:

```text
recovery klijent
    -> HTTP POST na opaque relay mailbox
    -> relay prosleđuje nečitljiv sealed body odgovarajućem node procesu
    -> node dešifruje, proverava poruku i menja svoje trajno stanje
    -> node šifruje odgovor za sveži recovery-recipient ključ
    -> relay vraća sealed odgovor
    -> samo recovery klijent može da ga otvori
```

Spoljašnji HTTP sloj sadrži mailbox potreban za rutiranje. `config_id`,
`request_id`, signer identitet, guardian indeks, nonce i recovery recipient
ostaju u unutrašnjem enkriptovanom payloadu kada rutiranje ne zahteva drugačije.

Request i response koriste različite domain-separated associated-data
kontekste. Byteovi iz request konteksta zato ne mogu samo da se predstave kao
validan response.

Ovaj kanal štiti sadržaj, ali ne skriva sve metapodatke. Jedan relay vidi vreme,
veličinu, kontaktirani mailbox i sledeći node. HTTP bez TLS-a takođe otkriva
zaglavlja i mrežne endpoint podatke. To je razlog zbog kog stvarni runtime ne
tvrdi da je produkcioni mixnet.

### Ko zove koga

| Faza | Pošiljalac | Primalac | Mrežna akcija | Zaštita i svrha |
|---|---|---|---|---|
| Setup | Owner | Signer ili guardian | `GET /v1/node-info` | Preuzima ulogu, node id i X-Wing javni ključ |
| Setup | Owner | Signer ili guardian | `POST /v1/provision` | Admin token dozvoljava upis, a sealed body skriva zapis od mreže |
| Setup | Owner | Relay | `POST /v1/register` | Admin token registruje nasumični mailbox, target URL i transportni javni ključ |
| Setup | Owner | Config store | `PUT /v1/configs/{config-id}` | Admin token objavljuje write-once Config Capsule bez otvorenog descriptora |
| Recovery | Recovery klijent | Config store | `GET /v1/configs/{config-id}` | Javno preuzima pseudonimni Capsule sa bootstrap podacima |
| Recovery | Recovery klijent | Relay | `GET /v1/mailboxes/{opaque-id}/key` | Dobija transportni javni ključ nodea iza mailboxa |
| Recovery | Recovery klijent | Relay, zatim signer | `POST /v1/mailboxes/{opaque-id}` | Šalje sealed RecoveryRequest ili release zahtev |
| Recovery | Signer | Relay, zatim recovery klijent | HTTP response | Vraća sealed SignerContribution ili ReleaseVote |
| Recovery | Recovery klijent | Relay, zatim guardian | `POST /v1/mailboxes/{opaque-id}` | Šalje Begin ili ReleaseCertificate |
| Hard cancel | Owner control | Relay, zatim guardian | `POST /v1/mailboxes/{opaque-id}` | Šalje OwnerCancelCertificate potpisan setup-time privatnim ključem |
| Recovery | Guardian | Relay, zatim recovery klijent | HTTP response | Vraća sealed prihvatanje, odbijanje ili GuardianContribution |

Direktni provisioning endpointi pripadaju administratorskoj mreži. Na odvojenim
VM-ovima treba da budu dostupni samo setup administraciji. Normalan recovery
ide preko opaque relay mailboxa.

## Recovery: ceo tok na potpuno novom uređaju

Recovery uređaj počinje samo sa Recovery Card podatkom.

### 1. Bootstrap

Klijent čita `config_id`, Config Capsule locatore, relay baze, signer mailboxes
i signer-set commitment sa kartice. Zatim javno preuzima prvi Capsule koji
kriptografski odgovara podacima pinovanim na kartici.

### 2. Sveži primalac

Za svaki pokušaj pravi novu jednokratnu X-Wing recipient keypair. Privatni
decapsulation ključ nikad ne napušta recovery proces.

### 3. Tačan RecoveryRequest

Klijent pravi novi `request_id`, nonce, vreme nastanka i expiry. Canonical
transcript uključuje verziju protokola, crypto suite, config id i verziju,
request id, tačan recipient javni ključ, vreme, nonce i expiry.

Signer ne potpisuje rečenicu "odobreno". Potpisuje upravo taj skup byteova.

### 4. Signer odobrenja

Zahtev putuje kroz opaque mailbox do svakog dostupnog signera. U pravom načinu
rada signer van protokola proverava da li osoba zaista sme da pokrene recovery.
To može biti društvena ili organizaciona provera. Kriptografija sama ne zna ko
je čovek sa druge strane.

Signer proverava verziju, expiry, recipient, replay id i nonce. Zatim svoj deo
`A` šifruje direktno za novi recovery recipient, potpisuje ceo doprinos i vraća
ga kroz relay. Trajno zapisuje replay stanje pre odgovora.

Docker demo ima `GP_AUTO_APPROVE=true` da bi scenario mogao da se izvrši bez
troje ljudi za tastaturom. To je demo prekidač, ne predlog za produkciju.

### 5. Rekonstrukcija `A`

Klijent proverava signer potpise, signer Merkle proofove, duplikate i vezivanje
za isti zahtev. Kada dobije prag validnih odgovora, lokalno dešifruje Shamir
delove i sastavlja `A`.

Sa `A` otvara Recovery Descriptor. Tek tada saznaje koji guardian mailboxes i
slotovi pripadaju ovoj konfiguraciji.

### 6. Begin

Signer doprinosi se pakuju u `BeginRecoveryCertificate`. Recovery klijent ga
šalje guardianima iz privatnog descriptora.

Svaki guardian sam proverava signer potpise, membership proofove, request
digest, recipient, nonce, expiry, config verziju i svoj replay state. Ako je sve
validno, trajno zapisuje Begin i računa lokalni `not_before` iz monotonog sata.

### 7. Delay

Guardian koristi Unix wall time za nastanak i expiry zahteva. Za samo čekanje
koristi Linux monotoni uptime. Time pomeranje sistemskog sata ne preskače delay.

Uz pending zahtev čuva se i Linux boot id. Ako se VM ili kernel restartuje tokom
čekanja, guardian ne pretpostavlja da je vreme prošlo. Odbija release dok se ne
pokrene protokolski bezbedan novi pokušaj.

Produkcijska policy granica je najmanje 86.400 sekundi. Docker demonstracija
koristi eksplicitni nesigurni demo flag i kratko čekanje da publika ne bi čekala
24 sata. Recovery klijent zaista čeka, a svaki guardian proverava svoj sat. UI
timer nema uticaj na odluku.

### 8. Owner hard-cancel grana

Tokom čekanja owner control potpisuje tačan request digest per-config privatnim
cancellation ključem. Signeri ne mogu da otkažu zahtev. Guardian proverava
potpis prema javnom ključu pinovanom tokom setupa i trajno zapisuje tombstone.

Potpis vezuje i recovery recipient i poseban sveži recipient za šifrovane
guardian potvrde. Tombstone važi i ako hard cancel stigne pre Begin poruke zbog
mrežnog reorderinga. Kasniji Begin za isti zahtev tada se odbija.

Owner ne računa da je cancel završen čim pošalje poruku. Guardian prvo trajno
upiše tombstone, pa vraća svoju potpisanu potvrdu vezanu za tačan cancel
transkript. Potrebno je najmanje `n - k + 1` različitih potvrda. Za podrazumevani
raspored od osam guardiana i recovery prag pet, dovoljne su četiri: tada ostaju
najviše četiri guardian-a koji nisu potvrdili cancel, što nije dovoljno za
rekonstrukciju.

Guardian koji je već poslao svoj doprinos ne sme naknadno da potpiše cancel
potvrdu. Hard cancel ne može da povuče podatke koji su već isporučeni; njegova
svrha je da preseče recovery tokom reaction window-a, pre dostizanja praga.

### 9. Release grana

Ako nema cancellationa, klijent traži sveže release glasove signera za isti
nepromenjeni RecoveryRequest. Threshold-validni glasovi formiraju
`ReleaseCertificate`.

Sertifikat nije komanda koja prisiljava guardiana. Guardian i dalje proverava
da li je prihvatio Begin, da li je njegov lokalni delay istekao, da zahtev nije
expired, da verzija nije zastarela i da ne postoji cancellation tombstone. Na
nejasno stanje odgovara odbijanjem.

### 10. Guardian doprinosi

Guardian šalje svoj committed ciphertext fragment, enkriptovani deo `DEK`,
Merkle proof i potpis. Ceo odgovor je ponovo zapečaćen za isti recovery
recipient.

Ako guardian izmeni fragment i zatim ispravno potpiše izmenjene byteove, potpis
sam nije dovoljan. Merkle proof više ne odgovara setup commitmentu. Klijent
odbacuje taj doprinos i pita sledećeg guardiana.

### 11. Lokalna rekonstrukcija

Kada prikupi `k` validnih guardian odgovora, recovery klijent:

1. iz `A` izvodi odgovarajući `K_i` za svaki guardian indeks;
2. otvara `E_i` i dobija validne Shamir delove `D_i`;
3. sastavlja `DEK` iz najmanje `k` delova;
4. sastavlja ciphertext iz najmanje `k` Reed-Solomon fragmenata;
5. dešifruje ciphertext sa `DEK` i originalnim associated-data kontekstom;
6. prikazuje ili snima originalni sadržaj lokalno;
7. zeroize-uje privremene ključeve i osetljive međurezultate gde biblioteke to
   podržavaju.

Ni relay, signer, guardian ni config store ne učestvuje u ovoj plaintext fazi.

## Zašto postoje Begin i Release, a ne samo jedno odobrenje

Jedan signer sertifikat pre čekanja stvorio bi neprijatan problem. Guardian bi
posle delayja morao da zaključi da stara autorizacija i dalje važi. U
nepouzdanoj mreži odsustvo owner hard-cancel poruke nije dozvola.

Zato postoje dve signer faze. Begin pokreće lokalni guardian delay. Release je
druga, request-specific saglasnost. Guardian pored nje proverava trajno stanje
i owner cancellation tombstone. Ovaj model sprečava da sam relay ili jedna
stara poruka zaobiđu policy.

## Stanja recovery zahteva

Core koristi eksplicitna stanja:

```text
Created
  -> AwaitingApprovals
  -> Authorized
  -> DelayPending
  -> Releasing
  -> Completed
```

Iz aktivnog toka zahtev može da pređe u `Cancelled` ili `Expired`. Ne postoji
skriveno stanje koje preskače autorizaciju, delay ili release proveru.

`gp-core` nema socket, filesystem, sistemski sat, environment ili sopstveni OS
random generator. Dobija događaje, vreme i entropiju spolja. Isti deterministički
state-machine kod koristi simulator i stvarni network runtime. Razlika je u
izvoru događaja: simulator ih pravi kontrolisano, a `gp-network` ih dobija preko
HTTP-a, lokalnog sata i trajnog diska.

## Šta se trajno čuva

Svaki Docker actor ima svoj volume. Stanje se upisuje atomskim temp-file plus
rename postupkom. Na Unix sistemu fajlovi dobijaju mode `0600`.

Signer trajno čuva svoj deo `A`, potpisni ključ, membership proof, request id i
nonce replay podatke. Nema cancellation ključ ni cancellation pravo.

Guardian trajno čuva svoj `F_i`, `E_i`, proof, policy, Begin podatke, monotono
`not_before` vreme, boot id, viđene nonce vrednosti i cancellation tombstone.

Relay čuva mailbox rute. Config store čuva javne Config Capsules. U ovom
network MVP-u capsule je write-once po `config_id`, jer specifikacija još nema
canonical threshold-authorized mrežnu poruku za rotaciju.

JSON state nije šifrovan na disku. Mode `0600` smanjuje pristup drugim lokalnim
korisnicima, ali nije zamena za šifrovan volume i upravljanje ključevima.
Isto važi za `owner-control.json`, koji je najosetljiviji cancellation artefakt.

## Šta je stvarno, a šta je simulirano

### Stvarni network runtime

- relay, config store, signeri i guardiani su odvojeni OS procesi ili Docker
  kontejneri;
- poruke zaista putuju preko TCP/HTTP konekcija;
- svaki actor ima sopstveni ključ i trajno stanje;
- X-Wing, XChaCha20-Poly1305, Ed25519, Shamir, Reed-Solomon i Merkle provere su
  stvarne bibliotečke operacije;
- delay koristi stvarni monotoni sat;
- gašenje kontejnera pravi stvarni connection failure;
- neispravan guardian vraća stvarno nevalidan fragment koji klijent odbacuje;
- plaintext se zaista rekonstruiše samo u recovery procesu.

### Simulator

`gp-sim` kontroliše virtuelni sat, seed, latency, loss, duplication, offline
stanja i zlonamerne akcije da bi scenario mogao identično da se ponovi.

STRONG režim u simulatoru prikazuje fixed-size ćelije, epohe, cover traffic,
dummy zahteve i odgovore, rotirajuće mailbox identifikatore i više relay hopova.
Simulator zna koje su poruke realne radi animacije, ali protokolski actori i
observer objekat ne dobijaju tu oznaku.

### Granica tvrdnje

Moguće je reći: "Napravili smo stvarnu distribuiranu mrežu za protokol i
simulator za proučavanje metadata zaštite."

Nije moguće reći: "Deployovali smo produkcioni anonimni mixnet."

## Privatnost metapodataka

Enkripcija skriva sadržaj, ne i činjenicu da komunikacija postoji. Projekat
zato razdvaja tri nivoa:

| Režim | Šta radi | Poštena tvrdnja |
|---|---|---|
| OFF | Direktna šifrovana isporuka | Bazna linija bez anonymity tvrdnje |
| BASIC | Simulira opaque mailboxes, randomizovane delaye i multi-hop putanje | Otežava jednostavno direktno povezivanje |
| STRONG | Dodaje epohe, size buckets, cover saobraćaj, dummy poruke, rotaciju mailboxa i iste outer formate | Demonstrira kako se smanjuje jednostavna timing i route korelacija |

Čak i u STRONG simulatoru globalni observer vidi vreme, volumen, približnu size
kategoriju i susedne hopove na posmatranom linku. Signer zna da odobrava neki
recovery. Guardian zna da se pristupa jednom njegovom slotu. Threshold signera
može da sastavi `A` i otvori guardian roster. Projekat te činjenice prikazuje,
ne pokušava da ih sakrije marketinškim jezikom.

## Kako mreža reaguje na kvarove i napade

### Jedan signer je offline

Podrazumevani prag je 2 od 3. Recovery nastavlja sa dva dostupna signera.
Gašenje dva signera zaustavlja recovery. Kod ne spušta prag da bi scenario
prošao.

### Guardian je offline

Relay dobija stvarni connection failure. Klijent prelazi na sledećeg guardiana
dok ne prikupi `k` validnih odgovora.

### Guardian vraća izmenjen materijal

Klijent proverava potpis i originalni Merkle commitment. Izmenjeni fragment se
odbacuje kao erasure. Reed-Solomon se koristi tek nakon što je integritet
proveren.

### Relay menja poruku

Izmenjeni sealed payload ne prolazi X-Wing i AEAD proveru ili kasnije canonical
potpis. Relay može da uskrati dostupnost, ali ne može neprimećeno da preusmeri
validan doprinos na drugi recovery recipient.

### Relay ispusti sve poruke

Recovery staje. Kriptografija ne može da natera mrežu da isporuči paket. Za
produkciju su potrebni redundantni putevi i relay čvorovi.

### Stara poruka se ponovi

Signer i guardian proveravaju config verziju, request id, nonce, expiry i
canonical request digest. Viđeni zahtevi i nonce vrednosti čuvaju se na disku.

### Owner hard cancel i Begin promene redosled

Validan owner potpis kreira tombstone čak i ako Begin još nije stigao. Kasniji
Begin za isti zahtev se odbija.

### VM se restartuje tokom čekanja

Promena boot id vrednosti aktivira fail-closed ponašanje. Guardian ne zaključuje
da je delay prošao samo zato što nema pouzdanu vezu sa prethodnim monotonim
satom.

## Kako izvesti live demonstraciju

### Pre izlaska pred publiku

Na računaru sa Docker Engine ili Docker Desktop i Compose v2 pokrenite:

```sh
make network-demo
make network-cancel
make network-down
```

Prvi build traje duže jer kompajlira Rust image. Za prezentaciju ga uradite
unapred. Proverite da postoje:

```text
demo-data/recovery-card.json
demo-data/owner-control.json
demo-data/recovered-secret.bin
```

### Predloženi redosled priče

1. Pokažite topologiju: tri relay replica procesa, tri config-store replica
   procesa, tri signera i osam
   guardiana. Naglasite da su to odvojeni procesi sa odvojenim diskovima.
2. Pokrenite setup. Objasnite da plaintext postoji samo u owner procesu i da
   svaki node dobija drugačiji zapečaćeni zapis.
3. Otvorite Recovery Card. Pokažite da nema `guardian` polje, `A`, `DEK` ili
   plaintext i da owner cancellation privatni ključ postoji samo u odvojenom
   mode-0600 control fajlu.
4. Pokrenite recovery. Pokažite dva signer odobrenja, Begin na guardianima i
   stvarni delay.
5. Kada guardian 1 bude odbijen zbog Merkle proofa, ne predstavljajte to kao
   grešku demoa. To je namerni dokaz da validan potpis zlonamernog čvora ne može
   da zameni setup commitment.
6. Pokažite da sledećih pet validnih doprinosa ipak rekonstruiše isti sadržaj.
7. Pokrenite owner hard-cancel scenario. Objasnite da je validan release namerno
   pripremljen kao hostile race, ali guardian prihvata samo setup-time owner
   potpis i odbija release zbog trajnog tombstonea.
8. Završite granicom: stvarni runtime dokazuje mrežni protokol, a STRONG
   metadata režim se pošteno prikazuje kao simulator, ne kao deployovan mixnet.

### Komande koje publika može da vidi

```sh
make network-demo
docker compose -f compose.network.yml ps
docker compose -f compose.network.yml logs -f
jq . demo-data/recovery-card.json
make network-cancel
make network-down
```

Za demonstraciju stvarnog offline guardiana, posle setupa:

```sh
docker compose -f compose.network.yml stop guardian-2
make network-recover
```

Za demonstraciju offline signera:

```sh
docker compose -f compose.network.yml stop signer-3
make network-recover
```

## Tvrdnje koje možemo da branimo

- Plaintext je prisutan samo na owner klijentu tokom setupa i recovery klijentu
  pri završnoj rekonstrukciji.
- Signer i guardian thresholdi su stvarni Shamir thresholdi.
- Payload je šifrovan pre Reed-Solomon deljenja.
- Guardian nema otvoreni `DEK` share. Njegov share je šifrovan pod ključem
  izvedenim iz `A`.
- Svaki approval i contribution vezan je za celu tačnu recovery poruku i sveži
  recipient.
- Samo per-config privatni owner cancellation ključ može da napravi validan
  hard cancel; signeri nemaju taj protokolski put.
- Honest guardian koji vidi validan hard cancel setup-time owner ključa trajno
  odbija taj zahtev.
- Pokvaren guardian materijal se proverava i odbacuje pre rekonstrukcije.
- Guardian roster nije javno objavljen. Nalazi se u Recovery Descriptoru
  šifrovanom pod `A`.
- Stvarni runtime koristi zasebne procese, mrežne konekcije, disk stanje i
  monotoni delay.
- Projekat je post-quantum-skewed zbog X-Wing transporta, ali nije potpuno
  post-kvantan dok Ed25519 ostaje u sigurnosno važnom putu.

## Tvrdnje koje ne treba izgovoriti

- "Sistem je potpuno anoniman."
- "Niko ne može da vidi da se recovery dešava."
- "Delay je neprobojni kriptografski timelock."
- "Kompromitovani signer prag nije opasan."
- "Mreža je potpuno post-kvantno bezbedna."
- "Relay ne može ništa da uradi."
- "Recovery Card je beznačajna ako se ukrade."
- "Ovo je već spremno za čuvanje produkcionih tajni velike vrednosti."

## Kratak rečnik

| Pojam | Značenje u ovom projektu |
|---|---|
| Threshold | Najmanji broj različitih validnih učesnika potreban za sledeći korak |
| Shamir share | Jedan matematički deo ključa koji sam ne otkriva ceo ključ |
| Ciphertext | Sadržaj posle šifrovanja, pre završnog lokalnog dešifrovanja |
| AEAD | Enkripcija koja istovremeno proverava autentičnost ciphertexta i vezanog konteksta |
| KEM | Mehanizam kojim pošiljalac i tačan primalac uspostavljaju ključ za zaštićenu poruku |
| Commitment | Kriptografska obaveza prema tačno određenim podacima koja kasnije otkriva izmenu |
| Merkle proof | Kratak dokaz da određeni zapis pripada committed skupu |
| Canonical transcript | Jednoznačno poređani i domain-separated byteovi koje učesnik potpisuje |
| Opaque mailbox | Nasumična adresa za rutiranje koja ne kodira config, actor ulogu ili indeks |
| Recovery Descriptor | Privatni spisak guardian ruta, slotova i parametara rekonstrukcije, šifrovan pod `A` |
| Config Capsule | Javni pseudonimni bootstrap zapis bez plaintexta, ključeva i otvorenog guardian rostera |
| Recovery Card | Prenosivi locator za nov uređaj, koristan za bootstrap ali nedovoljan za recovery |
| Owner control | Privatni mode-0600 fajl sa per-config cancellation seed-om, guardian rutama i relay failover bazama; može samo da otkaže |
| Tombstone | Trajni zapis da je tačan zahtev otkazan i da više ne sme da bude oslobođen |
| Fail closed | Odbijanje operacije kada stanje ili dokaz nisu jasni i proverljivi |
| Monotoni sat | Brojač vremena koji ne ide unazad kada se promeni sistemsko wall vreme |

## Dvadeset kritičnih pitanja za odbranu

### 1. Koji konkretan problem projekat rešava ako već postoje backup sistemi?

Backup rešava postojanje kopije. Ovaj projekat rešava kontrolisani pristup toj
kopiji kada vlasnik više nema originalni uređaj ili ključ. Cilj je da nijedan
cloud server, osoba od poverenja ili storage node ne postane jedina tačka koja
može da odobri i izvrši recovery. Protokol zato odvaja autorizaciju signera od
custody materijala kod guardiana.

### 2. Zašto jednostavno ne podeliti plaintext među guardianima?

Zato što bi guardian shareovi tada bili delovi originalne tajne. Ovde se prvo
šifruje ceo payload sa `DEK`, pa se deli ciphertext. Guardiani dobijaju samo
fragmente ciphertexta. Dodatno, njihovi Shamir delovi `DEK` su šifrovani pod
ključevima izvedenim iz `A`. Kompromitovan storage sloj zato ne dobija otvoreni
payload niti odmah upotrebljiv `DEK`.

### 3. Zašto postoje i `A` i `DEK`? Zar jedan ključ nije dovoljan?

Jedan ključ bi spojio autorizaciju i dešifrovanje u isti trust domen. `A`
predstavlja odluku signera i otvara privatni recovery routing. `DEK` šifruje
sadržaj i deli se kroz guardian custody prag. Odvajanje znači da signeri nemaju
storage materijal, a guardiani ne mogu da otvore svoje `DEK` delove bez `A`.

### 4. Zašto se Shamir koristi dva puta?

Prvi put daje `s-of-m` prag za autorizacioni ključ `A`. Drugi put daje `k-of-n`
prag za `DEK`. To su dve različite grupe, dve različite odgovornosti i dva
nezavisno podešena praga. Reed-Solomon se odvojeno koristi za dostupnost velikog
ciphertexta, ne za podelu kriptografskog ključa.

### 5. Može li dovoljan broj signera sam da pročita tajnu?

Ne samo iz signer materijala. Threshold signera može da rekonstruiše `A`, otvori
Recovery Descriptor i autorizuje zlonameran zahtev. To je ozbiljan kompromis.
Ipak, signeri ne čuvaju ciphertext fragmente ni guardian `DEK` materijal, pa im
je za završetak potreban i guardian release put. Delay i owner hard cancel daju
vreme za reakciju dok vlasnik ima svoj per-config privatni ključ, ali ne
pretvaraju kompromitovan signer prag u bezopasan događaj.

### 6. Može li dovoljan broj guardiana sam da pročita tajnu?

Guardian prag može da prikupi ciphertext fragmente i šifrovane `DEK` shareove.
Shareovi `D_i` su zaključani posebnim ključevima izvedenim iz `A`. Bez `A`
guardian kompromis sam po sebi ne otkriva `DEK`. Maliciozni guardiani mogu da
ignorišu svoj delay, ali i dalje nemaju signer autorizacioni materijal.

### 7. Šta se dešava ako napadač kompromituje oba potrebna praga?

Tada bezbednosna pretpostavka pada i napadač može da završi recovery. Projekat
ne tvrdi suprotno. Njegova vrednost je u odvajanju materijala i uklanjanju jedne
centralne tačke kompromisa, ne u garantovanju bezbednosti nakon istovremenog
prelaska oba relevantna praga.

### 8. Šta napadač dobija krađom Recovery Carda ili owner-control fajla?

Dobija pseudonimni config locator, opaque signer mailbox adrese, signer-set
commitment i javni owner cancellation ključ. Ne dobija njegov privatni par,
plaintext, `A`, `DEK`, guardian roster ili ključ za dešifrovanje. Kartica ipak
nije beznačajna. Može da pomogne u korelaciji i da se
koristi za spam ili phishing prema signer mailboxima. Zato je označena kao
nepoverljiva u smislu sadržaja, ali privacy-sensitive, uz rate limiting zahteva.

`owner-control.json` je druga kategorija. On sadrži cancellation privatni ključ
i guardian rute. Njegova krađa ne daje `A`, `DEK` ili plaintext, ali napadač
može validno i trajno da otkazuje recovery zahteve za tu konfiguraciju. To je
denial of service. Gubitak tog fajla uklanja jedini cancellation autoritet,
zato produkcija zahteva hardware-backed ili šifrovano čuvanje i backup.

### 9. Zašto je recovery vezan za novi recipient ključ?

Bez tog vezivanja relay ili napadač bi mogao da pokuša da odobren zahtev
preusmeri na svoj javni ključ. Ovde signer potpisuje ceo request koji uključuje
recipient, a svoj `A` share šifruje baš tom recipientu. Release glasovi i
guardian contributions vezani su za isti request digest. Izmena recipienta
menja transcript i obara potpise ili AEAD kontekst.

### 10. Kako sprečavate replay starog odobrenja?

Poruke vezuju protocol i crypto-suite verziju, config id i verziju, jedinstven
request id, recipient, nonce, vreme i expiry. Signeri i guardiani trajno pamte
viđene request id i nonce vrednosti. Stara verzija, drugačiji digest, duplikat
ili expired zahtev se odbija. Potpis se pravi nad canonical, domain-separated
transcriptom, ne nad proizvoljnom Rust serijalizacijom.

### 11. Zašto postoji 24-časovni delay i da li je on kriptografski garantovan?

Delay ostavlja legitimnom vlasniku vreme da primeti i svojim setup-time ključem
otkaže sumnjiv recovery. Signeri nemaju cancellation pravo. Delay nije
trust-free cryptographic timelock. Svaki honest
guardian ga sprovodi policy odlukom nad svojim monotonim satom. Dovoljno
malicioznih guardiana može da ignoriše delay, ali njihov materijal i dalje
zahteva `A`. Produkcijska konfiguracija odbija period kraći od 86.400 sekundi;
demo skraćivanje je eksplicitno označeno nesigurnim flagom.

### 12. Zašto ne koristite blockchain ili drand za čekanje?

Specifikacija namerno ne stavlja blockchain, plaćanja ili drand u kritični put.
Delay je lokalna guardian policy. Time je model jednostavniji i precizno se zna
koju pretpostavku pravi. Projekat ne predstavlja delay kao trust-free dokaz
prolaska vremena i ne uvodi novi sigurnosni oslonac koji prototip ne može da
odbrani.

### 13. Šta ako cancellation i Begin stignu različitim redosledom?

Validan owner hard-cancel potpis stvara trajni tombstone čak i kada stigne pre
Begin poruke. Ako Begin kasnije stigne za isti request id i digest, guardian ga
odbija. Ako digest konfliktuje, guardian fail-closed odbija nejasno stanje. Zato
mrežni reorder ne pretvara raniji hard cancel u dozvolu za release.

### 14. Može li stari ReleaseCertificate da pobedi cancellation u trci?

Ne kod honest guardiana koji je video validan owner hard cancel.
ReleaseCertificate je samo jedan uslov. Guardian proverava i trajni tombstone
pre svakog doprinosa. Demo namerno priprema validan release, zatim dostavlja
owner potpis, čeka kraj delayja i ponovo nudi release. Guardian vraća šifrovano odbijanje. Time se
proverava upravo najnepovoljniji redosled za ovu logiku.

### 15. Kako sistem preživljava offline ili zlonamernog guardiana?

Threshold je manji od ukupnog broja guardiana. Klijent preskače connection
failure i nastavlja da traži doprinose. Za zlonamerni odgovor proverava potpis,
request binding, guardian indeks, Merkle proof i AEAD autentikaciju. Neispravan
doprinos se tretira kao erasure. Recovery uspeva tek kada postoji tačno
konfigurisan broj validnih odgovora. Prag se nikada automatski ne spušta.

### 16. Zašto potpis zlonamernog guardiana nije dovoljan dokaz integriteta?

Zlonamerni guardian poseduje svoj potpisni ključ, pa može pravilno da potpiše
lažan fragment. Potpis potvrđuje poreklo tih byteova, ne da su isti kao pri
setupu. Merkle commitment je napravljen pre napada i vezuje očekivani `F_i` i
`E_i`. Zato validan potpis nad izmenjenim fragmentom i dalje pada na Merkle
proveri.

### 17. Da li relay ili config store može da ukrade ili zameni recovery?

Relay može da vidi i blokira saobraćaj. Ne može da pročita sealed payload niti
da napravi odgovor koji prolazi recipient AEAD i canonical potpise. Config store
ima javni pseudonimni Capsule, ali nema ključ za Recovery Descriptor. Network
MVP tretira Capsule kao write-once po `config_id`, pa token-bearing proces ne
može da izmisli novu rotaciju. Ni relay ni config store ne mogu da garantuju
dostupnost. Mogu da izvedu denial of service.

### 18. Kako čuvate guardian roster i koje je ograničenje te privatnosti?

Roster je u Recovery Descriptoru šifrovanom ključem izvedenim iz `A`. Recovery
Card i javni Config Capsule ga nemaju. Jedan signer ga ne saznaje samo zato što
je dobio zahtev, a jedan guardian vidi samo svoj slot. Threshold signera može da
rekonstruiše `A` i otvori descriptor. To je eksplicitna trust granica. Stvarni
jedno-hop relay takođe vidi mailbox-to-node rute i mrežne obrasce, pa runtime ne
tvrdi punu metadata anonimnost.

### 19. Da li je ovo prava mreža ili samo vizuelna simulacija?

Oba dela postoje i imaju različite uloge. `gp-network` pokreće relay, config
store, signere i guardiane kao zasebne procese ili Docker kontejnere. Oni koriste
stvarne HTTP konekcije, ključeve, disk stanje i monotone satove. `gp-sim` daje
deterministički virtuelni sat, mrežne kvarove i OFF, BASIC i STRONG metadata
eksperimente. STRONG mixnet ponašanje nije deployovano u stvarnom runtimeu i ne
predstavlja se kao da jeste.

### 20. Da li je sistem spreman za produkciju i šta nedostaje?

Spreman je kao radni hackathon prototip i live dokaz protokola. Nije spreman za
vredne produkcione tajne. Potrebni su TLS ili privatni overlay za transportne
endpoint podatke, stvarni secret manager umesto demo tokena, šifrovani diskovi,
backup i oporavak node stanja, hardware-backed ili šifrovano čuvanje owner
cancellation ključa, autentifikovan owner notification kanal, OS hardening,
monitoring, redundantni relay
putevi, definisana potpisana rotacija, zamena ili migracija klasičnih Ed25519
potpisa ako se traži puna post-kvantna tvrdnja i nezavisan kriptografski i
implementacioni audit. Automatsko signer odobravanje i kratki delay moraju biti
isključeni.

## Završna poruka za odbranu

Na odbrani treba ostati unutar proverljivih granica svake komponente.

Signer prag daje autorizaciju, ali nema storage materijal. Guardian prag čuva
materijal, ali nema `A`. Relay prenosi poruke, ali ne čita njihov sadržaj.
Config store pokreće bootstrap, ali ne objavljuje guardian roster. Recovery
klijent je jedino mesto gde se dve strane spajaju, posle request-specific
odobrenja, lokalnog delayja i provere da owner cancellation ne postoji.

Demo treba da pokaže uspešan recovery, ali i odbijanje pogrešnog recipienta,
stare poruke, korumpiranog fragmenta i otkazanog zahteva.
