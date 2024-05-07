# Ohjelmistojen laatu

---

# Johdanto (peruskäsitteet)

- Laadun määritelmä
    
    Laatu ohjelmistojen kontekstissa tarkoittaa sitä, kuinka hyvin ohjelmisto täyttää sille asetetut vaatimukset ja odotukset. 
    
    Ohjelmiston laatu voi sisältää useita eri elementtejä, kuten suorituskyvyn, luotettavuuden, käytettävyyden, ylläpidettävyyden ja turvallisuuden. 
    
    Laadun määritelmä voi vaihdella riippuen sidosryhmästä; esimerkiksi käyttäjälle tärkeää voi olla käytettävyys ja suorituskyky, kun taas ohjelmistokehittäjälle tärkeää voi olla ylläpidettävyys ja modulaarisuus.
    
- Laadun kolme näkökulmaa
    - Prosessin laatu
        - Prosessin laatu tarkoittaa sitä, kuinka hyvin aikataulut ja budjetti pitivät ja kuinka toistettava prosessi oli.
    - Rakenteellinen laatu
        - Rakenteellinen laatu koostuu koodin ymmärrettävyydestä ja ylläpidettävyydestä, siitä kuinka uudelleen käytettävää ja siirrettävää koodi on, sekä sen turvallisuudesta ja testattavuudesta.
    - Toiminnallinen laatu
        - Toiminnallinen laatu kertoo siitä, kuinka hyvin ohjelmisto täyttää asetetut toiminnallisuusvaatimukset, kuinka helppokäyttöinen ja tehokas ohjelmisto on ja kuinka luotettavana sitä voi pitää (ei sisällä virheitä, tekee mitä lupaa)
- Sertifiointi
    
    Sertifioinnin tavoitteena on saada todiste/sertifikaatti siitä, että organisaatio noudattaa tiettyä standardia tms.
    
    Sertifiointia suorittaa ulkoinen sertifiointiorganisaatio, joka on riippumaton sertifioitavasta.
    
    Sertifioinnin lopputuloksena on konkreettinen sertifikaatti.
    
- Auditointi
    
    Auditointi on riippumattoman tahon tekemä prosessin laatuarviointi, joka vertaa prosessia suunnitelmaan ja ohjeistukseen. 
    
    Auditointi pohjautuu haastatteluihin ja havaintoihin, jotka voidaan tehdä sisäisesti tai ulkoisesti.
    
    Auditointi on tärkeää sillä sen avulla voidaan tehdä muunmuassa laadunvarmistusta, riskienhallintaa, tunnistaa parannuksia sekä asiakastyytyväisyyden varmistamista.
    

---

# Lean

- Tavoite (hukan minimointi, fokus asiakkaassa)
    
    Lean-ohjelmistokehityksessä tavoitteena on tehostaa tuotantoprosessia ja parantaa ohjelmiston laatua keskittymällä asiakkaan tarpeiden tarkkaan ymmärtämiseen ja turhan työn minimointiin. 
    
    Tässä lähestymistavassa korostetaan jatkuvaa arvon tuottamista asiakkaalle ja prosessien virtaviivaistamista, jolloin pyritään poistamaan kaikki hukka, eli ne toiminnot kehitysprosessissa, jotka eivät suoraan lisää tuotteelle arvoa.
    
    1. **Hukan minimointi**: Lean-pyrimykset keskittyvät hukan — kuten odotusajat, tarpeettomat toiminnot tai liiallinen dokumentaatio — poistamiseen. Tämä voi tarkoittaa esimerkiksi turhien kokousten karsimista, monimutkaisuuden vähentämistä ja yksinkertaistamista, sekä prosessien automatisointia siellä, missä se on mahdollista.
    2. **Asiakasfokus**: Kaikki kehitystyö pyritään kohdistamaan suoraan asiakkaan tarpeiden ja toiveiden täyttämiseen. Tämä tarkoittaa asiakkaan jatkuvaa osallistamista kehitysprosessiin, jotta voidaan varmistaa, että lopputuote vastaa heidän odotuksiaan ja ratkaisee heidän ongelmansa.
- Historia
    
    Lean-ajattelun juuret ovat Japanissa, erityisesti Toyotan autotehtailla 1950-luvulla. Lean-filosofia on osa laajempaa Toyota Production System (TPS) -järjestelmää, jonka kehittivät pääasiassa Taiichi Ohno ja Shigeo Shingo. He pyrkivät luomaan tehokkaamman tuotantoprosessin, joka vähentää hukkaa ja parantaa laatua. TPS ja sen periaatteet olivat vastaus Japanin haastaviin taloudellisiin olosuhteisiin toisen maailmansodan jälkeen, kun resurssit olivat rajalliset ja tarve tehokkuudelle suuri.
    
    Lean-termin popularisoi kirja "The Machine That Changed the World" (1990), joka perustui Massachusetts Institute of Technologyn (MIT) tekemään laajaan tutkimukseen maailman autoteollisuudesta. Kirjassa verrattiin länsimaisia massatuotantomenetelmiä Toyotan tehokkaampiin prosesseihin, ja siitä tuli katalysaattori lean-ajattelun omaksumiselle länsimaissa.
    
    1990-luvulta eteenpäin lean-ajattelu on laajentunut autoteollisuudesta monille muille toimialoille, kuten terveydenhuoltoon, rakennusteollisuuteen ja ohjelmistokehitykseen. Nykyään lean-periaatteita sovelletaan laajasti eri sektoreilla parantamaan tehokkuutta, asiakastyytyväisyyttä ja laadun hallintaa.
    
    Lean-menetelmän keskeiset periaatteet, kuten jatkuva parantaminen (kaizen), hukan minimointi ja arvon maksimointi asiakkaalle, ovat auttaneet monia organisaatioita tehostamaan toimintaansa ja parantamaan kilpailukykyään globaalissa markkinassa.
    
- Periaatetta (5 why, 6  sigma, …)
    
    ### **5 Whys**
    
    "5 Whys" on yksinkertainen mutta tehokas ongelmanratkaisumenetelmä, jota käytetään juurisyyanalyysiin. Tämän tekniikan kehitti Toyota ja se on osa laajempaa Toyota Production Systemiä. Menetelmän perusajatuksena on kysyä "miksi?" viisi kertaa tai niin monta kertaa kuin tarvitaan, jotta päästään ongelman perimmäiseen syyhyn. Tämä prosessi auttaa tunnistamaan ongelman alkulähteen, jolloin voidaan kehittää kestäviä ratkaisuja sen sijaan, että keskityttäisiin vain oireiden hoitoon. Esimerkiksi, jos kone hajoaa, ensimmäinen "miksi?" voi paljastaa, että se johtui voiteluaineen puutteesta, ja toinen "miksi?" voi osoittaa, että voitelujärjestelmä ei toiminut oikein, ja niin edelleen.
    
    ### **Six Sigma**
    
    Six Sigma on laadunhallintamenetelmä, joka kehitettiin alun perin Motorolalla 1980-luvulla ja jota myöhemmin laajensivat ja popularisoivat muun muassa General Electric ja muut yritykset. Six Sigma pyrkii parantamaan prosessien laatua ja tehokkuutta vähentämällä virheitä ja vaihtelua. Menetelmä käyttää joukkoa tilastollisia työkaluja ja tekniikoita prosessin jokaisen aspektin tarkkaan analysointiin ja hallintaan. Six Sigma-projekteissa tyypillisesti käytetään DMAIC-viitekehystä, joka jakautuu vaiheisiin: Define (määritä), Measure (mittaa), Analyze (analysoi), Improve (paranna) ja Control (valvo). Tavoitteena on saavuttaa prosessit, joiden virhetaso on enintään 3,4 virhettä miljoonaa mahdollisuutta kohden, mikä vastaa "kuutta sigmaa" normaalijakauman sisällä.
    
    ### **Muita Lean-työkaluja ja -periaatteita**
    
    - **Kanban**: Visuaalinen työkalu työnkulun hallintaan, joka auttaa organisaatioita visualisoimaan tehtäviä, priorisoimaan niitä ja hallitsemaan työmäärää. Kanban edistää läpinäkyvyyttä ja auttaa tiimejä keskittymään nykyisiin tehtäviin tehokkuuden ja tuottavuuden parantamiseksi.
    - **Jatkuva parantaminen (Kaizen)**: Filosofia, joka kannustaa jatkuvia pieniä parannuksia koko organisaatiossa. Kaizen korostaa, että kaikki työntekijät kaikilla tasoilla osallistuvat aktiivisesti prosessien parantamiseen.
    - **Virtaus ja Pull-järjestelmä**: Pyrkii varmistamaan, että työ virtaa sujuvasti ilman keskeytyksiä, ja että tuotanto perustuu asiakkaan kysyntään (pull) eikä optimoimattomaan varastotason ylläpitoon (push).
- Yhtymäkohdat ketterään ohjelmistokehitykseen
    1. **Asiakaskeskeisyys**: Sekä lean että ketterä korostavat asiakkaan tarpeiden ymmärtämistä ja asiakasarvon maksimointia. Molemmissa menetelmissä asiakas on keskiössä, ja tavoitteena on toimittaa tuote, joka vastaa heidän vaatimuksiaan ja odotuksiaan.
    2. **Iteratiivinen kehitys**: Sekä leanissa että ketterässä kehityksessä tuotetta kehitetään pienissä iteraatioissa, jotka mahdollistavat jatkuvan palautteen saamisen ja nopean reagoinnin muutoksiin. Tämä lähestymistapa vähentää riskejä ja mahdollistaa joustavamman reagoinnin markkinoiden muutoksiin.
    3. **Jatkuva parantaminen**: Molemmissa lähestymistavoissa korostetaan prosessien ja tuotteiden jatkuvaa parantamista. Kaizen, eli jatkuva parantaminen, on keskeinen osa lean-filosofiaa, ja ketterässä kehityksessä retrospektiivit ovat olennainen osa jokaista sprinttiä, mikä mahdollistaa tiimin toiminnan ja prosessien jatkuvan kehittämisen.
    4. **Tiimityöskentely ja yhteistyö**: Molemmissa menetelmissä korostetaan tiimityöskentelyn ja tiiviin yhteistyön merkitystä. Leanissa tiimit työskentelevät yhdessä hukkaa minimoiden, ja ketterässä kehityksessä cross-funktionaaliset tiimit työskentelevät yhdessä tuotteiden iteratiivisessa kehityksessä.

---

# SPICE

- Mitä prosessi tarkoittaa?
    
    Prosessi viittaa toimenpiteiden, menetelmien ja rutiinien joukkoon, joita käytetään tietyn tavoitteen saavuttamiseksi. Ohjelmistokehityksessä prosessi voi sisältää kaikki askeleet ohjelmistovaatimusten määrittelystä suunnitteluun, toteutukseen, testaukseen ja ylläpitoon.
    
- Millaisia prosesseja ohjelmistotuotantoon liittyy?
    - **Vaatimusmäärittely**: Määritellään, mitä käyttäjät ja sidosryhmät odottavat valmiilta ohjelmistolta.
    - **Suunnittelu**: Arkkitehtuurin ja komponenttien suunnittelu sekä rajapintojen määrittely.
    - **Toteutus**: Ohjelmiston koodaaminen ja kehittäminen.
    - **Testaus**: Ohjelmiston toiminnallisuuden ja suorituskyvyn varmistaminen ennen julkaisua.
    - **Ylläpito**: Ohjelmiston jatkokehitys ja virheiden korjaus käyttöönottovaiheen jälkeen.
    - **Projektinhallinta**: Resurssien hallinta, aikataulutus ja budjetointi.
- Mitä on prosessin laatu?
    
    Prosessin laatu viittaa siihen, kuinka hyvin ohjelmistotuotantoprosessit täyttävät niille asetetut tavoitteet ja vaatimukset. Laadukas prosessi on yleensä hyvin dokumentoitu, toistettavissa ja tehokas, ja se tuottaa korkealaatuisia ohjelmistoja johdonmukaisesti. Prosessin laatua voidaan mitata esimerkiksi virheiden määrällä, projektin aikataulussa pysymisellä ja budjetin noudattamisella.
    
- Prosessin kyvykkyyden arviointi
    
    SPICE-standardin mukaisesti prosessin kyvykkyys arvioidaan usein käyttämällä määriteltyä kyvykkyysasteikkoa, joka vaihtelee tasolta 0 (epätäydellinen) tasolle 5 (optimointi). Arviointiin sisältyy:
    
    - **Prosessimittaukset**: Mittaamalla prosessin suorituskykyä eri näkökulmista.
    - **Vertailu**: Vertaamalla prosessin suorituskykyä vakiintuneisiin standardeihin tai parhaisiin käytäntöihin.
    - **Itsearviointi ja ulkopuoliset auditoinnit**: Organisaation sisäiset ja ulkopuoliset arvioinnit prosessien tehokkuudesta.
    
    Kyvykkyysarviointi auttaa tunnistamaan prosessin vahvuudet ja heikkoudet sekä tarjoaa suuntaviivoja jatkuvan parantamisen mahdollistamiseksi.
    

---

# SQuaRE

- Mistä tuotelaatu koostuu?
    - **Toiminnallisuus**: Ohjelmiston kyky suorittaa määritetyt tehtävät tietyissä olosuhteissa.
    - **Luotettavuus**: Ohjelmiston kyky toimia luotettavasti ja virheettömästi.
    - **Käytettävyys**: Käyttäjän kyky käyttää ohjelmistoa tehokkaasti ja tyytyväisesti.
    - **Suorituskyky**: Ohjelmiston kyky toimia tehokkaasti ja vastata suorituskyvyn vaatimuksiin.
    - **Ylläpidettävyys**: Ohjelmiston kyky mukautua muutoksiin ja korjaantua virhetilanteissa.
    - **Siirrettävyys**: Ohjelmiston kyky toimia eri ympäristöissä ja alustoilla.
- Mistä käytönaikainen laatu koostuu?
    - **Käyttökokemus**: Loppukäyttäjien kokemukset ja tyytyväisyys ohjelmiston käytön aikana.
    - **Vakaus ja luotettavuus käytössä**: Ohjelmiston kyky toimia keskeytyksettä ja odotetusti reaalimaailman käyttötilanteissa.
    - **Tuki ja huolto**: Ohjelmiston ylläpidon ja tukipalveluiden saatavuus ja tehokkuus käyttäjille.
    - **Skaalautuvuus**: Ohjelmiston kyky kasvaa ja sopeutua käyttäjämäärän tai datan määrän kasvaessa.
- Edellä mainittujen suhde prosessin laatuun
    
    Prosessin laatu viittaa siihen, miten hyvin ohjelmistokehityksen prosessit ovat suunniteltu, hallittu ja toteutettu. Prosessin laatu on perusta, jolle tuotelaatu ja käytönaikainen laatu rakentuvat. Prosessin laadun parantaminen voi johtaa parempaan tuotelaatuun ja parempaan käyttökokemukseen, koska se voi sisältää:
    
    - **Paremmat suunnittelukäytännöt**: Tarkemmat vaatimusmäärittelyt ja suunnittelut voivat johtaa virheettömämpiin tuotteisiin.
    - **Tehokkaat kehityskäytännöt**: Agile-menetelmät, jatkuva integraatio ja testaus auttavat paljastamaan ja korjaamaan virheitä aikaisessa vaiheessa.
    - **Laadunvarmistus**: Kattavat testaus- ja tarkastusprosessit varmistavat, että tuote täyttää kaikki laadulliset vaatimukset ennen julkaisua.
    
    Parantamalla kehitysprosesseja voidaan varmistaa, että tuote ei ainoastaan täytä teknisiä vaatimuksia vaan myös tarjoaa erinomaisen käyttökokemuksen ja suorituskyvyn loppukäyttäjille. Tämä integroitu lähestymistapa laatuun luo pohjan kestävälle ohjelmistotuotteelle, joka palvelee käyttäjiensä tarpeita tehokkaasti.
    

---

# Stattinen analyysi

- Lähtökohta: koodia ei ajeta.
    
    Staattinen analyysi tarkoittaa koodin tarkastelua sen suorittamatta jättämistä. Toisin sanoen, analyysi suoritetaan koodin lähdekoodille ilman, että itse ohjelmaa ajetaan. Tämä mahdollistaa virheiden, puutteiden ja mahdollisten suorituskykyongelmien tunnistamisen jo kehitysvaiheessa.
    
- Kompleksisuusmitat
    
    Kompleksisuusmitat ovat keskeisiä työkaluja koodin laadun arvioinnissa staattisen analyysin avulla. Ne antavat kehittäjille kvantitatiivisia tietoja koodin monimutkaisuudesta, joka voi olla indikaattori mahdollisista ongelmista. Yleisiä kompleksisuusmittoja ovat esimerkiksi:
    
    - **Cyclomatic Complexity**: Mittaa ohjelman kompleksisuutta sen ohjausrakenteiden, kuten ehtolauseiden ja silmukoiden määrän perusteella. Korkeampi arvo voi viitata siihen, että koodi on vaikeampi ymmärtää ja ylläpitää.
    - **Halstead Complexity Measures**: Arvioi ohjelmiston kompleksisuutta perustuen operaattorien ja operandien määrään. Nämä mittarit voivat auttaa ymmärtämään ohjelman vaativuutta ja mahdollisia testauksen tarpeita.
- Millaisia seikkoja stattinen analyysi löytää?
    
    Staattinen analyysi voi tunnistaa monenlaisia koodin ongelmia, kuten:
    
    - **Syntaksivirheet**: Vaikka nämä yleensä havaitaan jo käännösaikana, staattinen analyysi voi tarjota lisätietoja virheiden syistä.
    - **Koodin hajuvirheet (Code Smells)**: Nämä ovat ei-optimaalisia koodin pätkiä, jotka voivat heikentää ohjelman ylläpidettävyyttä.
    - **Tietoturva-aukot**: Esimerkiksi puskurin ylivuodot ja injektiohaavoittuvuudet.
    - **Suorituskykyongelmat**: Kuten tarpeettoman monimutkaiset silmukat tai tehottomat datarakenteiden käytöt.
    - **Tyyli- ja standardivirheet**: Kuten noudattamatta jättäminen tietyistä koodaustyylin säännöistä.
- Miten tulosten pohjalta parannetaan koodia?
    
    Kun staattinen analyysi on tunnistanut potentiaaliset ongelmat, kehittäjät voivat käyttää näitä tietoja koodin parantamiseen. Tässä muutamia yleisiä toimenpiteitä:
    
    1. **Korjaa virheet**: Välittömästi korjaa kaikki löydetyt virheet, erityisesti tietoturvaan liittyvät uhat.
    2. **Refaktoroi koodi**: Paranna koodin rakennetta refaktoroimalla monimutkaiset osat selkeämmiksi ja tehokkaammiksi.
    3. **Noudatetaan koodaustyylin standardeja**: Yhtenäistä koodia noudattamalla tietyt koodaustyylin säännöt, mikä parantaa sen luettavuutta ja ylläpidettävyyttä.
    4. **Opi virheistä**: Kehittäjät voivat oppia analyysin tuloksista ja välttää samankaltaisia virheitä tulevaisuudessa.
    
    Staattinen analyysi on siis arvokas työkalu ohjelmistokehityksessä, joka auttaa varmistamaan koodin laadun ja turvallisuuden jo varhaisessa vaiheessa.
    

---

# Siisti koodi

- Sovelluksen arkkitehtuuri
    
    Sovelluksen arkkitehtuuri viittaa ohjelman rakenteeseen ja suunnitteluun, joka mahdollistaa vaatimusten täyttämisen tehokkaasti. Hyvä arkkitehtuuri tukee sovelluksen kehittämistä, testaamista ja ylläpitoa pitkällä aikavälillä. Se sisältää suunnittelupäätöksiä, jotka määrittävät komponenttien väliset suhteet ja vuorovaikutuksen, sekä sen, miten data liikkuu järjestelmässä. Kestävä arkkitehtuuri mahdollistaa järjestelmän laajentamisen ja muokkaamisen ilman, että se vaatii suuria uudelleenkirjoituksia tai rakennekorjauksia.
    
- Löyhä kytkentä
    
    Löyhä kytkentä tarkoittaa sitä, että järjestelmän eri osat ovat toiminnallisesti riippumattomia toisistaan. Kun moduulit tai komponentit ovat löyhästi kytkettyjä, yhden osan muutokset eivät aiheuta laajoja muutostarpeita muissa osissa. Tämä parantaa modulaarisuutta ja helpottaa esimerkiksi yksittäisten komponenttien päivittämistä, korjaamista tai vaihtamista ilman, että koko järjestelmä kärsii. Löyhä kytkentä on erityisen tärkeää suurissa, monimutkaisissa järjestelmissä, joissa muutosten hallittavuus on keskeistä.
    
- Korkea koheesio
    
    Korkea koheesio viittaa siihen, että moduulin, luokan tai komponentin sisällä olevat toiminnot liittyvät tiiviisti toisiinsa. Korkean koheesion omaavat komponentit ovat itsenäisiä ja keskittyvät yhteen tehtävään tai toiminnallisuuteen, mikä tekee niistä ymmärrettävämpiä, helpommin hallittavia ja virhealttiimpia. Korkea koheesio usein kulkee käsi kädessä löyhän kytkennän kanssa, ja yhdessä ne parantavat ohjelmiston suorituskykyä ja ylläpidettävyyttä.
    

---

# Refaktorointi

- Mitä tarkoittaa
    
    Refaktorointi tarkoittaa olemassa olevan ohjelmakoodin muokkaamista siten, että sen sisäinen rakenne parantuu, mutta ulkoinen toiminnallisuus pysyy samana. Tavoitteena on tehdä koodista selkeämpää, ylläpidettävämpää ja laajennettavampaa. Refaktorointi on tärkeä osa ohjelmistokehitystä, sillä se auttaa pitämään koodikannan terveenä ja helposti ymmärrettävänä, vaikka itse ohjelmisto kehittyisi ja kasvaisi.
    
- Koodin haisut
    
    Koodin haisut (Code Smells) ovat merkkejä ohjelmakoodissa, jotka voivat viitata syvemmälle juurtuneisiin ongelmiin. Ne eivät välttämättä ole välittömiä virheitä, mutta ne voivat olla potentiaalisia indikaattoreita huonosta suunnittelusta tai käytännöistä, jotka voivat myöhemmin johtaa virheisiin tai vaikeuksiin koodin ylläpidossa. Esimerkkejä koodin haisuista ovat:
    
    - **Suuri luokka** (Large Class): Luokka, joka sisältää liian monta toiminnallisuutta.
    - **Pitkät menetelmät** (Long Method): Metodit, jotka ovat liian pitkiä ja tekevät useita asioita.
    - **Toisteinen koodi** (Duplicate Code): Sama koodi toistuu useassa paikassa.
    - **Liialliset parametrit** (Long Parameter List): Metodeilla on liian monta parametria.
- Refaktorointitekniikoita
    1. **Metodien pilkkominen** (Extract Method): Jos metodissa on koodeja, jotka näyttävät toimivan erillisenä tehtävänä, ne voidaan erottaa omiksi metodeikseen.
    2. **Luokan pilkkominen** (Extract Class): Jos luokka tekee liikaa erilaisia tehtäviä, osa sen toiminnallisuuksista voidaan siirtää uuteen luokkaan.
    3. **Muuttujan nimeäminen uudelleen** (Rename Variable): Sekavasti nimetyt muuttujat voidaan nimetä uudelleen kuvaavammiksi, mikä parantaa koodin luettavuutta.
    4. **Parametrien vähentäminen** (Reduce Parameters): Metodeja voi muokata niin, että niiden parametrimäärää vähennetään, esimerkiksi käyttämällä objekteja parametrien ryhmittelyyn.
    
    Nämä tekniikat auttavat ylläpitämään koodin selkeyttä ja tehokkuutta, mikä on erityisen tärkeää pitkäaikaisissa ja suurissa ohjelmistoprojekteissa.
    

---

# Dynaaminen analyysi

- Lähtökohta: koodi suoritetaan
    
    Dynaaminen analyysi perustuu siihen, että koodi todella suoritetaan jollakin alustalla tai testiympäristössä. Tämä eroaa staattisesta analyysistä, jossa koodia analysoidaan suorittamatta sitä. Dynaamisen analyysin avulla voidaan havaita ongelmia, jotka ilmenevät vain suorituksen aikana, kuten muistivuodot, rinnakkaisuusongelmat ja suorituskykyongelmat.
    
- Näytteenotto ja instrumentointi
    
    Näytteenotto (sampling) tarkoittaa prosessin tai ohjelman suorituksen aikaisten tietojen keräämistä tietyin väliajoin. Tämä auttaa ymmärtämään suorituksen profiilia ja tunnistamaan suorituskyvyn pullonkauloja.
    
    Instrumentointi on prosessi, jossa koodiin lisätään ylimääräisiä komponentteja (esimerkiksi lisäkoodia), jotka keräävät tietoa ohjelman suorituksen aikana. Tämä voi sisältää muistin käytön seurannan, funktiokutsujen ajoituksen, ja muita suorituskykyyn liittyviä mittareita. Instrumentointi on tehokas keino kerätä tarkkaa dataa ohjelman käyttäytymisestä suorituksen aikana.
    
- Millaisia seikkoja dynaaminen analyysi löytää?
    - **Suorituskykyongelmat:** Esimerkiksi muistin ja prosessorin käytön tehoton hyödyntäminen.
    - **Synkronointivirheet:** Rinnakkain suoritettavissa ohjelmissa esiintyvät lukitusongelmat ja kilpailutilanteet.
    - **Muistivuodot:** Muistialueet, joita ei vapauteta ja jotka kuluttavat muistia tarpeettomasti.
    - **Käyttövirheet:** Esimerkiksi väärän tyyppisen datan käyttö tai funktioiden virheelliset paluuarvot.
- Miten tulosten pohjalta parannetaan koodia?
    1. **Virheiden korjaus:** Löydettyjen virheiden, kuten muistivuotojen tai synkronointivirheiden korjaaminen.
    2. **Refaktorointi:** Koodin uudelleenjärjestely tai kirjoittaminen uudelleen tehokkaammaksi tai ymmärrettävämmäksi perustuen löydettyihin suorituskyvyn pullonkauloihin.
    3. **Optimointi:** Algoritmien ja datarakenteiden valinnan uudelleenarviointi ja mahdollisesti tehokkaampien vaihtoehtojen käyttöönotto.
    4. **Testauksen laajentaminen:** Dynaamisen analyysin aikana löydettyjen ongelmakohtien perusteella testikattavuuden parantaminen, jotta samankaltaiset ongelmat voidaan löytää ja korjata tulevaisuudessa nopeammin.
    
    Dynaaminen analyysi on siis keskeinen osa ohjelmistojen laadunvarmistusta, joka auttaa tunnistamaan ja korjaamaan virheitä, jotka eivät välttämättä ilmene muissa testaus- tai analyysimenetelmissä.
    

---

# Testaus

- Testauksen tavoitteet
    
    Testauksen päätavoitteena on varmistaa, että ohjelmisto toimii suunnitellusti ja täyttää sille asetetut vaatimukset sekä laatuvaatimukset. Testaus pyrkii tunnistamaan ohjelmistosta mahdolliset virheet ja puutteet, jotta ne voidaan korjata ennen tuotteen julkaisua. Lisäksi testauksella pyritään lisäämään luottamusta ohjelmiston toimivuuteen, varmistamaan käyttäjien tyytyväisyys ja vähentämään ylläpitokustannuksia pitkällä aikavälillä.
    
- Testauksen kohteet
    
    Testauksen kohteita ovat kaikki ohjelmistokomponentit ja niiden integraatiot, mukaan lukien käyttöliittymät, tietokantatoiminnot, API:t, ja muut järjestelmän osat. Testauksen kohteena voi olla myös ohjelmiston toimintaympäristö ja kuinka ohjelmisto käyttäytyy eri alustoilla ja laitteilla.
    
- Testitapausten suunnittelu
    
    Testitapausten suunnittelu vaatii tarkkaa vaatimusmäärittelyjen ymmärtämistä ja testattavan ohjelmiston rakenteen tuntemista. Hyvä testitapaus on yksiselitteinen, toistettavissa oleva ja keskittyy yhteen konkreettiseen skenaarioon tai toiminnallisuuteen. Testitapauksien tulisi kattaa sekä onnistuneet että epäonnistuneet skenaariot, ja niiden tulisi mahdollistaa järjestelmällinen virheiden tunnistaminen ja dokumentointi.
    
- Testien kattavuus
    
    Testien kattavuus mittaa, kuinka suuri osa ohjelmiston koodista tai toiminnoista testataan. Kattavuuden tyyppejä ovat esimerkiksi rivikattavuus, haarautumiskattavuus ja tilakattavuus. Tavoitteena on saavuttaa mahdollisimman korkea kattavuusprosentti, joka takaa, että ohjelmistossa ei ole testaamattomia osia, jotka voisivat sisältää kriittisiä virheitä.
    
- Riskipohjainen testaus
    
    Riskipohjainen testaus tarkoittaa testaustoiminnan priorisointia perustuen eri ohjelmiston osien aiheuttamiin riskeihin liiketoiminnalle. Tällöin keskitytään erityisesti niihin ohjelmiston osiin, joiden virhetilanteet voisivat olla kaikkein vahingollisimpia tai todennäköisimpiä. Riskipohjaisessa testauksessa arvioidaan myös virheiden potentiaalisia vaikutuksia ja käytetään näitä tietoja testauksen suunnittelussa ja toteutuksessa.
    
- Hyvän/huonon testin piirteet
    
    **Hyvä testi**:
    
    - On riittävän yksityiskohtainen ja tarkka
    - Kattaa sekä positiiviset että negatiiviset skenaariot
    - On toistettavissa ja tuottaa johdonmukaisia tuloksia
    - On riittävän itsenäinen, eli sen suoritus ei ole riippuvainen muista testeistä
    - Dokumentoi selkeästi odotetut tulokset ja testin kulun
    
    **Huono testi**:
    
    - On epämääräinen tai liian yleinen
    - Ei kattavasti testaa ohjelmiston toiminnallisuutta
    - Tuottaa epäjohdonmukaisia tai vaihtelevia tuloksia
    - On riippuvainen monista muista testeistä tai ulkoisista tekijöistä
    - Ei dokumentoi selkeästi, mitä testataan ja mikä on odotettu lopputulos

---

# Mock-olio testauksessa

- Mikä on mock-olio?
    
    Mock-olio on testauksessa käytetty ohjelmistokomponentti, joka matkii oikean ohjelmiston toimintaa testausympäristössä. Sen avulla voidaan simuloida järjestelmän osia, jotka eivät ole testauksen kohteena tai joiden todellista toimintaa ei haluta tai voi käyttää testauksessa. Mock-olioiden avulla voidaan esimerkiksi simuloida tietokantayhteyksiä, verkkopalveluita tai muita riippuvuuksia, jotka ovat tarpeellisia testattavan ohjelmiston toiminnan kannalta, mutta joiden käyttäminen suoraan testauksessa olisi hankalaa, kallista tai epäkäytännöllistä.
    
- Käyttötarve
    
    Mock-olioita käytetään pääasiassa yksikkötestauksessa, missä tavoitteena on eristää testattava koodiyksikkö (esim. funktio tai luokka) ja varmistaa sen oikea toiminta erillään muista järjestelmän osista. Mock-oliot ovat hyödyllisiä, kun:
    
    - Testattavaan koodiin liittyy ulkoisia riippuvuuksia, kuten tietokantoja, tiedostojärjestelmiä tai ulkoisia API-kutsuja.
    - Halutaan varmistaa, että koodi käsittelee riippuvuuksien vastauksia oikein, esimerkiksi virhetilanteissa tai kun saadaan odottamaton vastaus.
    - Testauksen suorituskyky on tärkeää, ja todellisten riippuvuuksien käyttö hidastaisi testien suorittamista merkittävästi.
    - Testattavan koodin toimintaympäristöä on vaikea tai kallista jäljitellä testausympäristössä.
- Miten mock-testaus etenee (opettaminen, …) ?
    
    Mock-testaus etenee yleensä seuraavasti:
    
    1. **Mock-olion luominen:** Aluksi luodaan mock-olio, joka korvaa testattavan koodin riippuvuuden. Mock-olio määritellään vastaamaan riippuvuuden rajapintaa, mutta sen sisäinen toiminta on yksinkertaistettu tai ohjelmoitu vastaamaan testitapauksia.
    2. **Opettaminen (Mocking):** Mock-oliolle "opetetaan" halutut toimintatavat ja vastaukset. Tämä tarkoittaa, että ohjelmoidaan, miten mock-olion tulee reagoida tietyissä tilanteissa. Esimerkiksi, mitä palautetaan kun tiettyä metodia kutsutaan tietyillä parametreillä.
    3. **Integraatio testattavaan koodiin:** Mock-olio syötetään testattavan koodin osaksi siten, että se käyttää mock-oliota oikean riippuvuuden sijasta.
    4. **Testauksen suoritus:** Suoritetaan testit, jotka tarkistavat, että testattava koodi toimii oikein mock-olion avulla simuloitujen riippuvuuksien kanssa.
    5. **Varmistaminen (Verification):** Varmistetaan, että mock-olioita on käytetty odotetulla tavalla. Esimerkiksi, tarkistetaan, että tietyt metodit on kutsuttu oikeilla parametreilla.
    
    Mock-oliot ovat tehokas työkalu ohjelmistokehittäjän työkalupakissa, mahdollistaen tarkan ja eristetyn yksikkötestauksen, joka nopeuttaa kehityssykliä ja parantaa ohjelmiston laatua.
    

---

# Tietokannan testaus

- Erityishaasteet
    1. **Datan monimuotoisuus ja määrä**: Tietokantojen sisältämä data voi olla laajaa ja monimutkaista, mikä tekee testidatan hallinnasta ja testitapausten suunnittelusta haastavaa.
    2. **Riippuvuudet muihin järjestelmiin**: Tietokannat ovat usein kytköksissä muihin sovelluksiin ja palveluihin, mikä lisää testauksen monimutkaisuutta.
    3. **Transaktioiden hallinta**: Tietokannat käsittelevät transaktioita, jotka voivat sisältää useita toimintoja. Testauksessa on varmistettava, että kaikki transaktiot suoritetaan oikein ja että ne voidaan palauttaa tarvittaessa.
    4. **Samanaikaisuuden hallinta**: Tietokantojen on kyettävä käsittelemään useita samanaikaisia käyttäjiä ja kyselyitä ilman suorituskyvyn menetystä tai datan eheyden heikkenemistä.
- Rollback-toiminnallisuuden hyödyntäminen
    
    Rollback-toiminnallisuus on tärkeä työkalu tietokannan testauksessa. Se mahdollistaa muutosten peruuttamisen transaktioissa, mikä on erityisen hyödyllistä testausympäristössä:
    
    - **Testitilanteen nollaaminen**: Rollbackin avulla testitilanteet voidaan palauttaa alkuperäiseen tilaansa testien jälkeen, mikä eliminoi tarpeen manuaaliselle datan puhdistukselle.
    - **Virhetilanteiden hallinta**: Rollback mahdollistaa virhetilanteissa tehdyt muutokset peruuttaa, jolloin järjestelmän tila säilyy ennallaan ja virhetilanteita voidaan tutkia tehokkaammin.
- Tietokannan testauskirjasto (DBUnit)
    
    DBUnit on suosittu tietokannan testauskirjasto, joka on erityisesti suunniteltu Java-sovelluksille. Se tarjoaa työkaluja tietokantaympäristön hallintaan testauksen aikana:
    
    - **Datan alustaminen**: DBUnit voi alustaa tietokannan määritellyllä testidatalla ennen testien suorittamista.
    - **Datan vertailu**: Testien jälkeen DBUnit voi verrata tietokannan tilaa odotettuihin tuloksiin, jolloin testien oikeellisuus on helppo varmistaa.
    - **Datan ekspertointi ja impertointi**: DBUnit mahdollistaa datan viemisen ja tuomisen XML-muodossa, mikä helpottaa datan hallintaa ja siirtämistä eri ympäristöjen välillä.

---

# ATDD

- TDD ja ATDD: lähtökohdat ja suhde toisiinsa
    
    **TDD (Test-Driven Development) eli testivetoinen kehitys** on ohjelmistokehityksen lähestymistapa, jossa ohjelmisto kehitetään pienissä iteraatioissa kirjoittamalla ensin testit, jotka määrittelevät uuden toiminnon vaatimukset, ja vasta sen jälkeen itse koodi, joka läpäisee nämä testit. TDD keskittyy yksikkötestien kirjoittamiseen, joka varmistaa koodin toiminnallisuuden pienimmällä tasolla.
    
    **ATDD (Acceptance Test-Driven Development) eli hyväksymistestivetoinen kehitys** laajentaa TDD:tä siten, että testit kirjoitetaan ennen kehitystä kuvastamaan käyttäjän hyväksymäkriteereitä tai liiketoiminnan vaatimuksia. Nämä testit ovat usein laajempia kuin yksikkötestit ja ne tarkastelevat ohjelmiston toimivuutta käyttäjän näkökulmasta.
    
    TDD ja ATDD ovat toisiaan täydentäviä menetelmiä:
    
    - **TDD** keskittyy tekniseen toteutukseen ja koodin virheettömyyteen.
    - **ATDD** puolestaan keskittyy siihen, että lopputulos vastaa asiakkaan tai loppukäyttäjän tarpeita ja odotuksia.
- Käyttötapaukset ja todentamiskriteerit
    
    ATDD:ssä käyttötapaukset ja todentamiskriteerit ovat keskeisiä. 
    
    **Käyttötapaukset** kuvaavat, miten käyttäjä vuorovaikuttaa järjestelmän kanssa tietyssä tilanteessa, ja ne auttavat määrittämään, mitä järjestelmän on kyettävä tekemään. 
    
    **Todentamiskriteerit (tai hyväksymiskriteerit)** ovat konkreettisia ehtoja, joiden täyttyessä voidaan sanoa, että järjestelmä toimii odotetulla tavalla. Nämä kriteerit muodostavat perustan ATDD:n hyväksymistesteille.
    
- Gherkin
    
    Gherkin on kieli, jota käytetään käyttäytymisvetoinen kehitys (BDD) -menetelmässä, mutta se sopii hyvin myös ATDD:n yhteyteen. Gherkin avulla määritellään toiminnallisuuksia luonnollisen kielen kaltaisella syntaksilla, joka on helppo ymmärtää sekä kehittäjille että ei-teknisille sidosryhmille. Gherkin-skriptit alkavat yleensä avainsanoilla kuten:
    
    - **Feature:** Kuvailee testattavan ominaisuuden.
    - **Scenario:** Kuvailee tietyn käyttötapauksen tai liiketoimintalogiikan.
    - **Given, When, Then:** Kuvaavat testitapauksen prekonditiot (Given), toiminnot (When) ja odotetut tulokset (Then).
    
    Esimerkki Gherkin-skriptistä:
    
    ```gherkin
    Feature: Kirjautuminen
      Scenario: Onnistunut kirjautuminen
        Given käyttäjä on rekisteröitynyt palveluun
        When käyttäjä syöttää oikean käyttäjätunnuksen ja salasanan
        Then käyttäjä näkee etusivun
    ```
    

---

*Aman Mughal 07.05.2024*