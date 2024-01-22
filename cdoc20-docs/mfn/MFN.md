Moved to https://confluence.ria.ee/x/o4NWDQ

<del>
<!-- 0 -->
|  |  |  |  |  |
|---|---|---|---|---|
| kategooria | nr | nõude sõnastus | nõude selgitus | märkused ||
|  |  |  |  |  |
|meta|1.1|Nõuete rakendamisel arvestada konkreetse tarkvara eripära.|Rakenduvad ainult need nõuded, mida konkreetse tarkvara iseloomu, ülesehituse ja kasutatavate komponentide kontekstis on mõistlik rakendada.|OK. Nõudeid rakendatakse vastavalt loodava süsteemi eripäradele.|
|meta|1.2|Nõudeid rakendada hierarhia põhimõttel.|RIA MFN-i nõudeid tuleb rakendada kõigis RIA infosüsteemides. Valdkonna MFN määratleb valdkonna tarkvara spetsiifilised nõuded. Hanke MFN-i nõuded täpsustavad ja täiendavad asutuse või valdkonna nõudeid. X-tee tuumtarkvara arendatakse ühiselt Soome riigiga. Vastavalt on ka MFN inglise keeles ja avaldatud Soome partnerasutuse GitHub-repos: [X-Road Non-Functional Requirements](https://github.com/vrk-kpa/xroad-joint-development/blob/master/NFR.md). RIHA nõuded asuvad [arhitektuuriteatmikus](https://arhitektuur.riha.ee/).|OK|
|vorming|2.1|Andmebaasides ja rakendustes kasutada UTF-8 kodeeringut.||OK. Arendaja ja süsteemihalduri vastutus.|
|vorming|2.2|Ühe faili piires kasutada alati sama reavahetuse kodeeringut - kas Windowsi (`CR+LF; 0x0D0A; U+000D U+000A`) või Linux/Unix standardile vastavat (`LF; 0x0A; U+000A`).||OK. Kõik reavahetused vastavalt Linux/Unix standardile. Koodihaldussüsteemi konfiguratsioon.|
|vorming|2.3|Aja esitamisel tekstikujul lähtuda standardist ISO 8601.|___Kuupäevad___ kirjutatakse kujul `AAAA-KK-PP`. Näide: `2. juuni 2012` kirjutada kujul `2012-06-02`.<br>___Kellaajad___ kirjutatakse kujul `hh:mm:ss`, kus `hh` järgib 24-tunnist kellaajaformaati.<br>Millisekundi täpsusega kellaaja teksti kujul esitamisel kasutatakse formaati `hh:mm:ss,nnnn`, kus `nnnn` on millisekundite arv.<br>Kuupäev ja kellaaeg samas andmeväljas esitatakse kujul, kus kuupäevavormingu ja kellaajavorming vahele lisatakse täht `T`.<br> <br>___Ajaintervallide___ kirjeldamiseks kasutatakse kahte sama täpsusega (kuupäev, kellaaeg või kuupäev ja kellaaeg) ajavormingut (algus ja lõpp), mis eraldatakse sümboliga `/`.<br>Vt ka [RFC 3339 Date and Time on the Internet: Timestamps](https://tools.ietf.org/html/rfc3339), kus määratletakse internetiprotokollidele sobiv ISO 8601 profiil. Märkus. Mõned standardid nõuavad aja esitamist [Unix epoch](https://en.wikipedia.org/wiki/Unix_time) vormingus, nt: 1) nt OpenID Connect ja 2) [W3C veebiliidesed](https://w3ctag.github.io/design-principles/#times-and-dates). Märkus. Aja esitamisel inimkasutajale kasutajaliidestes lähtuda vastavas kultuuris omaksvõetud vormingutest.|OK. Hetkel aega ei esitleta|
|litsents|3.1|Tarkvara markeerida litsentsiga.|Teose autoriõigused tuleb selgelt välja tuua. Standardseks vahendiks selleks on litsents. Litsents esitatakse ühel või mõlemal alljärgnevatest viisidest: 1) LICENCE-fail repos; 2) litsentsi tekst iga faili päises. RIA põhimõte on arendada tarkvara avatult ja avaldada tarkvara vaba litsentsiga. Erandid turva- jm õigusega pandud piirangute korral. Soovitatav on kasutada [MIT litsentsi](https://en.wikipedia.org/wiki/MIT_License) - nii tagatakse paremini tarkvarade litsentsiline ühtesobivus. Alternatiiv on [EUPL](https://en.wikipedia.org/wiki/European_Union_Public_Licence).|MIT - Copyright (c) 2022 Estonian Information System Authority|
|litsents|3.2|Tarkvara arendamisel lähtutakse avatuse ja vaba lähtekoodi põhimõttest.|Välja arvatud õigusest tulenevad piirangud (turvameetmed, andmekaitse, ärisaladuses).|OK. Loodav tarkvara on avatud lähtekoodiga.|
|moodulstruktuur|4.1|Rakenduse välissõltuvused peavad olema ilmutatult, selgelt välja toodud.||OK. Kasutatakse Maven sõltuvuste halduse süsteemi, sõltuvused on fikseeritud kindla versiooninumbriga.|
|moodulstruktuur|4.2|Rakendus peab olema väliste süsteemide tõrgete suhtes vastupanuvõimeline (_resilient_).|Välise süsteemi tõrge tohib mõjutada ainult sellest otseselt sõltuvate kasutuslugude toimimist.|OK. Süsteemi arhitektuur arvestab sellega.|
|moodulstruktuur|4.3|Rakendus peab olema tehniliselt tükeldatud vastavalt loogilisele jaotusele. Saadud osised peavad olema eraldi versioneeritavad ja paigaldatavad. Muuhulgas peab andmebaas olema rakendusest eraldi paigaldatav.|Näiteks, kui rakendusel on eraldi turvakontekstidega liidesed ametnikule ja kodanikule, peab rakendus olema jaotatud kaheks eraldi liidesekomponendiks ning nende mõlema poolt kasutatavaks andmebaasiks.|OK. Süsteemi arhitektuur/arendaja vastutus.|
|moodulstruktuur|4.4|Rakenduse funktsionaalsuses tuleb selgelt eraldada avaliku teenuse liides muudest mitteavalikest, sisemistest, konfigureerimis jms. liidestest.||OK. Süsteemi arhitektuur/arendaja vastutus.|
|moodulstruktuur|4.5|Kõik liidesed rakenduse eri osade vahel peavad olema vajadusel kaitstavad kahepoolset tuvastamist ja krüpteerimist võimaldava protokolliga.||Kohaldub osaliselt, täpsustatakse liideste kirjelduses. Erisused tulenevad rakenduse iseloomust.|
|moodulstruktuur|4.6|Rakenduse pakutav(ad) HTTP REST masinliidesed (API-d) kirjeldatakse masinloetavas OpenAPI vormingus.|Masinloetav kirjeldus ei välista täiendavat, paremini inimloetavat vabavormilist kirjeldust.|OK. API on kirjeldatud OpenAPI 3.0.3|
|keel|5.1|Lähtekoodi dokumentatsioon, lähtekood ise ning logiteated peavad olema inglisekeelsed.||OK.|
|keel|5.2|Rakendustes kasutatud eestikeelsetele tekstidele kehtivad infotehnoloogia reeglid Eesti keele ja kultuuri keskkonnas EVS 8:2008.||OK. Arendaja vastutus.|
|testimine|6.1|Lähtekood peab olema varustatud ___ühiktestidega___.||OK. Arendaja vastutus.|
|testimine|6.2|Tarkvara peab olema enne toodangusse paigaldamist läbinud ___turvatestimise___.||OK. Turvatestimise viib läbi kolmas osapool.|
|testimine|6.3|Alates integratsioonitasemest peavad automaattestid olema parameteriseeritud.||TODO: hetkel integratsioonitestid puuduvad|
|testimine|6.4|Automaattestid peavad raporteerima tulemusi inim- ja masinloetaval kujul (näiteks JUnit XML ja HTML).||OK. Junit tulemused raporteeritakse XML ja teksti kujul.|
|testimine|6.5|Automaatteste käivitatakse RIA CI vahendi Jenkins vahendusel.||TODO: RIA Jenkinsi integratsioon puudub. Kuidas lahendada Id-kaardi seotud funktsionaalsuse testimist integreerimist?|
|koodi kvaliteet|7.1|Lõplik kood peab olema läbinud staatilise koodianalüüsi.|Kasutada otstarbekat tööriista: Java puhul [Checkstyle](https://github.com/checkstyle/checkstyle), [PMD](https://pmd.github.io/), [SonarQube](https://www.sonarqube.org/) vms; Javascripti puhul [ESLint](https://eslint.org/). Samuti kasutada arendusredaktoritesse sisseehitatud kontrollijaid.|OK. Checkstyle on Maven ehituse protsessi integreeritud, SQ vastu on kontrollitud versiooni 0.0.3|
|frontend|8.1|Stiiliteave asetada CSS-failidesse.|Stiile ei tohiks sisse kirjutada HTML-teksti, ei `style`-taagide vahelise tekstina ega `style`-atribuutidena.|Mittekohalduv, loodaval süsteemil puudub brauseripõhine graafiline kasutajaliides.|
|frontend|8.2|Mahukate laadilehtede puhul kaaluda [Sass](http://sass-lang.com/)-i kasutamist.|Sass võib suurendada laadilehtede loetavust ja hallatavust.|Mittekohalduv|
|frontend|8.3|Järgida ajakohaseid veebistandardeid.|HTML5, CSS3 jms.|Mittekohalduv|
|frontend|8.4|Rakendus peab töötama veebisirvijates, mis toetavad eID baastarkvara kaht viimast versiooni.|Vt sirvikute loetelu ID-tarkvara abikeskuse lehel [ID-tarkvara paigaldamine](https://installer.id.ee/?lang=est).|Mittekohalduv|
|frontend|8.5|Veebisirvija toe puudumisel andku rakendus veateate.|Kui kasutajaliides, mille poole kasutaja pöördub, ei ole ühilduv kasutatava veebisirvijaga, peab rakendus arusaadaval ja juhendaval viisil sellest kasutajat teavitama.|Mittekohalduv|
|kasutatavus|9.1|Veebirakenduse kasutajaliides peab olema juurdepääsetav. Tuleb täita WCAG 2.1 taseme AA nõuded.|Vt: [Web Content Accessibility Guidelines (WCAG) 2.1](https://www.w3.org/TR/WCAG21/). (Eestikeelne tõlge on v2.0 kohta: [Veebi sisu juurdepääsetavussuunised (WCAG) 2.0](https://www.w3.org/Translations/WCAG20-et/))|Mittekohalduv, loodaval süsteemil puudub brauseripõhine graafiline kasutajaliides.|
|URL-id|10.1|Kasutada selge, ühtse mustriga, inimloetavaid veebiaadresse (URL-e).||Mittekohalduv, loodaval süsteemil puuduvad nähtavad URL-id.|
|URL-id|10.2|Igal lehel peab olema unikaalne veebiaadress.||Mittekohalduv|
|URL-id|10.3|URL ei tohi sisaldada isikuandmeid.|Võimalikud on erandid, kui isikuandmete kaitseks on rakendatud asjakohaseid tehnilisi ja organisatsioonilisi meetmeid. Meetmetega peab tagama kaitse vähemalt järgmiste riskide vastu: isikuandmete lekkimine sirviku ajaloost, HTTP seansi pealtkuulamine, isikuandmete lekkimine vahendusserveri (proxy) logist, isikuandmete lekkimine serveri logist.|Mittekohalduv|
|URL-id|10.4|URL ei tohi sisaldada sessioonivõtit.||Mittekohalduv|
|teated|11.1|Vea- jm teated peavad oleva arusaadavad.|Muuhulgas peab rakendus asendama vaikimisi veateate (`404` vms) lehekülje, kuid säilitama algse HTTP vastuskoodi.|Mittekohalduv. |
|teated|11.2|Veasituatsioonid tuleb varustada ___veakoodidega___. Kasutajale tuleb esitada koos veateatega ka veakood.||TODO: Veasituatsioonides puuduvad veakoodid|
|teated|11.3|Veateated tuleb logida.||OK. Vastavalt süsteemi disainile.|
|koodisüsteemid|12.1|Objektid identifitseerida registrikoodide abil.|Riiklikesse registritesse kantavad objektid (isikud, katastriüksused jne) kantakse andmebaasi nende registrikoodiga, mida täiendab riigiprefiks vastavalt ISO3166-1 Alpha 2 standardile. Näiteks isikute sidumiseks süsteemi kasutajakontoga peab kasutama isikukoodi rahvastikuregistrist.<br>Eesti Vabariigi kodanik identifitseeritakse Eesti Vabariigi poolt väljastatud eIDga. Igasuguse muu identifitseerimisevahendi kasutamine peab olema selgelt põhjendatud.<br>Mittekodanike isikuidentifikaator saadakse järgmisel viisil: `riigikood + sookood + sünniaeg + [ dok_nr \| id_riigis ]`, kus<br>`riigikood` - kolmekohaline ISO 3166-1 Alpha-3 standardile vastav riigi kood<br>`sookood` - soo identifikaator nii nagu Eesti Vabariigi isikukoodis<br>`sünniaeg` - sünniaeg formaadis `YYYYMMDD`<br>`id_riigis` - kui see on olemas, tuleb kasutada isiku koduriigi isikuidentifikaatorit. 16 kohta, 0-polsterdatud vasakult<br>`dok_nr` - kui isiku koduriigis isikuidentifikaatorit ei ole, siis kasutatakse isiku dokumendi numbrit. Dokumendi number, 16 kohta, 0-polsterdatud vasakult.|Mittekohalduv. Loodav süsteem ei tegele selliste andmetega.|
|koodisüsteemid|12.2|Rakendus ei tohi luua uut identiteedisüsteemi. Tuleb tugineda olemasolevatele riiklikele (ID-kaart) või põhiliste op-süsteemide süsteemidele (Kerberos jms).||OK. Kasutatakse id-kaarti ja selle infrastruktuuri (SK LDAP)|
|koodisüsteemid|12.3|Rakendada aadressiandmete süsteemi nõudeid.|Eesti aadressiandmete sisestamisel, kuvamisel ja hoidmisel lähtuda Vabariigi Valitsuse 8. oktoobri 2015. a määrusest nr 103 „Aadressiandmete süsteem“.|Mittekohalduv|
|koodisüsteemid|12.4|Rakendada klassifikaatorite süsteemi nõudeid.|Eesti tegevusalade andmete sisestamisel, kuvamisel ja hoidmisel lähtuda Vabariigi Valitsuse 10. jaanuari 2008. a määrusest nr 11 „Klassifikaatorite süsteem“ ja kasutada EMTAK infosüsteemis kehtivat klassifikaatorit.|Mittekohalduv|
|autentimine|13.1|Väliste kasutajate, so. Eesti Vabariigi residentide ja EL teiste liikmesriikide residentide autentimislahenduse loomisel lähtuda dokumendist [Autentimislahendustele kehtivad nõuded](https://www.ria.ee/sites/default/files/content-editors/EID/autentimislahendustele-kehtivad-nouded.pdf).||Mittekohalduv|
|autentimine|13.2|ID-kaardiga autentimisel ei kasutata serdi edastamise päises side- (`-`) ega alakriipse (`_`).||Mittekohalduv|
|rollihaldus|14.1|Rakenduse mitteavalike osade kasutajate rollid asuvad rakendusevälises LDAP serveris või muus autentimislahenduses. <strike>Süsteem ei tohi realiseerida omaenda rollide haldamist.</strike>||Mittekohalduv|
|väljumine|15.1|Süsteemist väljumine peab toimuma sõnaselgelt, kasutajale arusaadaval ja turvalisel viisil.|Kasutaja saab süsteemist väljuda kahel viisil: tema sessioon on pikem, kui sessiooni pikkuse seadistatav piirväärtus (eraldi määratletavad piirangud kogu sessioonile ning tegevuseta perioodile sessioonis) või kasutaja lõpetab sessiooni enda algatusel.|Mittekohalduv. Loodav süsteem ei sisalda seansihaldust sellisel kujul.|
|väljumine|15.2|Juhul kui rakenduse turvanõuded näevad seda ette, peab olema võimalus koheselt lõpetada kasutaja sessiooni nii, et kasutaja saaks arusaadava ja põhjendatud teate sessiooni lõpetamise kohta.||Mittekohalduv|
|andmebaas|16.1|Andmebaasi kasutaval rakendusel on vähemalt kaks andmebaasikasutajat:<br>`<rakendus>` nimeline andmebaasi skeem kuulub andmebaasi kasutajale `<rakendus>` (roll `db owner`, skeemid ja seal paiknevad objektid kuuluvad sellele kasutajale).<br>`<rakendus>` nimelises andmebaasi skeemis on defineeritud `<rakendus>_app` nimeline kasutaja, kes omab ligipääsu (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) ainult rakenduse käitamiseks vajalikele tabelitele, protseduuridele või funktsioonidele.|Nõue tuleneb eelkõige sellest, et vahel kasutame andmebaaside ""koosmajutamist" s.t erinevate süsteemide või ka ühe süsteemi erinevate komponentide (mikroteenuste) andmebaase hoiame ühes PostgreSQL instantsis. Sellisel juhul on vaja tagada eristatus: iga andmebaas peab olema eraldi skeemis; rakendus ei tohi teise rakenduse skeemile ligi pääseda (suheldakse API-de kaudu); rakendus ei tohi ise skeeme moodustada s.t skeemi tohib moodustada ainult paigaldusprotsess. Ka siis, kui koosmajutust hetkel ei kasutata, on eristamine hea praktika.|OK. Hetkel andmebaas ei ole kasutuses|
|andmebaas|16.2|Ühest andmetabelist teise viitamisel tuleb kasutada välisvõtmeid (_foreign key_). Kõik välisvõtmed peavad olema indekseeritud mitteunikaalse indeksiga ja välisvõtmetena kirjeldatud.||OK. Hetkel andmebaas ei ole kasutuses|
|andmebaas|16.3|Kõigis andmebaasi tabelites peab olema defineeritud `integer`-tüüpi primaarvõti, mis on surrogaatvõti. Primaarvõtmena ei tohi kasutada reaalse eluga seotud andmevälju.||OK. Hetkel andmebaas ei ole kasutuses|
|andmebaas|16.4|Kõik primaarvõtmed (_primary key_) peavad olema indekseeritud unikaalse indeksiga.||OK. Hetkel andmebaas ei ole kasutuses|
|andmebaas|16.5|Kui andmebaasis olevate andmete ISKE tervikluse klass on 2 või kõrgem, siis tuleb kõik klass 2 infot sisaldavad andmebaasi kirjed versioneerida.||Mittekohalduv|
|andmebaas|16.6|Andmebaasi väljade pikkused tuleb andmekirjelduskeeles (DDL-is) kirjeldada sümbolites, mitte baitides.||OK. Hetkel andmebaas ei ole kasutuses|
|andmebaas|16.7|Päringulaused ei tohi sisaldada konstantidena sisse kirjutatud  päringutingimuse võrdlusväärtusi.|Kasutada päringumuutujaid (_variable binding_).|Mittekohalduv|
|andmebaas|16.8|Andmebaasi objektide nimetused peavad olema inglisekeelsed. Nimetused tohivad sisaldada ainult Latin1 (ISO8859-1) kodeeringu tähti `a-z; A-Z`, numbreid `0-9`, ning alakriipsu `_`. Objektide nimetused ei tohi alata numbritega. Andmebaasiobjektide nimed peavad olema semantilised st. objekti tähendust avavad.||OK. Hetkel andmebaas ei ole kasutuses|
|andmebaas|16.9|Rakendus peab olema tabelite [partitsioneerimise](http://en.wikipedia.org/wiki/Partition_%28database%29) suhtes agnostiline st. tabelite partitsioneerimisstruktuuride muutmine ei tohi mõjutada rakenduse tööd.||OK. Hetkel andmebaas ei ole kasutuses|
|andmebaas|16.10|Kasutada rakendusserveri (Tomcat) võimalusi andmebaasiühenduste (JDBC) puulimiseks.|Rakendus ei puuli ise, vaid küsib JNDI abil rakendusserveri puuli aadressi. Nõude eesmärk on jõudluse parem hallatavus.|OK. Hetkel andmebaas ei ole kasutuses|
|logimine|17.1|Rakenduse logimine peab olema organiseeritud kasutades selleks ettenähtud standardseid vahendeid viisil, mis võimaldab rakenduse administraatoril määratleda ja muuta logide väljundit (vähemalt fail, andmebaas, `syslogd`), logimise taset ja logimise formaati.||OK. Logide väljundit saab muuta vastavalt Sl4j võimalustele|
|logimine|17.2|Java rakenduste korral logitakse [SLF4J](vt http://www.slf4j.org) raamistiku abil.|Ühtlustatud selleks, et rakendusi saaks seadistada ühtemoodi.|OK. Kasutatakse SLF4J|
|logimine|17.3|Logid kirjutatakse inglise keeles (välja arvatud kasutajale näidatud teated).||OK.|
|logimine|17.4|Turvalisuse seisukohalt kriitilised sündmused (sisenemine, väljumine, rolli muut(u)mine) ning tegevused, mis toovad kaasa rahalisi või juriidilisi tagajärgi, logitakse eraldi konfigureeritavasse ___turvalogisse___.||TODO: Eraldi turvalogi puudub|
|ehitamine|18.1|Rakenduse (RIA poolt hallatavasse serverisse) pakendamine, paigaldamine, uuendamine, muudatuse taastamine ja testide käivitamine peavad olema automatiseeritud standardse üldkasutatava vahendi abil.|Kasutusel on Maven ja Jenkins.|TODO: Kasutusel Maven, integratsioon RIA Jenkinsiga puutub.|
|ehitamine|18.2|Ehitatud paki nimi peab sisaldama projekti nime ja paki versiooni ning tohib sisaldada ainult tähemärke `[a-z;0-9]` ja `-` (miinus) ja `_` (alakriips) (nt `projektinimi-1_0_23`).|Pakk peab olema keskkonnaagnostiline s.t arendus-, toodangu- jm keskkondade jaoks normaalselt ei tehta eraldi pakke. Tarkvara muutub konkreetse keskkonna osaks pärast keskkonda paigaldamist ja keskkonnas seadistamist.|OK.|
|ehitamine|18.3|Rakendused ehitatakse ja paigaldatakse ainult lähtekoodihoidlast, selle üheselt viidatud harust.||OK.|
|ehitamine|18.4|Kood tarnitakse RIA taristus olevasse reposse. Koodi võib tarnida GitHubi, juhul kui on seadistatud GitHubi repo peegeldamine RIA sisereposse. Kumba meetodit kasutatakse, määrab RIA.||TODO|
|ehitamine|18.5|Lähtekoodi kompileerimine peab olema teostatav ka välisvõrguühenduse puudumise korral. Selle nõude täitmise võimaldamiseks on RIAs kasutusel sisemised tarkvarakomponentide repod.|Vt täpsemalt sisenõuete dokumendist.|TODO: Kasutusel on avalikud Maveni repod, integratsioon RIA repodega puudub|
|ehitamine|18.6|Fat jar-id ei sobi (Java rakendustes).||OK. Kliendi käsurea liides ehitakse nii fat jar-i kui eraldi komponendina. Muud moodulid ainult eraldi komponentidena.|
|ehitamine|18.7|Java rakenduse tööks vajalikud teegid peavad olema rakenduse osa.|Nt PostgreSQL JDBC ohjur.|OK.|
|ehitamine|18.8|Fondid, laadilehed ja Javascripti failid serveerida rakendusest endast.||Mittekohalduv|
|ehitamine|18.9|Toodangusse evitatavas tarkvaras peavad sõltuvuste versioonid olema fikseeritud.|Eesmärgiks on ehitamise korratavus (*repeatable build*). Näiteks: Node.js platvormil toodangusse evitatavate moodulite `package.json` failis, jaotises `dependencies` ei tohi olla versioonimärkeid `^`, `~`, `*`, `x`.|OK.|
|paigaldamine|19.1|Rakendus saadab e-kirju RIA SMTP edastusteenuse kaudu.|Täpsemad nõuded vt SMTP edastusteenuse kirjeldusest.|Mittekohalduv. Loodav süsteem ei saada e-kirju.|
|paigaldamine|19.2|Rakendus peab olema loodud sõltumatuna rakendusserveri tarkvarast.|Rakendust peab olema võimalik konfiguratsioonimuudatuste abil paigaldada teisele samatüübilisele rakendusserverile. Kui see ei ole võimalik tuleb rakendusele luua sobituspaketid põhiliselt kasutatavate rakendusserverite jaoks.|OK. Kasutusel Spring Boost võimaldab paigaldada serverit erinevatele rakendusserveritele (TLS konfiguratsioon peab olema lahendatud väljaspool rakendusserverit - nt Nginx)|
|paigaldamine|19.3|Kõik rakenduse versiooniuuendused (sealhulgas muudatused andmebaasi struktuuris ja koodis) peavad kuni järgmise versiooniuuenduseni olema täielikult tagasi pööratavad st. koos versiooni uuendusega peavad olema loodud vahendid ja kirjeldatud protseduurid versiooniuuenduse tagasi võtmiseks.||OK.|
|paigaldamine|19.4|Rakendus ei tohi eeldada paigalduskeskkonna turvalisust.||?|
|paigaldamine|19.5|Rakendusservereid peab olema võimalik lisada teenust pakkuvasse klastrisse ja sealt eemaldada vastavalt vajadusele.||TODO: Arhitektuur pole veel lõplik|
|paigaldamine|19.6|Rakendus ei tohi kasutada konfigureerimata viiteid failidele või välistele süsteemidele st. kõik viited peavad olema programmikoodi välised.||OK.|
|paigaldamine|19.7|Kõik andmebaasiühendused tuleb kirjeldada täispika URI abil. Java rakendustes kasutatakse JNDI ühendusi.||OK. Hetkel andmebaasi ei kasutata|
|paigaldamine|19.8| Andmebaasi JNDI objekti Datasource-i nimetamisel tuleb kasutada prefiksit `jdbc` ning ühesõnaliste lühendite korral väiketähti. Nt: `jdbc/system1`, `jdbc/system2` jne.||OK. Andmebaasi veel ei kasutata|
|paigaldamine|19.9|Rakenduse andmebaasi või andmeskeemi paigaldamine ei tohi nõuda punktis erilisi kasutajaõigusi.||?|
|infoturve|20.1|Kui ei ole määratud teisiti, peab rakendus olema kasutatav ISKE klassile `K2T2S2` vastavate süsteemide loomisel.|Turvameetmetega tutvu [ISKE portaalis](https://iske.ria.ee).|TODO|
|infoturve|20.2|Süsteem ei tohi võimaldada kasutajale ligipääsu süsteemi toimimise informatsioonile, nagu failide täisnimed, kutsepinud (_stack trace_) jms.||OK. Hea süsteemi disain, arendaja vastutus.|
|infoturve|20.3|Kaitsmata avalik võrguliiklus ei ole lubatud. Igasugune avalik võrguliiklus on krüpteeritud. TLS keskkonna parameetrid on administraatori, mitte arendaja kontrolli all. Erandjuhul, kui edastatav informatsioon ei sisalda konfidentsiaalseid andmeid ega isikuandmeid, on lubatud andmete edastamine krüpteerimata kujul, kuid viisil, mis võimaldab andmete vastu võtjal veenduda saadetise tervikluses st. allkirjastatult või ajatembeldatult (X-tee turvaserveri seadistuse edastamise näide).||OK. Võrguliiklus kliendi ja serveri vahel kasutab TLSi.|
|infoturve|20.4|Vastavalt rakenduse olemusele ja riskianalüüsile rakendada meetmed OWASP ohuedetabelites (Top 10) jm tekstides antud soovituste järgimiseks.|vt [OWASP](https://www.owasp.org) ja [OWASP Application Security Verification Standard (ASVS)](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project).|TODO|
|infoturve|20.5|Kaitsta seansiküpsiseid (`secure` ja `http only` parameetrid).||Mittekohalduv. Seansiküpsiseid ei kasutata.|
|infoturve|20.6|Rakendada päringuvõltsimise (CSRF) vastast kaitset.||TODO: |
|infoturve|20.7|Sisendite kontroll nii front- kui ka backend-is.|Olulised sisendid tuleb kontrollida (puhastada) (ka) serveri poolel.|OK. Võtmeserver teostab sisendi kontrolli.|
|infoturve|20.8|Veebirakendustes määratleda ja rakendada sisuturbepoliitika.|Vt [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).|Mittekohalduv. Loodav süsteem ei ole veebirakendus.|
|infoturve|20.9|Eraldipaigaldatavate komponentide vahelistel liidestel peab olema TLS võimekus (vastastikune autentimine sertide abil). Vastavad konfigureerimisjuhised peavad sisalduma rakenduse paigaldusjuhendis.||OK. Kirjeldatakse üksikasjalikult liideste spetsifikatsioonis ja paigaldusjuhendites.|
|krüpto|21.1|Krüptograafiliste algoritmide ja meetodite valimisel lähtuda kehtivast RIA tellitud [krüptograafiliste algoritmide elutsükli uuringust](https://www.ria.ee/ee/kruptograafiliste-algoritmide-elutsukli-uuringud.html).||TODO|
|krüpto|21.2|Krüptoalgoritme peab olema võimalik väikeste muudatustega vahetada||OK. Loodava lahenduse vorming toetab seda.|
|krüpto|21.3|Võtmete kaitsele tähelepanu!|Juhtida tähelepanu ja rakendada meetmeid vältimaks võtmete lubamatut avalikukstulekut. Näiteid ohupraktikatest (mitteammendav loetelu): 1) võtme hoidmine versioonihalduse (git) all olevas koodirepos -> oht: push-takse avalikusse reposse -> kaitsemeede: `.gitignore` või võtmete hoidmine üldse eraldi; 2) võtmete seisundi ja omaduste ebaselgus -> võtmete segiminek, sellest tulenev kompromiteerumine või kaitse langus -> kaitsemeede: läbimõeldud võtmehalduse protseduur; 3) näite-seadistusfailides ei markeerita näitevõtmeid -> oht: näitevõtmed jõuavad toodangusse. Võtmeid tuleb reeglina kaitsta juba test- ja arenduskeskkondades. Ligipääs võtmetele korraldada teadmisvajaduse (_need to know_) põhimõttel. Võtmed, mida enam ei vajata, koheselt hävitada. Kirjandus: [NIST SP-800-57 Key Management Guidelines](https://csrc.nist.gov/Projects/Key-Management/Key-Management-Guidelines); European Payments Council (2017) [Guidelines on cryptographic algorithms usage and key management](https://www.europeanpaymentscouncil.eu/document-library/guidance-documents/guidelines-cryptographic-algorithms-usage-and-key-management).|TODO: Ühiktestid kasutavad näidisvõtmeid. Lõplik serveri TLS võtmete haldamine sõltub lõplikust arhitektuurist.|
|andmekaitse|22.1|Rakendustes tuleb tagada isikuandmete kaitse nõuded.|Eriti isiku õigus olla unustatud ja meie kohustus seejärel kustutada kõik isikuandmed, mida me ei vaja tööks või mida me ei pea seaduse alusel töötlema. Vt [isikuandmete kaitse üldmäärus](http://eur-lex.europa.eu/legal-content/ET/TXT/?uri=CELEX%3A32016R0679). Samuti peame alati olema valmis vastama isiku nõudmisele välja anda [IKS](https://www.riigiteataja.ee/akt/104012019011?leiaKehtiv#para24) § 24 sätestatud teave.|Loodav süsteem ei talleta isikuandmeid.|
|andmekaitse|22.2|Rakendus ei tohi kasutada RIA taristu väliseid kasutaja tegevust analüüsivaid teenuseid (nt Google Analytics).|Andmekaitse ja turvalisuse kaalutlustel.|OK. Ei kasutata kasutaja tegevust analüüsivaid teenuseid.|
|käideldavus|23.1|Rakendus peab sirvikusse laaduma kiiresti.|Sirvikuühendusi tuleb efektiivselt kasutada. Vajadusel kasutada laadimisaja optimeerimistehnikaid (pakkimine, minimeerimine, profileerimine jm).|Mittekohalduv. Loodav süsteem ei ole veebirakendus.|
|käideldavus|23.2|Kõrgkäideldavuse võimekus. Kui ei lepita kokku eraldi, peab iga eraldipaigaldatav tarkvarakomponent olema paigaldatav mitmes eksemplaris.||TODO: Arhitektuur ei kokku lepitud.|
|käideldavus|23.3|Kõrgkäideldavate rakenduste puhul tuleb seansihalduse lahendus kokku leppida kohe arendusprojekti algul. Seansi hoidmine jagatud failisüsteemis (nt. NFS) ei ole lubatud.||TODO: Arhitektuur ei kokku lepitud.|
|monitooring|24.1|Süsteemi iga eraldi paigaldatav osa peab väljastama  RIA monitooringusüsteemile (näiteks aadressilt `heartbeat.json`) masinloetaval kujul oma nime ja versiooninumbri, oluliste väliste süsteemide oleku, viimase käivitamise aja, pakendamise aja ning serveriaja.||TODO: monitoorimisnõuded ei ole kokku lepitud|

93 nõuet.
</del>