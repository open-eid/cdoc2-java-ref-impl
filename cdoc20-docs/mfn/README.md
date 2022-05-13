# RIA MFN ja nende lahendamine CDOC 2.0 projektis

MFN on algselt defineeritud https://e-gov.github.io/MFN

MFN asub genereeritud failis `MFN.md`. Ära muuda seda faili käsitsi!

MFN lähteandmed on defineeritud failis `jekyll/_data/Nouded.yml`. Lähteandmete formaat on järgmine:

```
- kategooria:
  nimetus: <kategooria nimetus>
  nouded:
    - nr: <nr>
      son: <nõude sõnastus>
      sel: <nõude selgitus>
      lah: <lahendus>
```

Markdown formaadis MFN dokumendi genereerimiseks vajalikud tööriistad:
* `ruby/ruby-dev`
* `jekyll`

Genereerimiseks käivita `generate.sh` või käsud:
1. `jekyll b -s jekyll -d jekyll/_site`
1. `mv jekyll/_site/index.html ./MFN.md`
