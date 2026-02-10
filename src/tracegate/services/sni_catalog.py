from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SniCatalogEntry:
    fqdn: str
    providers: list[str]
    note: str | None


_RAW = r"""
stats.vk-portal.net - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
sun6-21.userapi.com - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
sun6-20.userapi.com - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
avatars.mds.yandex.net
queuev4.vk.com - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
sun6-22.userapi.com - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
sync.browser.yandex.net
top-fwz1.mail.ru
ad.mail.ru
eh.vk.com - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
akashi.vk-portal.net - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
sun9-38.userapi.com
st.ozone.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
ir.ozone.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
vt-1.ozone.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
io.ozone.ru
ozone.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
xapi.ozon.ru
top-fwz1.mail.ru
strm-rad-23.strm.yandex.net
online.sberbank.ru
esa-res.online.sberbank.ru
egress.yandex.net
st.okcdn.ru
rs.mail.ru
counter.yadro.ru
742231.ms.ok.ru
splitter.wb.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
a.wb.ru - работает на МТС.
user-geo-data.wildberries.ru
banners-website.wildberries.ru
chat-prod.wildberries.ru
servicepipe.ru
alfabank.ru - работает на МТС, Мегафон, Т2, Yota.
statad.ru
alfabank.servicecdn.ru
alfabank.st
ad.adriver.ru
privacy-cs.mail.ru
imgproxy.cdn-tinkoff.ru
mddc.tinkoff.ru
le.tbank.ru
hrc.tbank.ru
id.tbank.ru
rap.skcrtxr.com
eye.targetads.io
px.adhigh.net
top-fwz1.mail.ru
nspk.ru
sba.yandex.net - работает на МТС, Мегафон.
identitystatic.mts.ru
tag.a.mts.ru
login.mts.ru
serving.a.mts.ru
cm.a.mts.ru
login.vk.com - работает на МТС, Мегафон, Т2, Тмобайл, РТК.
api.a.mts.ru
mtscdn.ru
d5de4k0ri8jba7ucdbt6.apigw.yandexcloud.net
moscow.megafon.ru
api.mindbox.ru
web-static.mindbox.ru
storage.yandexcloud.net
personalization-web-stable.mindbox.ru
www.t2.ru
beeline.api.flocktory.com
static.beeline.ru
moskva.beeline.ru
wcm.weborama-tech.ru
1013a--ma--8935--cp199.stbid.ru
msk.t2.ru
s3.t2.ru
get4click.ru
dzen.ru - работает на Мегафон, Т2.
yastatic.net
csp.yandex.net
sntr.avito.ru
yabro-wbplugin.edadeal.yandex.ru
cdn.uxfeedback.ru
goya.rutube.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК.
api.expf.ru
fb-cdn.premier.one
www.kinopoisk.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
widgets.kinopoisk.ru
payment-widget.plus.kinopoisk.ru
api.events.plus.yandex.net
tns-counter.ru
speller.yandex.net - работает на МТС, Мегафон, Т2, Тмобайл, РТК, Yota.
widgets.cbonds.ru
www.magnit.com
magnit-ru.injector.3ebra.net
jsons.injector.3ebra.net
2gis.ru
d-assets.2gis.ru
s1.bss.2gis.com
www.tbank.ru
strm-spbmiran-08.strm.yandex.net
id.tbank.ru
tmsg.tbank.ru
vk.com - работает на МТС, Мегафон, Т2, Тмобайл, РТК.
www.wildberries.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК.
www.ozon.ru - работает на МТС, Мегафон, Т2, Тмобайл, РТК.
ok.ru - работает на МТС, Мегафон.
yandex.ru - работает на МТС, Мегафон, Т2.
"""


_PROVIDER_MAP = {
    "мтс": "mts",
    "мегафон": "megafon",
    "т2": "t2",
    "тмобайл": "tmobile",
    "ртк": "rtk",
    "yota": "yota",
    "билайн": "beeline",
    "beeline": "beeline",
}


def _parse_providers(note: str) -> list[str]:
    # "работает на МТС, Мегафон, Т2, ..."
    m = re.search(r"работает на (.+)", note, flags=re.IGNORECASE)
    if not m:
        return []
    raw = m.group(1).strip().rstrip(".")
    out: list[str] = []
    for part in raw.split(","):
        key = part.strip().lower()
        code = _PROVIDER_MAP.get(key)
        if code and code not in out:
            out.append(code)
    return out


def load_default_catalog() -> list[SniCatalogEntry]:
    entries: dict[str, SniCatalogEntry] = {}
    for raw_line in _RAW.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue

        fqdn: str
        note: str | None
        if " - " in line:
            fqdn, note = line.split(" - ", 1)
            fqdn = fqdn.strip()
            note = note.strip() or None
        else:
            fqdn, note = line, None

        providers = _parse_providers(note or "")
        key = fqdn.lower()
        if key in entries:
            prev = entries[key]
            merged_providers = sorted(set(prev.providers).union(providers))
            merged_note = prev.note or note
            entries[key] = SniCatalogEntry(fqdn=prev.fqdn, providers=merged_providers, note=merged_note)
        else:
            entries[key] = SniCatalogEntry(fqdn=fqdn, providers=providers, note=note)

    # Stable ordering for deterministic inserts.
    return [entries[k] for k in sorted(entries.keys())]

