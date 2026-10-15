"""Generate SVG figures for the Word article into figures.html (rendered to PNG by render_figures.js)."""
import os

FONT = "'Liberation Serif','Times New Roman',serif"
INK, INK2, INK3 = "#16191d", "#3d444d", "#6b737d"
GRAY, BLUE, ORANGE = "#aeb6bf", "#1f57b5", "#d0571b"
BLUE_BG, ORANGE_BG, BLUE_LT = "#eef3fb", "#fdf1ea", "#dbe6f7"
W = 620
CW = 520  # ширина диаграмм


def num(v, d=0):
    v = v + (1e-9 if v > 0 else 0)
    s = f"{v:,.{d}f}".replace(",", " ").replace(".", ",")
    return s


def t(x, y, s, size=13, anchor="start", fill=INK, weight="normal", italic=False):
    st = ' font-style="italic"' if italic else ""
    return (f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}" fill="{fill}" '
            f'font-weight="{weight}"{st}>{s}</text>')


def svg(h, body, fid, w=W):
    return (f'<div class="fig" id="{fid}"><svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}" font-family="{FONT}">{body}</svg></div>')


def bar(x, y, w, h, fill, r=3):
    if w <= r:
        return f'<rect x="{x}" y="{y}" width="{max(w,1.5)}" height="{h}" fill="{fill}"/>'
    return (f'<path d="M{x} {y} H{x+w-r} a{r} {r} 0 0 1 {r} {r} V{y+h-r} a{r} {r} 0 0 1 -{r} {r} H{x} Z" '
            f'fill="{fill}"/>')


SUB = lambda base, sub: f'{base}<tspan font-size="9" dy="3">{sub}</tspan><tspan dy="-3"></tspan>'
DEFS = (f'<defs><marker id="a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" '
        f'orient="auto-start-reverse"><path d="M0 0L8 4L0 8z" fill="{INK2}"/></marker>'
        f'<marker id="b" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" '
        f'orient="auto-start-reverse"><path d="M0 0L8 4L0 8z" fill="{BLUE}"/></marker></defs>')


def arrow(x1, y1, x2, y2, blue=False, dashed=False):
    c, m = (BLUE, "b") if blue else (INK2, "a")
    d = ' stroke-dasharray="4 3"' if dashed else ""
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" stroke-width="1.4"{d} '
            f'marker-end="url(#{m})"/>')


def box(x, y, w, h, stroke=GRAY, fill="#fff", sw=1.2, r=6):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'


# ---------- Рисунок 1: архитектура ----------
def fig_arch():
    b = [DEFS]
    b += [box(0.6, 40, 95, 62), t(48, 60, "Открытые", 12.5, "middle", weight="bold"),
          t(48, 75, "ключи", 12.5, "middle", weight="bold"), t(48, 91, "pk" + "", 12, "middle", INK2)]
    b[-1] = f'<text x="48" y="92" font-size="12" text-anchor="middle" fill="{INK2}" font-style="italic">pk<tspan font-size="9" dy="3">cl</tspan><tspan dy="-3">, pk</tspan><tspan font-size="9" dy="3">pq</tspan></text>'
    b.append(arrow(96, 71, 113, 71))
    b += [box(115, 18, 140, 104, BLUE, BLUE_BG, 1.4), t(185, 34, "Гибридный KEM", 12.5, "middle", BLUE, "bold"),
          box(122, 42, 126, 32), t(185, 63, "X25519 (ECDH)", 12.5, "middle", weight="bold"),
          box(122, 81, 126, 32, BLUE), t(185, 102, "ML-KEM-768", 12.5, "middle", BLUE, "bold")]
    b.append(arrow(255, 71, 298, 71, blue=True))
    b.append(f'<text x="277" y="62" font-size="11" text-anchor="middle" fill="{BLUE}" font-style="italic">K<tspan font-size="8" dy="3">cl</tspan><tspan dy="-3">, K</tspan><tspan font-size="8" dy="3">pq</tspan></text>')
    b += [f'<rect x="300" y="38" width="170" height="66" rx="6" fill="{BLUE}"/>',
          t(385, 58, "HKDF-SHA256", 13.5, "middle", "#fff", "bold"),
          t(385, 76, "salt = info = метка домена", 11, "middle", "#dbe6f7"),
          f'<text x="385" y="94" font-size="10.5" text-anchor="middle" fill="#dbe6f7" font-style="italic">IKM = len ‖ K<tspan font-size="8" dy="3">cl</tspan><tspan dy="-3"> ‖ len ‖ K</tspan><tspan font-size="8" dy="3">pq</tspan></text>']
    b.append(arrow(385, 104, 385, 148, blue=True))
    b.append(t(392, 131, "DEK, 256 бит", 11.5, fill=BLUE))
    b.append(f'<path d="M185 18 V6 H557 V148" fill="none" stroke="{INK2}" stroke-width="1.2" stroke-dasharray="4 3" marker-end="url(#a)"/>')
    b.append(f'<text x="550" y="24" font-size="11.5" text-anchor="end" fill="{INK2}" font-style="italic">C<tspan font-size="8" dy="3">cl</tspan><tspan dy="-3"> ‖ C</tspan><tspan font-size="8" dy="3">pq</tspan></text>')
    # row 2
    b += [box(0.6, 150, 95, 54), t(48, 172, "Цифровой", 12.5, "middle", weight="bold"),
          t(48, 188, "актив", 12.5, "middle", weight="bold")]
    b.append(arrow(96, 177, 113, 177))
    b += [box(115, 150, 152, 54, ORANGE, ORANGE_BG, 1.4), t(191, 171, "Сжатие", 13, "middle", "#a83f0c", "bold"),
          t(191, 189, "ZSTD / LZ4 / GZIP / FOURIER", 10.5, "middle", INK2),
          t(191, 222, "нет выигрыша → NONE", 11, "middle", INK3, italic=True)]
    b.append(arrow(267, 177, 298, 177))
    b += [box(300, 150, 170, 54, BLUE, "#fff", 1.4), t(385, 171, "AES-256-GCM", 13, "middle", weight="bold"),
          t(385, 189, "nonce 12 Б, тег 16 Б", 11, "middle", INK2)]
    b.append(arrow(470, 177, 494, 177))
    b += [f'<rect x="496" y="150" width="123" height="54" rx="6" fill="{INK}"/>',
          t(557, 171, "Контейнер", 13, "middle", "#fff", "bold"), t(557, 189, "EncryptedMessage", 11, "middle", "#c9ced4")]
    b.append(arrow(557, 204, 557, 243))
    b += [box(470, 245, 149, 50, ORANGE, "#fff", 1.4), t(544, 265, "Гибридная подпись", 12.5, "middle", weight="bold"),
          t(544, 283, "Ed25519 ‖ ML-DSA-65", 11, "middle", INK2)]
    b.append(arrow(470, 270, 422, 270))
    b += [box(300, 245, 120, 50), t(360, 265, "Хранилище", 12.5, "middle", weight="bold"),
          t(360, 283, "Data-at-Rest", 11, "middle", INK2, italic=True)]
    return svg(300, "".join(b), "fig1")


# ---------- Рисунок 2: формат контейнера ----------
def fig_wire():
    fields = [("Ver", "1 Б", 44, "#eef1f4", INK), ("KemAlg", "1 Б", 58, "#eef1f4", INK),
              ("CompAlg", "1 Б", 62, "#eef1f4", INK), ("KEM len", "4 Б", 62, "#eef1f4", INK),
              ("Инкапсуляции KEM", "C_X25519 ‖ C_ML-KEM", 170, BLUE_LT, BLUE), ("Nonce", "12 Б", 56, "#eef1f4", INK),
              ("Шифротекст", "сжатый актив", 108, INK, "#fff"), ("Tag", "16 Б", 58, "#eef1f4", INK)]
    b, x = [], 0.6
    xs = []
    for name, sz, w, fill, col in fields:
        xs.append(x)
        b.append(f'<rect x="{x}" y="44" width="{w-2}" height="48" fill="{fill}"/>')
        b.append(t(x + w / 2 - 1, 64, name, 12, "middle", col, "bold"))
        if sz.startswith("C_"):
            b.append(f'<text x="{x+w/2-1}" y="82" font-size="11" text-anchor="middle" fill="{col}" font-style="italic">C<tspan font-size="8" dy="3">X25519</tspan><tspan dy="-3"> ‖ C</tspan><tspan font-size="8" dy="3">ML-KEM</tspan></text>')
        else:
            b.append(t(x + w / 2 - 1, 82, sz, 11, "middle", col if col == "#fff" else INK2))
        x += w
    xs.append(x)

    def brace(x1, x2, label):
        return (f'<path d="M{x1+2} 36 V30 H{x2-4} V36" fill="none" stroke="{INK3}" stroke-width="1"/>'
                + t((x1 + x2) / 2, 22, label, 11.5, "middle", INK2))
    b.append(brace(xs[0], xs[4], "Заголовок, 7 Б"))
    b.append(brace(xs[4], xs[5], "32 + 1088 Б (ML-KEM-768)"))
    b.append(brace(xs[5], xs[8], "Выход AES-256-GCM"))
    b.append(t(310, 116, "Байтовые поля фиксированной длины и префикс длины исключают неоднозначность разбора", 11, "middle", INK3, italic=True))
    return svg(124, "".join(b), "fig2")


# ---------- столбчатые диаграммы ----------
def hbars(fid, rows, vmax, title, label_w=120, unit_fmt=lambda v: num(v), area=None, row_h=30, bar_h=16):
    area = area or (CW - label_w - 120)
    h = 34 + row_h * len(rows) + 6
    b = [t(0, 14, title, 11.5, fill=INK3, weight="bold")]
    b.append(f'<line x1="{label_w}" y1="26" x2="{label_w}" y2="{h-4}" stroke="{INK3}" stroke-width="1"/>')
    for i, (name, v, color, note, bold) in enumerate(rows):
        y = 34 + i * row_h
        w = area * v / vmax
        b.append(t(label_w - 8, y + bar_h - 3, name, 13, "end", BLUE if color == BLUE and bold else (("#a83f0c") if color == ORANGE else INK), "bold" if bold else "normal"))
        b.append(bar(label_w, y, w, bar_h, color))
        lab = f'<tspan font-weight="{"bold" if bold else "normal"}">{unit_fmt(v)}</tspan>'
        if note:
            lab += f'<tspan fill="{INK3}">  {note}</tspan>'
        b.append(f'<text x="{label_w + w + 6}" y="{y + bar_h - 3}" font-size="12.5" fill="{INK}">{lab}</text>')
    return svg(h, "".join(b), fid, CW)


def fig_text():
    rows = [("Без сжатия", 23675, GRAY, "", False), ("ZSTD", 1239, BLUE, "−94,8 %", False),
            ("GZIP", 1320, BLUE, "−94,4 %", False), ("LZ4", 1322, BLUE, "−94,4 %", False),
            ("FOURIER", 3256, ORANGE, "−86,2 %", True)]
    return hbars("fig3", rows, 23675, "РАЗМЕР КОНТЕЙНЕРА, БАЙТ (МЕНЬШЕ — ЛУЧШЕ)")


def fig_telemetry():
    rows = [("Без сжатия", 50000, GRAY, "", False), ("LZ4", 46500, BLUE, "−7 %", False),
            ("GZIP", 42800, BLUE, "−14 %", False), ("ZSTD", 39200, BLUE, "−21 %", False),
            ("FOURIER", 14350, ORANGE, "−71 %", True)]
    return hbars("fig4", rows, 50000, "РАЗМЕР ПОСЛЕ СЖАТИЯ, БАЙТ (МЕНЬШЕ — ЛУЧШЕ)")


def fig_cycle():
    data = [("ZSTD", 1.03, 0.72), ("LZ4", 0.96, 0.68), ("FOURIER", 1.09, 0.72)]
    lw, area, vmax = 100, 340, 1.2
    b = [t(0, 14, "ВРЕМЯ ЦИКЛА «ШИФРОВАНИЕ + РАСШИФРОВАНИЕ», МС", 11.5, fill=INK3, weight="bold")]
    b += [bar(lw, 26, 14, 12, GRAY, 0), t(lw + 20, 36, "без сжатия", 12, fill=INK2),
          bar(lw + 120, 26, 14, 12, BLUE, 0), t(lw + 140, 36, "со сжатием", 12, fill=INK2)]
    y0 = 52
    for k in range(0, 7):
        v = k * 0.2
        x = lw + area * v / vmax
        b.append(f'<line x1="{x}" y1="{y0-4}" x2="{x}" y2="{y0+3*52-6}" stroke="#e3e6ea" stroke-width="1"/>')
        b.append(t(x, y0 + 3 * 52 + 8, num(v, 1), 11, "middle", INK3))
    for i, (name, a, c) in enumerate(data):
        y = y0 + i * 52
        b.append(t(lw - 8, y + 24, name, 13, "end", "#a83f0c" if name == "FOURIER" else INK, "bold" if name == "FOURIER" else "normal"))
        b.append(bar(lw, y, area * a / vmax, 16, GRAY))
        b.append(t(lw + area * a / vmax + 6, y + 13, num(a, 2), 12.5))
        b.append(bar(lw, y + 20, area * c / vmax, 16, BLUE))
        d = round((1 - c / a) * 100)
        b.append(f'<text x="{lw + area * c / vmax + 6}" y="{y + 33}" font-size="12.5" fill="{INK}"><tspan font-weight="bold">{num(c, 2)}</tspan><tspan fill="{BLUE}" font-weight="bold">  −{d} %</tspan></text>')
    b.append(f'<line x1="{lw}" y1="{y0-4}" x2="{lw}" y2="{y0+3*52-6}" stroke="{INK3}" stroke-width="1"/>')
    return svg(y0 + 3 * 52 + 14, "".join(b), "fig5", CW)


def fig_tps():
    data = [("X25519", "(классика)", 15200, GRAY), ("Гибрид", "без сжатия", 4100, BLUE),
            ("Гибрид", "+ ZSTD", 4850, BLUE), ("Гибрид", "+ LZ4", 5300, BLUE)]
    h, top, base, lw = 230, 30, 180, 70
    area_h, vmax = base - top, 16000
    b = [t(0, 14, "ПРОПУСКНАЯ СПОСОБНОСТЬ, ОПЕРАЦИЙ/С (БОЛЬШЕ — ЛУЧШЕ)", 11.5, fill=INK3, weight="bold")]
    for v in range(0, 16001, 4000):
        y = base - area_h * v / vmax
        b.append(f'<line x1="{lw}" y1="{y}" x2="{CW-10}" y2="{y}" stroke="{"#e3e6ea" if v else INK3}" stroke-width="1"/>')
        b.append(t(lw - 8, y + 4, num(v), 11, "end", INK3))
    slot = (CW - 10 - lw) / 4
    for i, (n1, n2, v, c) in enumerate(data):
        x = lw + slot * i + slot / 2
        hh = area_h * v / vmax
        b.append(f'<path d="M{x-34} {base} V{base-hh+3} a3 3 0 0 1 3 -3 H{x+31} a3 3 0 0 1 3 3 V{base} Z" fill="{c}"/>')
        b.append(t(x, base - hh - 6, num(v), 13, "middle", INK, "bold"))
        b.append(t(x, base + 18, n1, 12.5, "middle"))
        b.append(t(x, base + 34, n2, 12, "middle", INK2))
    return svg(h, "".join(b), "fig6", CW)


def fig_sigsize():
    rows = [("Ed25519", 64, GRAY, "классика", False), ("ML-DSA-65", 3309, BLUE, "FIPS 204", False),
            ("Ed25519 + ML-DSA-65", 3381, ORANGE, "64 + 3309 + 8", True)]
    return hbars("figX", rows, 3381, "РАЗМЕР ПОДПИСИ, БАЙТ", label_w=150, area=270)


def fig_latency():
    rows = [("RSA-2048", 0.968, 0.0367, GRAY), ("ECDSA P-256", 0.115, 0.364, GRAY), ("Ed25519", 0.447, 0.453, GRAY),
            ("ML-DSA-44", 0.110, 0.0339, BLUE), ("ML-DSA-65", 0.175, 0.0547, BLUE), ("ML-DSA-87", 0.218, 0.0874, BLUE),
            ("Ed25519 + ML-DSA-65", 0.630, 0.510, ORANGE), ("ECDSA + ML-DSA-65", 0.294, 0.422, ORANGE),
            ("RSA + ML-DSA-65", 1.16, 0.0927, ORANGE)]
    lw, pw, gap = 150, 160, 40
    x1, x2 = lw, lw + pw + gap
    sc = 150 / 1.2  # px per ms
    rh, y0 = 24, 56
    b = [bar(0, 4, 14, 12, GRAY, 0), t(20, 14, "классика", 12, fill=INK2),
         bar(100, 4, 14, 12, BLUE, 0), t(120, 14, "PQC (FIPS 204)", 12, fill=INK2),
         bar(240, 4, 14, 12, ORANGE, 0), t(260, 14, "гибрид", 12, fill=INK2),
         t(x1, 42, "а) формирование, мс", 12.5, fill=INK, weight="bold"),
         t(x2, 42, "б) проверка, мс", 12.5, fill=INK, weight="bold")]
    for i, (name, s, v, c) in enumerate(rows):
        y = y0 + i * rh
        col = BLUE if c == BLUE else ("#a83f0c" if c == ORANGE else INK)
        b.append(t(lw - 8, y + 13, name, 12.5, "end", col))
        for x, val in ((x1, s), (x2, v)):
            w = sc * val
            b.append(bar(x, y + 1, w, 14, c))
            d = 3 if val < 0.1 else 2
            b.append(t(x + w + 5, y + 13, num(val, d), 12))
    for x in (x1, x2):
        b.append(f'<line x1="{x}" y1="{y0-4}" x2="{x}" y2="{y0+9*rh}" stroke="{INK3}" stroke-width="1"/>')
    return svg(y0 + 9 * rh + 6, "".join(b), "fig7", CW)


figs = [fig_arch(), fig_wire(), fig_text(), fig_telemetry(), fig_cycle(), fig_tps(), fig_latency()]
html = ('<!doctype html><html><head><meta charset="utf-8"><style>body{margin:0;background:#fff}'
        '.fig{display:inline-block;padding:6px;background:#fff}</style></head><body>' + "".join(figs) + "</body></html>")
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures.html")
open(out, "w", encoding="utf-8").write(html)
print("ok", out)
