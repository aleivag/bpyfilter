"""bpyfilter's logo: bpfilter's, with a snake instead of the bee.

    python3 docs/logo/make_logo.py      # writes logo{,mark}-{light,dark}-mode.svg here

The README shows the PNGs (PyPI can't show the SVGs reliably); after changing the
logo, regenerate them, e.g. with librsvg (transparent background, 2x for HiDPI):

    for f in docs/logo/*.svg; do rsvg-convert -w 720 "$f" -o "${f%.svg}.png"; done

The mark is drawn on bpfilter's logomark grid (2000 wide): the same three bars,
at the same places, with the same 53-unit outline. The snake replaces the bee's
hexagon: its head peeks out above the bars, its tail curls out below them, and
its forked tongue takes the place of the antennae.
"""

LIGHT = {"outline": "#5C1E0F", "red": "#E95738", "green": "#B2CF7D", "body": "#FEDC76",
         "text": "#5C1E0F", "py": "#E95738"}
# bpfilter's dark mode: yellow bars and text, the middle bar left transparent
DARK = {"outline": "#AD4B1D", "red": "#FECF15", "green": "none", "body": "#E58D06",
        "text": "#FECF15", "py": "#E58D06"}
S = 53  # outline width, as in bpfilter's logomark


def bars(c):
    """bpfilter's three bars: red, green, red (outline centered on the edge)."""
    pill = '<rect x="{}" y="{}" width="{}" height="188" rx="94" fill="{}" stroke="{}" stroke-width="%d"/>' % S
    return "\n".join(pill.format(x, y, w, fill, c["outline"]) for x, y, w, fill in (
        (27, 859, 1471, c["red"]),
        (416, 670, 1557, c["green"]),
        (170, 481, 1328, c["red"]),
    ))


def snake(c):
    """Head above the bars (side view, facing right), tail below them; the body
    in between is hidden behind the bars, like the bee's."""
    outline = f'fill="{c["body"]}" stroke="{c["outline"]}" stroke-width="{S}" stroke-linejoin="round"'
    head = ("M 760 600 L 760 330 C 760 200 860 125 1010 130 C 1200 137 1345 200 1405 290 "
            "C 1445 350 1415 412 1340 425 C 1250 442 1135 430 1080 470 L 1080 600 Z")
    tail = ("M 760 950 L 760 1120 C 760 1270 900 1330 1140 1325 C 1430 1318 1645 1210 1765 985 "
            "C 1630 1125 1445 1180 1240 1180 C 1140 1180 1080 1150 1080 1090 L 1080 950 Z")
    eye = (f'<circle cx="1090" cy="255" r="50" fill="{c["outline"]}"/>'
           f'<circle cx="1106" cy="239" r="16" fill="{c["body"]}"/>')
    nostril = f'<circle cx="1345" cy="300" r="13" fill="{c["outline"]}"/>'
    tongue = (f'<path d="M 1415 360 C 1490 360 1540 345 1590 315 M 1590 315 L 1665 250 '
              f'M 1590 315 L 1690 330" fill="none" stroke="{c["outline"]}" stroke-width="{S}" '
              f'stroke-linecap="round" stroke-linejoin="round"/>')
    return f'<path d="{tail}" {outline}/>\n{tongue}\n<path d="{head}" {outline}/>\n{eye}\n{nostril}'


def logomark(c):
    return f"{snake(c)}\n{bars(c)}"


# --- the wordmark: monoline letters with round ends, like bpfilter's -------------------

W, X, A, D = 10, 31, 46, 13         # stroke, x-height, ascender, descender (outer sizes), as bpfilter's
RC = (X - W) / 2                    # bowl radius, at the stroke's center
GAP = 3.5                           # between letters' outer edges


def letters(word, base, colors):
    """(svg, width) of `word` set from x=0, baseline `base`; colors: one per letter."""
    # flat ends: stems run edge to edge; horizontal strokes sit on their centerline
    yc, top, bot = base - X / 2, base - X, base
    asc, desc, bar = base - A, base + D, base - X + W / 2
    out, x = [], 0.0
    for ch, color in zip(word, colors):
        s = x + W / 2               # stem center, for a letter starting at x
        stroke = f'fill="none" stroke="{color}" stroke-width="{W}" stroke-linecap="butt" stroke-linejoin="round"'
        if ch in "bp":
            stem = (s, asc, s, bot) if ch == "b" else (s, top, s, desc)
            d = f"M {stem[0]} {stem[1]} L {stem[2]} {stem[3]}"
            out.append(f'<path d="{d}" {stroke}/><circle cx="{s + RC}" cy="{yc}" r="{RC}" {stroke}/>')
            width = X
        elif ch == "y":
            # arms drawn past the x-height and descender lines, clipped there: flat ends
            k = RC / (bot - top)        # horizontal run per unit of height
            e = W                       # overshoot, cut by the clip
            d = (f"M {s - k * e} {top - e} L {s + RC} {bot} "
                 f"M {s + 2 * RC + k * e} {top - e} L {s + RC - k * (desc - bot + e)} {desc + e}")
            clip = f"y{len(out)}"
            out.append(f'<clipPath id="{clip}"><rect x="{x - W}" y="{top}" width="{X + 2 * W}" '
                       f'height="{desc - top}"/></clipPath><path d="{d}" {stroke} clip-path="url(#{clip})"/>')
            width = X
        elif ch == "f":
            s = x + 0.9 * RC        # the crossbar starts at x
            d = (f"M {s} {bot} L {s} {asc + W / 2 + RC} A {RC} {RC} 0 0 1 {s + RC} {asc + W / 2} "
                 f"L {s + RC + 3} {asc + W / 2} M {s - 0.9 * RC} {bar} L {s + 1.1 * RC} {bar}")
            out.append(f'<path d="{d}" {stroke}/>')
            width = 1.9 * RC + 3
        elif ch == "i":
            out.append(f'<path d="M {s} {top} L {s} {bot}" {stroke}/>'
                       f'<circle cx="{s}" cy="{base - A + W * 0.6}" r="{W * 0.62}" fill="{color}"/>')
            width = W
        elif ch == "l":
            out.append(f'<path d="M {s} {asc} L {s} {bot}" {stroke}/>')
            width = W
        elif ch == "t":
            s = x + 0.9 * RC
            d = (f"M {s} {asc + 7} L {s} {bot - W / 2 - RC} A {RC} {RC} 0 0 0 {s + RC} {bot - W / 2} "
                 f"L {s + RC + 2} {bot - W / 2} M {s - 0.9 * RC} {bar} L {s + 1.1 * RC} {bar}")
            out.append(f'<path d="{d}" {stroke}/>')
            width = 1.9 * RC + 2
        elif ch == "e":
            cx = x + X / 2
            d = (f"M {cx - RC} {yc} L {cx + RC} {yc} A {RC} {RC} 0 1 0 "
                 f"{cx + RC * 0.72} {yc + RC * 0.69}")
            out.append(f'<path d="{d}" {stroke}/>')
            width = X
        elif ch == "r":
            d = f"M {s} {top} L {s} {bot} M {s} {yc + 3} A {RC} {RC} 0 0 1 {s + RC} {bar} L {s + RC + 3} {bar}"
            out.append(f'<path d="{d}" {stroke}/>')
            width = W / 2 + RC + 3
        x += width + GAP
    return "\n".join(out), x - GAP


def svg(body, width, height):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" '
            f'width="{width:.0f}" height="{height:.0f}">\n{body}\n</svg>\n')


def full_logo(c, scale=0.16):
    """The mark, scaled like bpfilter's logo (320 wide), with "bpyfilter" under it."""
    word = "bpyfilter"
    colors = [c["text"]] + [c["py"]] * 2 + [c["text"]] * 6
    text, text_w = letters(word, base=0, colors=colors)
    mark_w, mark_h = 2000 * scale, 1360 * scale
    width = max(mark_w, text_w) + 10
    base = mark_h + 12 + A
    height = base + D + 4
    mark = f'<g transform="translate({(width - mark_w) / 2:.1f} 2) scale({scale})">\n{logomark(c)}\n</g>'
    words = f'<g transform="translate({(width - text_w) / 2:.1f} {base:.1f})">\n{text}\n</g>'
    return svg(f"{mark}\n{words}", width, height)


if __name__ == "__main__":
    from pathlib import Path

    here = Path(__file__).resolve().parent
    for mode, colors in (("light", LIGHT), ("dark", DARK)):
        (here / f"logomark-{mode}-mode.svg").write_text(svg(logomark(colors), 2000, 1360))
        (here / f"logo-{mode}-mode.svg").write_text(full_logo(colors))
    print("wrote logo-{light,dark}-mode.svg logomark-{light,dark}-mode.svg")
