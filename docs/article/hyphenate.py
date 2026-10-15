"""Insert soft hyphens into Russian body text (Chromium ships no ru hyphenation dictionary)."""
import re, sys, pyphen

dic = pyphen.Pyphen(lang="ru_RU")
src, dst = sys.argv[1], sys.argv[2]
html = open(src, encoding="utf-8").read()
head, body = html.split("<body>", 1)
parts = re.split(r"(<svg.*?</svg>)", body, flags=re.S)
word = re.compile(r"[А-Яа-яЁё]{7,}")
for i in range(0, len(parts), 2):
    parts[i] = re.sub(r">([^<]+)<", lambda m: ">" + word.sub(lambda w: dic.inserted(w.group(0), hyphen="­"), m.group(1)) + "<", parts[i])
open(dst, "w", encoding="utf-8").write(head + "<body>" + "".join(parts))
