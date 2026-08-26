
msg = "VILCHA WIOJFY WFIA WOLCIOM"
txt = ""

for i in range(1, 27):
    txt = ""

    for c in msg:
        if c == " ":
            txt += " "
        else:
            ac = ord(c)
            nv = ac + i

            if nv > 90:
                nv -= 26

            txt += chr(nv)

    print(f"{txt} -> {i}\n")