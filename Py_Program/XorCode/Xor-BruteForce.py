import secrets

msg = "28110f101d49090a143f0e0d3c1704"
msgbyte = bytes.fromhex(msg)


for key in range(256):
    txt = ""

    for c in msgbyte:
        txt += chr(key ^ c)
         
    
    if "CTF{" in txt:
        print(f"Reponce: \n key: {key} \n msg: {txt}")



