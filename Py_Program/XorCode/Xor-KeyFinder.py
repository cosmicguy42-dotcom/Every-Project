import secrets

msg = "08111f301d16191a147f160d0e1724"
Kmsg =b"CTF{"

msgbyte = bytes.fromhex(msg)
cl = msgbyte[:4]

txt = ""
key = ""


for i in range(4):
    key += chr(cl[i] ^ Kmsg[i])


print(f"The key is {key}")    


