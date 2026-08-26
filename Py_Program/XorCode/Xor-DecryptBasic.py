import secrets


msg = "08111f301d16191a147f160d0e1724"

msgbyte = bytes.fromhex(msg)
txt = ""
dekey = b"kEY"


for i in range(len(msgbyte)):
    oKey = dekey[i % 3]
    omsg = msgbyte[i]

    txt += chr(omsg ^ oKey)



print(f"The flag is : {txt}")    

