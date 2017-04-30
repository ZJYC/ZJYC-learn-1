
while(True):
    Input=str(input("\r\nPlease input HEX stream\r\n"))
    if len(Input) % 2 != 0:
        print("The string you input was incorrect")
        continue
    Input = Input.upper()
    for i in range(0,len(Input)//2):
        if i % 8 == 0:print("");
        print("%s%s"%(Input[i*2],Input[i*2+1]),end=" ")
