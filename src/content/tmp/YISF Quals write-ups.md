---
title: YISF Quals REV write-ups
published: 2025-08-13
description: '순천향대학교 청소년 정보보호 페스티벌 예선 풀이'
image: ''
tags: ["rev", "CTF"]
category: 'Write-ups'
draft: false 
lang: ''
---

# Preface

YISF 예선전을 치뤘다.  
금요일 19시부터 일요일 9시까지라는 파격적인 대회시간이 개학 전 아주 치명적이였지만, 리버싱 올솔과 본선 진출을 해냈으니 그냥 기분 좋게 끝맞혔다.

6위했다.

<img src='/YISFquals/scoreboard.png'>

다른 분야 문제는 GPT가 쉽게 풀어주는 문제들만 풀었기에 리버싱 문제들만 롸업을 작성해보았다.

# jump

코드를 어셈블리로 본다면 0x1582 부분에서 jnz로 코드를 뛰어넘어버려서 잘못된 플래그가 출력되고 있는 모습을 어렵지 않게 볼 수 있다.  

```asm
.text:0000000000001582 nop
.text:0000000000001583 nop
```
nop으로 패치하면 실행파일이 플래그를 출력하는 파일로 바뀐다.

flag: `YISF{we1C0Me_TO_yI5F__rEv3rS3_3NgINe3riN9}`

# Verifier

```py
import hashlib
import itertools
import string
s_targets = [
    "3355b58b97617985ad032226043d3008c5dc915288326e0074654ba344f5b471",
    "d2c2198d191d3c2f14bba11fe2bb4396bd1dfb7d3df32b70e472d15a72eed13f",
    "74515ecf40255d006ecaca61026235e0694b9916be6fbdd62c4581d58664b5b4",
    "a77b3237cb73acfb0e31f93694398f8e7dc158edb14552cbede81d9bf3839e86"
]
unk_2139 = bytes.fromhex("CF51C3EE7F41B6D")
charset = string.ascii_letters + string.digits

def find_block(target_hash):
    for cand in itertools.product(charset, repeat=4):
        block = ''.join(cand)
        h = hashlib.sha256(block.encode()).hexdigest()
        if h == target_hash:
            return block
    return None

blocks = [find_block(t) for t in s_targets]

v_ints = [int.from_bytes(b.encode(), 'little') for b in blocks]
key = sum(v_ints) & 0xffffffff
# print(f"Key = {key:#x}")

name_bytes = bytearray(8)
for i in range(8):
    name_bytes[i] = unk_2139[i] ^ ((key >> (8*(i%4))) & 0xff)
name = name_bytes.decode()
print("Name:", name)
serial = "-".join(blocks)
print("Serial:", serial)
```
딱히 설명이 필요없는 문제이다.

Name: y15f2025  
Serial: 312a-91ac-41ca-5132

flag: `YISF{6eb5632b9271329694aa196d7f27eb0ccd653407bfa45271efe86433747c02f75a761b8c35a62a48bade6853b9fd46f43b82edaf9d53e939388202634f541da9}`

# too many functions

단순하게 함수들이 길게 늘어져있는데 pwntools로 추출해서 capstone으로 파싱하여 분석해서 역산하였다.

```py
pairs = [
    (0x1A0, 0x8B8B2D176D477353), (0x198, 0x2B8F27938F2B278F),
    (0x190, 0x918F892D81278927), (0x188, 0x8B8B8F8D23272B83),
    (0x180, 0x852B8F8D8B8B2B2D), (0x178, 0x938D27298D819183),
    (0x170, 0x2D8B258393239185), (0x168, 0x852B858D93852D27),
    (0x160, 0x858D2D9191258987), (0x158, 0x85938F27278D2591),
    (0x150, 0x8323838989812525), (0x148, 0x87238993252D2D8B),
    (0x140, 0x2D91298985278F25), (0x138, 0x272D2B8B91892993),
    (0x130, 0x278329938B8D878D), (0x128, 0x9127298D2785858B),
    (0x122, 0x1B23912D29259127),
]
buf = bytearray(0x86)
base = 0x1A0
for off, val in pairs:
    idx = base - off
    chunk = val.to_bytes(8, 'little')
for i, b in enumerate(chunk):
    j = idx + i
    if 0 <= j < len(buf):
        buf[j] = b
target = list(buf)

from capstone import *
from pwn import *

context.log_level = 'error'

elf = ELF('./too_many_functions')
data = elf.read(0x0000000000478727, 0x59D6A7-0x478727)

md = Cs(CS_ARCH_X86, CS_MODE_64)
calling = []
for insn in md.disasm(data, 0x478727):
    # print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
    if insn.mnemonic == 'call':
    calling.append(insn.op_str)
    calling = calling[::-1]  # 뒤집기

op = []
for i in range(len(calling)):
    off = int(calling[i], 16)
    data = elf.read(off, 150)
# print(off)
for insn in md.disasm(data, off):
    if insn.mnemonic == 'shl':
        op.append(('rol', int(insn.op_str.split(', ')[1], 16) & 7))
        break
    elif insn.mnemonic == 'shr':
        op.append(('rol', (8-int(insn.op_str.split(', ')[1], 16))&7))
        break
    elif insn.mnemonic == 'xor':
        op.append(('xor', int(insn.op_str.split(', ')[1], 16)))
        break
assert len(op) == len(calling)

def rol(buf, sh):
    return [ ((x >> sh) | (x << (8-sh))) & 0xff for x in buf ]
def xor_v(buf, v):
    return [ (x ^ v) & 0xff for x in buf ]

for opcode, v in op:
    if opcode == 'xor':
        target = xor_v(target, v)
    if opcode == 'rol':
        target = rol(target, v)

# print(bytes(target))
print(bytes(target).decode())
```
flag: `YISF{f557ce79c7ec4c0f4781eca6755fe5567e21806dc6928a91b5fcf2962e234b88f628b6cc792bb0441a15ffb94a3b7c24d8f9d485efc63659d1c522c6dc8bdf8a}`

# ANGRybird

전형적인 오토리버싱 문제이지만 조금 연산 루틴이 파싱하기 까다롭게 생겼다.  
인텐은 그냥 문제 이름처럼 angr를 사용하는 문제인 것 같다.  
하지만 나는 '예선이고~ 그냥 capstone으로 좀 하면 풀리겠지~ 코딩 실력 상승도 되고 그냥 capstone으로 해보자'라는 안일한 생각을 가지고 연산을 파싱하기 시작했다. 

너무 후회한다.

일단 풀이 방식은 연산 어셈블리를 다 파싱한 후 input 부분을 z3 심볼로 바꾸어 똑같은 연산을 진행, 그 후 솔버에 던지는 방식이다.

```py
from pwn import *
from capstone import *
import base64
from z3 import *

md = Cs(CS_ARCH_X86, CS_MODE_64)
context.log_level = 'debug'
p = remote("211.229.232.98", 20401)
p.recvuntil(b'HELP ME!!\n')


def eval_lea_expr_quick(mem_expr: str, reg: dict) -> BitVecRef:
    inner = mem_expr.strip()[1:-1]
    val = eval(inner, {"__builtins__": None}, reg)
    if is_bv(val):
        return val & BitVecVal(0xFF, 8)
    return BitVecVal(int(val) & 0xFF, 8)


for i in range(50):
    p.recvline()
    data = base64.b64decode(p.recvline()[:-1])
    with open('./prob', 'wb') as f:
        f.write(data)

    elf = ELF('./prob')
    main = 0x00000000000010E0
    code = elf.read(main, 0x200)

    length = None
    off = 0
    start = 1
    inp = 0
    l = 0

    for insn in md.disasm(code, main):
        opcode = insn.mnemonic
        if start and opcode == 'lea':
            inp = int(insn.op_str.split(' + ')[1][:-1], 16)
            start = 0
        if opcode == 'cmp':
            length = int(insn.op_str.split(', ')[1], 16)
            l = length
            off = insn.address + 4
            break

    code = elf.read(off, 0x200)
    op = []
    instr = ""

    for insn in md.disasm(code, off):
        mnem = insn.mnemonic
        if mnem in ('je', 'jz', 'jne', 'jnz', 'js'):
            br = 'je' if mnem in ('je', 'jz') else ('jne' if mnem in ('jne', 'jnz') else 'js')
            block = instr
            if br == 'je':
                block = block.replace('test', 'test(je)').replace('cmp', 'cmp')
            elif br == 'js':
                block = block.replace('test', 'test(js)').replace('cmp', 'cmp(js)')
            op.append((block, br))
            instr = ''
            length -= 1
            continue
        instr += f"{insn.mnemonic} {insn.op_str}\n"
        if length == -1 or insn.mnemonic == 'call':
            break

    op = op[1:]
    inp = 0 if inp >= 0x100 else inp
    print(len(op), inp)

    for i in range(len(op)):
        block, br = op[i]
        block = block.replace('byte ptr [rsp]', 'input[0]') \
                     .replace('byte ptr [rsp + ', 'input[') \
                     .replace('eax', 'al').replace('edx', 'dl') \
                     .replace('rax', 'al').replace('ax', 'al') \
                     .replace('ecx', 'cl').replace('rcx', 'cl') \
                     .replace('esi', 'sil').replace('rsi', 'sil') \
                     .replace('rdx', 'dl')
        op[i] = (block, br)

    print('\n'.join(b for b, _ in op))

    reg = {'al': BitVecVal(0, 8), 'dl': BitVecVal(0, 8), 'cl': BitVecVal(0, 8), 'sil': BitVecVal(0, 8)}
    s = Solver()
    a = [BitVec(f'a{i}', 8) for i in range(l)]
    for bit in a:
        s.add(bit >= 0x20)
        s.add(bit < 0x7f)

    def bv8(x):
        return x if is_bv(x) else BitVecVal(int(x) & 0xFF, 8)

    chked = []

    def opval(tok):
        if tok.startswith('input[') and tok.endswith(']'):
            off = int(tok[6:-1], 0) - inp
            chked.append(off)
            return a[off]
        return reg[tok] if tok in reg else BitVecVal(int(tok, 0), 8)

    for i, (block, br) in enumerate(op):
        lines = block.strip().split('\n')
        idx = int(lines[0].split('[')[1].split(']')[0], 0) - inp
        chked.append(idx)
        has_explicit_cmp_test = any(l.startswith(('cmp', 'test', 'test(je)', 'cmp(js)', 'test(js)')) for l in lines[1:])
        last_zf = None
        last_block = (i == len(op) - 1)

        if len(lines) == 1 and lines[0].split(' ')[0] == 'cmp':
            s.add(a[idx] == BitVecVal(int(lines[0].split(', ')[1], 0), 8))
            continue
        if len(lines) == 1 and lines[0].split(' ')[0] == 'test':
            s.add((a[idx] & BitVecVal(int(lines[0].split(', ')[1], 0), 8)) == BitVecVal(0, 8))
            continue
        if len(lines) == 1 and lines[0].split(' ')[0] == 'test(je)':
            s.add((a[idx] & BitVecVal(int(lines[0].split(', ')[1], 0), 8)) != BitVecVal(0, 8))
            continue

        tmp = lines[0].split(' ', 1)[1].split(', ')[0]
        reg[tmp] = a[idx]

        for line in lines[1:]:
            opcode, rest = line.split(' ', 1)
            if ',' in rest:
                lreg, rstr = rest.split(', ')
            else:
                lreg = rest

            if opcode in ('mov', 'movzx'):
                reg[lreg] = bv8(opval(rstr))
            elif opcode == 'rol':
                reg[lreg] = RotateLeft(bv8(reg[lreg]), int(rstr, 0))
            elif opcode == 'ror':
                reg[lreg] = RotateRight(bv8(reg[lreg]), int(rstr, 0))
            elif opcode == 'shl':
                reg[lreg] = (bv8(reg[lreg]) << int(rstr, 0)) & BitVecVal(0xFF, 8)
                last_zf = lreg
            elif opcode == 'shr':
                reg[lreg] = LShR(bv8(reg[lreg]), int(rstr, 0)) & BitVecVal(0xFF, 8)
                last_zf = lreg
            elif opcode == 'xor':
                reg[lreg] = (bv8(reg[lreg]) ^ bv8(opval(rstr))) & BitVecVal(0xFF, 8)
                last_zf = lreg
            elif opcode == 'sub':
                reg[lreg] = (bv8(reg[lreg]) - bv8(opval(rstr))) & BitVecVal(0xFF, 8)
                last_zf = lreg
            elif opcode == 'add':
                reg[lreg] = (bv8(reg[lreg]) + bv8(opval(rstr))) & BitVecVal(0xFF, 8)
                last_zf = lreg
            elif opcode == 'and':
                reg[lreg] = bv8(reg[lreg]) & bv8(opval(rstr))
                last_zf = lreg
            elif opcode == 'or':
                reg[lreg] = bv8(reg[lreg]) | bv8(opval(rstr))
                last_zf = lreg
            elif opcode == 'not':
                reg[lreg] = ~bv8(reg[lreg]) & BitVecVal(0xFF, 8)
            elif opcode == 'lea':
                reg[lreg] = eval_lea_expr_quick(rstr, reg)
            elif opcode in ('cmp', 'cmp(js)'):
                rhs = bv8(opval(rstr))
                if last_block:
                    s.add(bv8(reg[lreg]) == rhs)
                else:
                    if opcode == 'cmp':
                        s.add(bv8(reg[lreg]) == rhs)
                    else:
                        s.add(((bv8(reg[lreg]) - rhs) & BitVecVal(0x80, 8)) == BitVecVal(0, 8))
                has_explicit_cmp_test = True
            elif opcode in ('test', 'test(je)', 'test(js)'):
                mask = bv8(opval(rstr))
                if opcode == 'test':
                    s.add((bv8(reg[lreg]) & mask) == BitVecVal(0, 8))
                elif opcode == 'test(je)':
                    s.add((bv8(reg[lreg]) & mask) != BitVecVal(0, 8))
                else:
                    s.add(((bv8(reg[lreg]) & mask) & BitVecVal(0x80, 8)) == BitVecVal(0, 8))
                has_explicit_cmp_test = True

        if not has_explicit_cmp_test:
            target_reg = last_zf if last_zf is not None else tmp
            if last_block:
                s.add(bv8(reg[target_reg]) == BitVecVal(0, 8))
            else:
                if br == 'je':
                    s.add(bv8(reg[target_reg]) != BitVecVal(0, 8))
                elif br == 'jne':
                    s.add(bv8(reg[target_reg]) == BitVecVal(0, 8))
                elif br == 'js':
                    s.add((bv8(reg[target_reg]) & BitVecVal(0x80, 8)) == BitVecVal(0, 8))

    print(chked)
    for i in range(l):
        if i in chked:
            continue
        s.add(a[i] == BitVecVal(ord(' '), 8))

    assert (s.check() == sat)
    m = s.model()
    sol = [m.eval(v).as_long() for v in a]
    p.sendlineafter(b'INPUT> ', bytes(sol))
    p.recvline()
    p.recvline()
    p.interactive()
```

<img src='/YISFquals/autorev.png'>

flag: `YISF{d1d_y0u_kn0w_4n6rrrrr?}`

# Microcode

VM이 너무 더럽게 생겼길래 GPT를 줬더니 풀어주었다.

[https://chatgpt.com/share/68992487-06e0-8013-afd4-1fe178b49017](https://chatgpt.com/share/68992487-06e0-8013-afd4-1fe178b49017)

flag: `YISF{9718067c22f31112cbcbdf9a2a33e07af74e443d561fdedf4c0404de3bb333740235921b611316a16b3c14b02b4e6043557ea006fe638d768f2c86e12b625ec7}`

# Hidden Camera

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pathlib import Path

KEY_STR = "aZ8bY7cX6dW5eV4fU3gT2hS1iR0jQ9kP8lO7mN6nM5oL4pK3jI2qH1rG_F-E+D_C@B_A"
KEY = bytes([ord(KEY_STR[(7*i + 13) % len(KEY_STR)]) for i in range(16)])

IV_BASE = b"YISFYISFYISFYISF"
IV = bytes([b ^ 0xAE for b in IV_BASE])

enc_path = 'firmware.bin.enc'
data = Path(enc_path).read_bytes()
cipher = AES.new(KEY, AES.MODE_CBC, IV)
plain = unpad(cipher.decrypt(data), 16)
out_path = enc_path[:-4] if enc_path.endswith(".enc") else enc_path + ".dec"
Path(out_path).write_bytes(plain)
```

가볍게 decrypt 시켜주면 squashfs 파일을 얻을 수도 있다.

`unsquashfs -d rootfs firmware.bin`로 해제 시켜준다.

여기서 많은 파일이 나오는 데 무엇을 분석해야할지 모르겠어서 헤맸다.  
하지만 ping, busybox 빼곤 아무 정보도 없기 때문에 그걸 분석하면 된다.(ping만 분석하면 된다.)


