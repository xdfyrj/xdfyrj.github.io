---
title: CCE 2025 Final Write-ups
published: 2025-10-06
description: 한 달 지난 CCE 롸업
tags: ["rev", "CTF"]
category: Write-ups
draft: false
---

지난 9월 11일, 2025 사이버공격방어대회 본선이 막을 내렸다.  
나는 청소년부 3등이라는 좋은 경험을 하고 시상식도 갔다 왔다.

나는 총 2문제를 팀원들과 함께 풀었다.  
지금 보면 혼자서는 절대 못 풀었을 것 같다.  
좋은 팀에 들어와서 수상까지 하니 기쁘다.

이제 내가 푼 리버싱 문제 풀이를 설명해보도록 하겠다.

:::warning
한 달이나 지나서 설명이 부족하다.
:::

# 국방본부

바이너리가 많이 크지 않고 파일 복호화 문제는 많이 풀어봤기 때문에 시도해보았다.

파일을 암호화 하는 로직을 분석해본다면 다음과 같다는 것을 알 수 있다.

1. `head` 작성
- `ChaCha20_XOR(key=k, nonce=IV1, counter=0, name + IV2 + SHA256(data))`
2. `main` 작성
- `ChaCha20_XOR(key=k, nonce=IV2, counter=0, data)`
3. `tail` 작성
- `RSA_enc(N, e=65537, SHA256(name) + SHA256(IV2) + IV1 + k)`

여기서 IV1, IV2는 12B에 모든 바이트가 동일하다.  
data는 파일 전체 내용을 의미한다.

## nonce 값 복구

이때, header에 적힌 nonce와 이를 암호화하는데 사용된 keystream의 nonce값은 다르
다. 즉, defence.png의 header을 encrypt하는데 사용된 nonce를 nonce1, header에 적힌
nonce를 nonce2, flag.png의 header을 encrypt하는데 사용된 nonce를 nonce3, header
에 적힌 nonce를 nonce4라 하자. 또한, 각각 사용된 key를 key1, key2라 하자. 바이너리와 두 png 파일의 헤더를 분석한 결과, 사용된 keystream이 같다는 것을 확인
하였다. 즉, key1과 key2는 같고, nonce1, nonce3또한 같다(앞으로 key와 nonce1로 서
술).
따라서, header 자체를 암호화하는데 사용된 keystream은 같으므로, 파일 이름
'defence.png'와 'flag.png' 길이 차이를 이용해 nonce2와 nonce4 값을 복구할 수 있다
(여기서 사용된 것은 nonce를 생성할 때 취약점으로 인해 모든 바이트 값이 같다는 것
이다).
현재 nonce1의 값은 모르는 상태이고, nonce2와 nonce4의 값은 알고있다.

아래 코드를 통해 값을 확인해가며 nonce를 찾아내었다.
```py
a = b'defence.png'
b = b'flag.png'
# a = b'defence.png\xf8\xf8\xf8\xf8\xf8\xf8\xf8\xf8\xf8\xf8'
# b = b'flag.png\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c'

flag_png = "BC 93 39 A3 93 02 A2 27 E0 D0 90 BB 2C 6E F9 CA 1C B7 2C 57 FA B9 A4 63 65 83 1B D2 9E 80 BD 89 1A 85 A0 FE 02 AF 3C D3 E6 51 3A 38 F7 F3 3C 20".split()
defence_png = "BE 9A 3E A1 D3 11 A9 6E CC E2 AB 1F 88 CA 5D 6E B8 13 88 F3 6E 92 2B 33 C2 C8 14 DC E6 DC 60 36 43 E5 98 D2 23 F5 B9 D5 20 D9 30 63 D6 6D A5 A1".split()

for j in range(0, min(len(a), len(b))):
    print(j, end=' ')
    # print(a[j], end=' ')
    print(a[j]^int(defence_png[j], 16), end=' ')
    print(b[j]^int(flag_png[j], 16))
```

## Key 복구
마지막 부분을 encrypt할 때를 보면, 파일이름의 SHA256값, nonce2 또는 nonce4의 SHA256값, nonce1값, key값을 이어 붙여 계산을 한다.  
하지만 여기서 nonce1값과 key값이 동일하므로, 결국 두 plaintext의 차이는 X와 X+y의 꼴로 표현될 수 있다.  
이는 **related message attack**에 취약하다.  
각각의 바이트 길이를 구한 후 이 점을 이용해 수식을 세워보면, $x^{65537}-c1 = 0\; mod\; N$ 과 $(x+y)^{65537}-c2=0\;mod\;N$이다. 이 두 식은 모두 $x$를 공통해를 가지므로, gcd를 통해 $x$의 값을 복구할 수 있다.  

related message attack을 사용하는 코드는 우리팀 대황크립토마스터초록프사단 히히망함씨가 갖고 있기 때문에 첨부를 못하였다.

$x$로부터 nonce1, key의 값을 모두 복구할 수 있고(nonce1 또한 같은 바이트로 이루어져있는 것을 확인), key와 nonce1을 구하면 복호화 스크립트는 어렵지 않게 짤 수 있다.

아래는 복호화 Python 코드이다.
```py
from pathlib import Path
from Crypto.Cipher import ChaCha20

KEY_HEX = "fe3201004fa05a3ac464174cf9e321af8e04fd4e4e3f3c5c2723b7be644a6f04"
NONCE   = b"\x5c" * 12
INFILE  = "flag.png.CCE2025"
OUTFILE = "flag.png"

def find_body(blob: bytes) -> bytes:
    marker = b"CCE2025"
    i1 = blob.find(marker)
    i2 = blob.find(marker, i1 + len(marker))
    return blob[i1 + len(marker) : i2]

blob = Path(INFILE).read_bytes()
body_ct = find_body(blob)

key = bytes.fromhex(KEY_HEX)
cipher = ChaCha20.new(key=key, nonce=NONCE)
body_pt = cipher.encrypt(body_ct)

Path(OUTFILE).write_bytes(body_pt)
```

크립토 잘하는 사람이 팀에 있어서 다행이다.  
뭔가 문제 같이 푸는 재미가 혼자서 씨름 하는 것보다 더 재밌는 것 같다.

# 석유공사

apk 파일이 주어진다.

adroid studio로 실행을 해보니, 뭔가 플래그 관련 부분은 보이지 않았다.  
하지만 같은 팀의 웹이 java 분석이 조금 되서 나에게 is_admin 값이 True인 계정이 있으면 무언가를 검사한다는 정보를 알려주었다.

또 is_admin 값이 True인 계정의 id와 pw와 VM opcode를 나에게 주었고, 나는 VM을 분석하여 플래그를 획득하였다.

```py
from typing import List, Tuple

MOD = 1 << 32
MASK = MOD - 1
A = 1103515245
A_INV = pow(A, -1, MOD)  # 4005161829

def parse_opcodes(code: str) -> List[Tuple[int, int]]:
    ops = []
    for ln in code.strip().splitlines():
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split()
        op = int(parts[0])
        arg = int(parts[1]) if len(parts) > 1 else 0
        ops.append((op, arg))
    return ops

def invert_value(ops: List[Tuple[int, int]], y: int) -> int:
    """y = f(x0)를 만족하는 x0를 역산(Val/Exit 제외 역순 적용)."""
    x = y & MASK
    # 마지막에서 첫 번째까지 역순 순회
    for op, v in reversed(ops):
        if op == 8:      # Exit: 무시
            continue
        elif op == 7:    # Xor v
            x = (x ^ v) & MASK
        elif op == 2:    # Add v  -> Sub v
            x = (x - v) & MASK
        elif op == 3:    # Sub v  -> Add v
            x = (x + v) & MASK
        elif op == 4:    # Aff b: x=A*x+b  ->  x=A_INV*(x-b)
            x = (A_INV * ((x - v) & MASK)) & MASK
        elif op == 1:    # Val: 시작지점 도달
            break
        elif op in (5, 6):
            raise ValueError("Shl/Shr가 포함되어 역변환이 결정적이지 않습니다.")
        else:
            raise ValueError(f"Unknown opcode {op}")
    return x

opcodes = '1\n4 19\n2 33\n7 74\n2 123\n4 14\n2 42\n7 85\n3 456\n3 77\n4 1\n2 34\n7 27\n2 38\n7 891\n3 9\n7 2\n2 1\n4 4\n3 567\n7 75\n2 1\n3 14\n4 234\n7 8\n2 42\n3 24\n4 19\n7 678\n7 0\n2 77\n3 55\n7 1\n3 789\n2 1\n7 2\n2 345\n4 1\n3 2\n2 17\n7 2\n4 456\n2 5\n4 2\n7 7\n8\n'
opcodes = parse_opcodes(opcodes)
print(invert_value(opcodes, 766847841))
```

결과 입력 검증 창에 `959231641`를 입력하면 플래그가 나온다.

<img src="/cce2025final/apkresult.png">

# 소감

한 문제도 온전히 내 힘으로 풀지 못해서 조금 아쉬운 감이 있었다.  
live fire도 좀만 더 잘했으면 2등인 건데 하는 아쉬움도 있지만 수상에 만족한다.

좋은 팀원 만나서 좋은 대회에 가 상도 타보는 좋은 경험이었다.

