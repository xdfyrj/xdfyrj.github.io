---
title: Codegate 2025 Quals Write-ups
published: 2025-04-15
description: codegate write-ups
tags: ["rev", "CTF"]
category: Write-ups
draft: false
---

# Preface
코드게이트 2025 예선을 치뤘다.   
최종적으론 16위에 랭크되었고, 총 7문제를 풀이하였다.   
평소 분야 편식이 심하여 포너블과 웹 쉬운 문제를 못 푼 것이 좀 아쉬웠지만 본선을 간 것에 만족한다.

<img src="/codegate2025/scoreboard.png">

문제는 전형적이었던 것 같다.   
조금 더 공부할 필요가 있다고 느끼게 된 대회였다.

# Hello Codegate

코드게이트 디스코드 시작 공지에 적혀있다.

플래그: `codegate2025{65782695e16255e3ef8517a1bfb059f0}`

# Capcha World

문제가 너무 빠르게 풀리길래 먼저 풀었다.

그냥 WSL에서 nc로 접속 후 보이는 문자열을 입력하면 된다.

10라운드만 보내면 됨.

<img src="/codegate2025/capcha.png">

플래그: `codegate2025{4445996c1f4cc11f9fb7eabe177d4988952dc112d768b8baf17076c0d30a10124aaee8b64682a53fab5d07bd31fff8}`

# Encrypted flag

## Me:

```python
from Crypto.Util.number import bytes_to_long, getPrime
from sympy import nextprime
import gmpy2

p = getPrime(512)
q = nextprime(p)

n = p * q
e = 65537

flag = "codegate2025{FAKE_FLAG}"
phi = (p - 1) * (q - 1)

d = gmpy2.invert(e, phi)

m = bytes_to_long(flag.encode())
c = pow(m, e, n)

print(f"n: {n}")
print(f"e: {e}")
print("Encrypted flag:", c)

# n : 54756668623799501273661800933882720939597900879404357288428999230135977601404008182853528728891571108755011292680747299434740465591780820742049958146587060456010412555357258580332452401727868163734930952912198058084689974208638547280827744839358100210581026805806202017050750775163530268755846782825700533559
# e : 65537
# Encrypted flag : 7728462678531582833823897705285786444161591728459008932472145620845644046450565339835113761143563943610957661838221298240392904711373063097593852621109599751303613112679036572669474191827826084312984251873831287143585154570193022386338846894677372327190250188401045072251858178782348567776180411588467032159

```

write the python code to find the correct flag

## ChagGPT:

Below is one way to break this RSA instance using Fermat’s factorization (which works well here since the primes are consecutive). In this code, we factorize nnn to recover ppp and qqq, compute ϕ(n)\phi(n)ϕ(n), derive the private exponent ddd, and then decrypt ccc to obtain the flag.

```python
from math import isqrt
from Crypto.Util.number import long_to_bytes
import gmpy2

# Given RSA parameters:
n = 54756668623799501273661800933882720939597900879404357288428999230135977601404008182853528728891571108755011292680747299434740465591780820742049958146587060456010412555357258580332452401727868163734930952912198058084689974208638547280827744839358100210581026805806202017050750775163530268755846782825700533559
e = 65537
c = 7728462678531582833823897705285786444161591728459008932472145620845644046450565339835113761143563943610957661838221298240392904711373063097593852621109599751303613112679036572669474191827826084312984251873831287143585154570193022386338846894677372327190250188401045072251858178782348567776180411588467032159

# Since q is the immediate prime after p, p and q are very close.
# We can use Fermat's factorization method to find them.
a = isqrt(n)
if a * a < n:
    a += 1

while True:
    b2 = a * a - n
    b = isqrt(b2)
    if b * b == b2:
        break
    a += 1

p = a - b
q = a + b

# Calculate the Euler totient function
phi = (p - 1) * (q - 1)

# Compute the modular inverse of e modulo phi to get d
d = int(gmpy2.invert(e, phi))

# Decrypt the ciphertext
m = pow(c, d, n)

# Convert the resulting number back to bytes (the flag)
flag = long_to_bytes(m)
print(flag.decode())

```

### How the code works:

1. **Fermat Factorization:**p=a−bandq=a+b
    
    We compute a=⌈n⌉a = \lceil \sqrt{n} \rceila=⌈n⌉ and then look for a bbb such that a2−n=b2a^2 - n = b^2a2−n=b2. When found, we have:
    
    p=a−bandq=a+bp = a - b \quad \text{and} \quad q = a + b
    
2. **Key Recovery:**
    
    Once ppp and qqq are known, we compute ϕ(n)=(p−1)(q−1)\phi(n) = (p-1)(q-1)ϕ(n)=(p−1)(q−1) and then determine the private key exponent ddd as the modular inverse of eee modulo ϕ(n)\phi(n)ϕ(n).
    
3. **Decryption:**
    
    The original message mmm is recovered by computing m=cdmod  nm = c^d \mod nm=cdmodn, and then it’s converted back into a string using `long_to_bytes`.
    

Running this script should reveal the flag.

--- 

플래그: `codegate2025{Cl0se_p_q_0f_RSA_Is_Vu1n3rabIe}`

# initial

쉽다. 다음 글자로 xor하고 마지막 글자에 xor된 0번 idx로 xor을 해준다.

<img src="/codegate2025/initial.png">

따라서 xor된 0번 idx의 값을 브루트 포싱 가능하므로 역연산이 가능하다.

```python
cmp = list(bytes.fromhex("36E22E866D24CD941A1A469B4983611520B247EA0D42E93DE4741B168B542EAA"))
Sbox = list(bytes.fromhex("45B81A8047CBD6191D5856E236E42765B173E95C7E427CDE7161F648F522571BAFDB8D8BC02BD4A1CCF2EBBE3738D91E63E34D9413BA9C861035FC4FD7D37B3AC98FD024F1052C535E8C963DA6A46ECF5B6D04ED127A172534DCADE120917506C4746F78006CC2ABA99FB0163390CDB23CAA9B514E3F1C50FA18E8B454B93B49F9B6999D7D0E66EFFF1597550FF8212E83F3950AA8BC5DB532FDF7D82689642FA7CA0DECC3FBACB709EE8492790107A2774A026039A093BD88C6E5E7CE23BBDF85C159EAD29AE63114FEC544118767D14BDA6A52BF0BF45A8A0828A37F30709E2D0C82AE40684376E03E8E2A4CA5D56972C8816B46C7B31F5F9829F06203DD41"))
def rol(a1, n):
    return ((a1 << n) | (a1 >> (8-n))) & 0xff
flag = bytearray(32)
for i in range(32):
    flag[i] = Sbox.index(rol(cmp[i], i & 6))
save = bytearray(flag)
for byte in range(0x100):
    flag[-1] ^= byte
    for i in range(31, 0, -1):
        # print(i)
        flag[i-1] ^= flag[i]
    if b'code' in bytes(flag):
        print(bytes(flag).decode())
    flag = save[:]
    
# codegate2025{Hell0_W0r1d_R3V_^^}
```

플래그: `codegate2025{Hell0_W0r1d_R3V_^^}`

# Ping Tester

`127.0.0.1; cat flag`를 하니까 되었다.

<img src="/codegate2025/ping.png">

플래그: `codegate2025{80fd12690c4d31a8cf3fe2865e3ceb99aca9e6047c6acb2cbb9157e26ec91f4b}`

# WebBinary

wasm file과 js 파일이 주어진다.

나는 wasm 문제에서 항상 ghidra wasm plugin을 쓰는 편이다.

[사용법](https://xdfyrj.github.io/posts/wasmplugin/)

```c

undefined4 export::main(undefined4 param1,undefined4 param2)

{
  undefined4 uVar1;
  
  uVar1 = unnamed_function_7();
  return uVar1;
}
```

메인 함수다

```c
undefined4 unnamed_function_7(void)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  byte *local_370 [4];
  byte *local_360 [3];
  int local_354;
  int local_350;
  byte *local_34c;
  char local_347 [4];
  byte local_343;
  byte local_342;
  byte local_341;
  int local_340;
  int local_33c;
  int local_338;
  int local_334;
  char local_330 [304];
  char local_200 [304];
  byte local_d0;
  undefined4 local_4;
  
  local_4 = 0;
  memory_fill(0,200,0,&local_d0);
  memory_fill(0,300,0,local_200);
  memory_copy(0,0,300,0x10000,local_330);
  local_360[0] = &local_d0;
  unnamed_function_10(0x10152,local_360);
  local_334 = unnamed_function_14(&local_d0);
  local_338 = 0;
  local_33c = 0;
  local_340 = 0;
  local_34c = &local_d0;
  while (iVar2 = local_334, iVar1 = local_33c, local_334 = local_334 + -1, iVar2 != 0) {
    pbVar3 = local_34c + 1;
    local_33c = local_33c + 1;
    (&local_343)[iVar1] = *local_34c;
    local_34c = pbVar3;
    if (local_33c == 3) {
      local_347[0] = (char)((int)(local_343 & 0xfc) >> 2);
      local_347[1] = (char)((local_343 & 3) << 4) + (char)((int)(local_342 & 0xf0) >> 4);
      local_347[2] = (char)((local_342 & 0xf) << 2) + (char)((int)(local_341 & 0xc0) >> 6);
      local_347[3] = local_341 & 0x3f;
      for (local_33c = 0; iVar1 = local_340, local_33c < 4; local_33c = local_33c + 1) {
        local_340 = local_340 + 1;
        local_200[iVar1] = local_347[local_33c];
      }
      local_33c = 0;
    }
  }
  if (local_33c != 0) {
    for (local_350 = local_33c; local_350 < 3; local_350 = local_350 + 1) {
      (&local_343)[local_350] = 0;
    }
    local_347[0] = (char)((int)(local_343 & 0xfc) >> 2);
    local_347[1] = (char)((local_343 & 3) << 4) + (char)((int)(local_342 & 0xf0) >> 4);
    local_347[2] = (char)((local_342 & 0xf) << 2) + (char)((int)(local_341 & 0xc0) >> 6);
    local_347[3] = local_341 & 0x3f;
    for (local_354 = 0; iVar1 = local_340, local_354 < local_33c + 1; local_354 = local_354 + 1) {
      local_340 = local_340 + 1;
      local_200[iVar1] = local_347[local_354];
    }
  }
  local_338 = local_340;
  if (local_340 == 43) {
    for (local_33c = 0; local_33c < 0x2c; local_33c = local_33c + 1) {
      if (local_200[local_33c] != local_330[local_33c]) {
        printf(0x10180,0);
        return 0;
      }
    }
    local_370[0] = &local_d0;
    printf(s_codegate2025{%s}_ram_0001016e,local_370);
  }
  else {
    printf(0x10180,0);
  }
  return 0;
}

```

이상한게 막 있지만 대충 codegate 플래그 포맷에 Wrong도 else 이용해서 출력하는 것을 보니 flag checker인 것을 알 수 있다. 비교 배열이 local_330인데 그건 맨처음 0x10000에서 memory_copy를 한다. 귀찮아서 cmp 배열과 GPT에 넣었다.

solve code by GPT

```python
def reverse_operation(encoded: bytes) -> bytes:
    """
    주어진 인코딩된 6비트 값(bytes 객체)을 역으로 디코딩하여 원본 바이트열을 반환합니다.
    인코딩 방식:
      - 3바이트를 4개의 6비트 값으로 변환:
          e0 = (byte0 & 0xfc) >> 2
          e1 = ((byte0 & 0x03) << 4) | ((byte1 & 0xf0) >> 4)
          e2 = ((byte1 & 0x0f) << 2) | ((byte2 & 0xc0) >> 6)
          e3 = byte2 & 0x3f
      - 남은 바이트가 있을 경우, 부족한 부분은 0으로 채워서 e0, e1, (e2) 생성하고
        출력은 남은 값의 개수+1 바이트를 복원합니다.
    """
    decoded = bytearray()
    index = 0
    # 전체 4바이트 그룹 처리
    full_groups = len(encoded) // 4
    remainder = len(encoded) % 4

    for _ in range(full_groups):
        e0 = encoded[index]
        e1 = encoded[index + 1]
        e2 = encoded[index + 2]
        e3 = encoded[index + 3]
        index += 4
        b0 = (e0 << 2) | (e1 >> 4)
        b1 = ((e1 & 0x0F) << 4) | (e2 >> 2)
        b2 = ((e2 & 0x03) << 6) | e3
        decoded.extend([b0, b1, b2])

    # 나머지 처리: 남은 인코딩 값의 개수에 따라 원본 바이트 복원
    if remainder:
        # 남은 값이 2개면 1바이트 복원, 3개면 2바이트 복원
        if remainder == 2:
            e0 = encoded[index]
            e1 = encoded[index + 1]
            b0 = (e0 << 2) | (e1 >> 4)
            decoded.append(b0)
        elif remainder == 3:
            e0 = encoded[index]
            e1 = encoded[index + 1]
            e2 = encoded[index + 2]
            b0 = (e0 << 2) | (e1 >> 4)
            b1 = ((e1 & 0x0F) << 4) | (e2 >> 2)
            decoded.extend([b0, b1])
        # remainder가 1인 경우는 정상적인 인코딩에서는 발생하지 않음

    return bytes(decoded)

# 주어진 인코딩 데이터
cmp_bytes = b'\x0d\x33\x00\x39\x0e\x03\x01\x23\x0d\x16\x04\x32\x19\x13\x08\x31\x0e\x13\x05\x21\x0c\x16\x11\x24\x0c\x03\x08\x30\x18\x36\x10\x35\x0c\x23\x1d\x24\x19\x06\x11\x24\x19\x06\x14'

# 역연산 수행
decoded_data = reverse_operation(cmp_bytes)

print("Encoded data length:", len(cmp_bytes))
print("Decoded data length:", len(decoded_data))
print(decoded_data.decode())
# codegate2025{70980c5a2e2191a1dd020cd527ddddde}
```

플래그: `codegate2025{70980c5a2e2191a1dd020cd527ddddde}`

# C0D3Matr1x

행렬 문제이다. 이렇게 함정이 많은 문제는 질색이지만 그래도 행렬을 아는 사람에게도 마냥 쉽기만 하지 않은 재밌는 문제였다.

더하는 함수에서 & % 연산을 ida가 자꾸 %로만 표기해서 6시간동안 진전이 없다가 과연 똑같은데 다른 함수로 만들었을까? 하는 생각이 들어서 asm을 GPT에 넣었는데 잘 말해줘서 풀었다.

Wrong을 출력하지 않는 484길이의 input을 찾아서 prob에 넣으면 되는 문제이다.

## 로직

로직은 다음과 같음

- 26x26 길이의 배열을 3x3씩 묶어서 더하여 24x24 길이의 배열을 구성.
- 4개 요소 스왑(회전 형식).
- 행렬 곱(`a3 = a1 * a2`)
- 행렬 곱(`a3 = a1 * a2`)
- 4개 요소 스왑(회전 형식, 아까와 회전되는 인덱스, 방향이 다름)
- add1(더하고 `% 0xffff`)
- 행렬 곱(`a3 = a1 * a2`)
- add2(더하고 `& 0xffff`)
- 비교

## 행렬

행렬 곱에는 다음과 같은 성질이 있다. ($I$는 단위행렬)

$A * B ≠ B * A$, $A * A^{-1} = I$

따라서, 

$A * X = Y → X = A^{-1} * Y$

$X * A = Y → X = Y * A^{-1}$

이것을 이용하여 $A$와 $Y$ 행렬을 알 때 $X$ 행렬을 구할 수 있다.

sage에선 `solve_right`와 `solve_left`로 그 기능을 제공한다.

## 역산

1. 그냥 비교 배열에 table 값을 빼고 `& 0xffff`
2. a2, a3가 아는 값이므로 `solve_left`
3. 그냥 배열에 table 값을 빼고 `% 0xffff`
4. 회전 스왑(`[j][i] ← [23-i][j] ←[23-j][23-i] ← [i][23-j] ← [j][i]`)
5. a1, a3가 아는 값이므로 `solve_right`
6. a2, a3가 아는 값이므로 `solve_left`
7. 회전 스왑(`[i][j] ← [j][23-i] ← [23-i][23-j] ← [23-j][i] ← [23-j][i]`)
8. `input + input`이 들어가므로 26x26으로 심볼과 C0D3GAT3 구성 후 z3 solver에 넣어줬다. 

---

solve code by `xdfyrj`

```python
from pwn import *
from z3 import *
from sage.all import *

context.log_level = 'error'

data = bytes.fromhex("3B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000130000003D0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000010000000C0000003D0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000040000000C0000000C00000036000000360000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000500000000C0000000C0000000C0000000C0000003D000000060000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B00000005000000410000000C0000003D000000360000003D000000120000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000000C0000003D0000000C000000360000000C0000001F000000130000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000004F0000003B0000003B0000003B000000180000000C000000360000000C0000003D000000360000001C0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003E000000540000003B0000003B0000003B0000003B0000003F0000003D000000360000000C0000003D0000003D00000038000000370000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000160000005400000003000000540000003B0000003B0000003B0000003B0000003B0000003B000000510000000C0000003D0000003D0000003D0000003D0000003B0000003B0000003B0000003B0000003B0000003B0000004300000054000000540000005400000054000000440000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000340000003D0000003D0000000C0000003B0000003B0000003B0000003B0000002900000003000000030000005400000003000000320000003C0000003B0000003B0000003B0000003B00000026000000460000003B0000003B0000003B0000003B0000003B000000190000001F0000003B0000003B000000370000005400000054000000540000000300000049000000010000003B0000003B0000003B0000003B0000003B0000003B00000012000000490000002F0000002C0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003D000000420000002F0000000300000054000000540000003F0000003B0000003B0000003B0000003B0000003B00000026000000540000000C0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B00000010000000320000000300000003000000030000005400000041000000400000003B0000003B0000003B00000006000000100000003B0000003B0000003B0000003B0000003B00000027000000310000003B0000003B0000003B0000003B0000003B0000003B0000000D00000032000000420000000300000054000000540000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000001D00000027000000270000004B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000200000003200000054000000490000003B0000003B0000003B0000003B0000003B0000003B00000047000000240000002400000024000000240000004B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000004C000000440000003B0000003B0000003B0000003B0000005300000024000000240000002400000024000000270000004A0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000002200000027000000240000002700000024000000240000000F0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000004D0000002400000024000000240000002400000024000000220000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000004F000000210000001D00000024000000240000002400000024000000090000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B000000140000002400000024000000240000002400000024000000240000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B00000052000000240000002400000024000000240000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000004E00000024000000240000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000003B0000000A000000")
compare = [int.from_bytes(data[i:i+4], 'little') for i in range(0, len(data), 4)]
assert len(compare) == 24*24

key = [ord(c) for c in "C0D3GAT3"]

mod = 0xffff
elf = ELF('./prob')
data = elf.read(0x3220, 0x900)
add_table1 = [int.from_bytes(data[i:i+4], 'little') for i in range(0, 0x900, 4)]
data = elf.read(0x3b20, 0x900)
add_table2 = [int.from_bytes(data[i:i+4], 'little') for i in range(0, 0x900, 4)]
data = elf.read(0x4d20, 0x900)
mul_table = [int.from_bytes(data[i:i+4], 'little') for i in range(0, 0x900, 4)]

arr = [0 for _ in range(576)]
r1 = 0
r2 = 0
for i in range(12):
    if i & 1 != 0:
        arr[24 * (23 - i) + i] = 1
        r1 = 23 - i
        r2 = 24 * i
    else:
        arr[25 * i] = 1
        r1 = 23 - i
        r2 = 24 * r1
    arr[r1 + r2] = 1

def inv_add1(a1, table):
    res = [0 for _ in range(24*24)]
    for i in range(24):
        for j in range(24):
            res[i*24 + j] = (a1[24*i + j] - table[24*i + j]) % 0xffff
    return res

def inv_add2(a1, table):
    res = [0 for _ in range(24*24)]
    for i in range(24):
        for j in range(24):
            res[i*24 + j] = (a1[24*i + j] - table[24*i + j]) & 0xffff
    return res

def right(Y, A):
    Y = [Y[i:i+24] for i in range(0, len(Y), 24)]
    Y = Matrix(IntegerModRing(mod), Y)
    A = [A[i:i+24] for i in range(0, len(A), 24)]
    A = Matrix(IntegerModRing(mod), A)

    X = A.solve_right(Y)
    res = X.list()
    return [ i % mod for i in res ]

def left(Y, A):
    Y = [Y[i:i+24] for i in range(0, len(Y), 24)]
    Y = Matrix(IntegerModRing(mod), Y)
    A = [A[i:i+24] for i in range(0, len(A), 24)]
    A = Matrix(IntegerModRing(mod), A)

    X = A.solve_left(Y)
    res = X.list()
    return [ i % mod for i in res ]

def inv_clockwise(matrix):
    res = matrix[:]
    for i in range(12):
        for j in range(i, 23 - i):
            temp = res[i * 24 + j]
            res[i * 24 + j] = res[j * 24 + (23 - i)]
            res[j * 24 + (23 - i)] = res[(23 - i) * 24 + (23 - j)]
            res[(23 - i) * 24 + (23 - j)] = res[(23 - j) * 24 + i]
            res[(23 - j) * 24 + i] = temp
    return res[:]

def inv_counterclockwise(matrix):
    res = matrix[:]
    for i in range(12):
        for j in range(i, 23 - i):
            temp = res[j * 24 + i]
            res[j * 24 + i] = res[(23 - i) * 24 + j]
            res[(23 - i) * 24 + j] = res[(23 - j) * 24 + (23 - i)]
            res[(23 - j) * 24 + (23 - i)] = res[i * 24 + (23 - j)]
            res[i * 24 + (23 - j)] = temp
    return res[:]

def z3solve(res):
    s = Solver()
    arr_z3 = [0 for _ in range(676)]
    a1 = [Int(f'a{i}') for i in range(484)]
    for var in a1:
        s.add(var >= 0x20)
        s.add(var < 0x7f)
    idx = 0
    for i in range(2, 24):
        for j in range(2, 24):
            arr_z3[26 * i + j] = a1[idx]
            idx += 1
    for i in range(1, 25):
        for j in range(1, 25):
            if arr_z3[26 * i + j] == 0:
                arr_z3[26 * i + j] = key[(i + j - 2) % 8]
    # for i in range(0, 26*26, 26):
    #     print(arr_z3[i:i+26])
    for i in range(24):
        for j in range(24):
            form = (
                arr_z3[26 * (i+2) + j+2] +
                arr_z3[26 * (i+2) + j+1] +
                arr_z3[26 * (i+2) + j+0] +
                arr_z3[26 * (i+1) + j+2] +
                arr_z3[26 * (i+1) + j+1] +
                arr_z3[26 * (i+1) + j+0] +
                arr_z3[26 * (i+0) + j+2] +
                arr_z3[26 * (i+0) + j+1] +
                arr_z3[26 * (i+0) + j+0]
            ) % 0x100000000
            # print(form)
            s.add(res[24 * i + j] == form)
    assert s.check() == sat
    m = s.model()
    return [m[a1[i]].as_long() for i in range(484)]

res = inv_add2(compare, add_table2)
res = left(res, mul_table)
res = inv_add1(res, add_table1)
res = inv_counterclockwise(res)
res = right(res, arr[:])
res = left(res, arr[:])
res = inv_clockwise(res)
# print(res)
flag = z3solve(res)
print(''.join(chr(i) for i in flag))
# C0DEGATE 1s a gl0ba1 internationa1 hacking d3f3ns3 competition and 5ecurity conference. Held annually since 2008, C0D3GAT3 is known as the Olympics for hackers, wh3re hack3rs and security 3xperts from around the world gath3r t0 c0mpet3 for the title of the w0rld's best hack3r. In addition to fierce competition among tru3 white-hat hackers, a juni0r division is also he1d, s3rv1ng as a p1atform f0r discover1ng talented 1ndividuals 1n th3 fi3ld of cyb3rsecurity. You are good hacker.
# coodegate2025{01194af52dd977b3db288b1b8ce2be42b7a18ab86ea403843c346dd14af83767}

```

플래그: `codegate2025{01194af52dd977b3db288b1b8ce2be42b7a18ab86ea403843c346dd14af83767}`

여담: 다른 사람들은 `% 0xffff` 해서 잘만 풀었다는데 나는 왜 안되는지 모르겠다;;


# Conclusion

포너블, 웹 쉬운 문제 뿐만 아니라 리버싱 어려운 문제를 풀어내지 못했다..   
Go, C++, Rust와 같은 언어 자체가 어려운 문제를 만나면 항상 간신히 풀거나 아얘 풀질 못한다.   
행렬 역연산은 이제 좀 익숙해진 듯 싶으니 언어 자체가 난독화 효과를 내는 리버싱 문제를 시도해보아야겠다고 생각했다.   
계속 정진해야겠다.

긴 글 읽어주셔서 감사합니다.   
좋은 하루 되세요.
