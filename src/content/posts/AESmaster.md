---
title: Master of the AES 
published: 2025-10-05
description: 'Amazig Encryption Sibal'
image: ''
tags: ['AES', 'rev']
category: 'Crypto'
draft: false 
lang: ''
---

# 서론

**AES**(Advanced Encryption Standard)는 현대 정보보안에서 가장 유우명한 **블록 암호화 방식**이다.  
보통 CTF에서 flag-checker 형식으로 문제가 많이 출제되는 리버싱 같은 경우, 암호화 방식을 직접 발명하여 문제를 출제하는 것은 매우 어렵기 때문에 AES와 같은 혼돈과 확산이 보장된 좋은 암호화 알고리즘이 프로그램에 구현되어 나오는 경우가 많다.

따라서 디스어셈블 된 코드나 디컴파일 된 코드가 AES인 것을 알아차리는 것이 매우 중요한데, 이를 위해 AES 로직에 대해서 알아보려고 한다.

:::tip
추가로 [Advanced_Encryption_Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)를 찾아보는 것을 추천한다.
:::

# 기본 구조

AES는 정해진 블록 단위로 암호화하는 블록 암호이다.  
따라서 다음과 같은 구조로 되어있다.

1. block 길이: 128비트(16바이트)
2. key 길이: 128비트(16바이트) | 192비트(24바이트) | 256비트(32바이트) 중 택 1
3. 라운드 수:
   1. AES-128 -> 10 round
   2. AES-192 -> 12 round
   3. AES-256 -> 14 round

# 암호화 로직

AES의 암호화 로직은 크게 4가지로 볼 수 있다.

SubBytes, ShiftRows, MixColumns, AddRoundKey

## SubBytes

[S-box](https://en.wikipedia.org/wiki/S-box)를 사용한 비선형 치환표를 이용하여 데이터를 다른 값으로 바꾼다.  
암호의 혼돈(Confusion)을 강화한다.

### 구현

다음은 표준 AES S-box이다.
```py
Sbox = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
```

암호화 방식과 복호화 방식을 간단하게 표현해보면 아래와 같다.
```py
# Sbox = [ ...(생략)... ]
invSbox = [ 0 for _ in range(0x100) ]
for i in range(0x100):
    invSbox[Sbox[i]] = i

for i in range(16):
    block[i] = Sbox[block[i]]
for i in range(16):
    block[i] = invSbox[block[i]]  # 또는 block[i] = Sbox.index(block[i])
```
구현의 차이로 4*4 for문으로 Sbox 암호화를 할 수도 있다.

### SubBytes 심화

더 깊게 들어가보자.  
[Rijndael S-box](https://en.wikipedia.org/wiki/Rijndael_S-box)를 참고하였다.

보통 AES는 속도를 위하여 Sbox를 그냥 하드코딩하여 사용한다.  
하지만 이러면 256 크기에 첫 바이트가 0x63인 table을 보면 리버서는 0.1초도 안되서 AES table인 것을 눈치채버리고 만다.  
따라서 분석을 최대한 힘들게 하고 싶은 개발자들은 S-box의 치환과정을 코드로 구현하여 SubBytes를 하기도 한다.

S-box 치환 알고리즘은 크게 두 가지로 나눌 수 있다.
1. $GF(2^8)$에서의 곱셈 역원
2. 아핀 변환(affine transformation)

이제 입력 바이트 $c$를 출력 바이트 $s = S(c)$로 변환하는 과정을 보자.

**1. 곱셈 역원(Multiplicative inverse)**


$GF(2^8)$은 0~255까지의 정수로 보이지만 내부적으론 다항식을 이용해 만든 체(Field)이다.

`c = 0x57`인 예를 들어보자.  
2진법으론 $01010111_2$이다.

이제 이걸 다항식으로 표현한다면 $c(x) = x^6 + x^4 + x^2 + x + 1$이다.  

1. $GF(2)$ 내에서 `+`는 `^`과 동치이다.

 - 덧셈은 단순히 비트 단위 XOR로 생각하면 된다.

2. $GF(2)$ 내에서 `*`는 `&`와 동치이다.

 - 곱셈은 비트·다항식 곱을 XOR로 누적한 뒤, $x^8 + x^4 + x^3 + x + 1$로 나머지를 취하는 연산이다.
 - 나눗셈의 의미는 항상 차수를 7 이하로 만들기 위함이다.

여기서 $m(x) = x^8 + x^4 + x^3 + x + 1$은 **기약 다항식**(irreducible polynomial)이라고 한다.  
기약 다항식은 더 낮은 차수의 다항식의 곱으로 나타낼 수 없는 다항식이다.  

따라서 이 다항식을 모듈러로 삼으면 모든 8비트 값이 곱셈, 덧셈, 역원 계산에 대해 닫힌 체를 이룬다.


**2. 아핀 변환(Affine Transformation)**

아핀 변환이 훨씬 쉽다.

역원 $b$를 얻었다면 그것을 비트 단위의 선형 변환의 조합과 0x63의 상수를 합쳐준다.  
공식은 아래와 같다.
$$
s = b \oplus \text{rol}(b, 1) \oplus \text{rol}(b, 2) \oplus \text{rol}(b, 3) \oplus \text{rol}(b, 4) \oplus \text{0x63}
$$

여기서 `rol`은 Rotate Left 그 함수가 맞다.

---

다음은 한 바이트를 치환된 바이트로 바꿔서 반환하는 함수의 C 구현이다.  
```c
#define rotl8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift)))) & 0xFF

uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi = (a & 0x80) != 0;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

uint8_t gf_pow(uint8_t a, uint16_t e) {
    uint8_t r = 1;
    while (e) {
        if (e & 1) r = gf_mul(r, a);
        a = gf_mul(a, a);
        e >>= 1;
    }
    return r;
}

uint8_t gf_inv(uint8_t a) {
    if (a == 0) return 0;
    return gf_pow(a, 254);  // a^-1 == a^254
}

uint8_t aes_sbox_byte(uint8_t c) {
    uint8_t b = gf_inv(c);
    uint8_t s = (uint8_t)(b ^ rotl8(b,1) ^ rotl8(b,2) ^ rotl8(b,3) ^ rotl8(b,4) ^ 0x63);
    return s;
}
```
여기서 `hi`가 있다, 즉 최상위 비트가 있을 때 `0x1B`를 xor하는 것에 의문이 생긴다.

`hi`가 1이라는 것은 곱셈 중에 $x^8$ 항이 새로 생겼다는 뜻이다.  
하지만 AES의 유한체 $GF(2^8)$에서는 차수가 7 이하인 다항식만 허용되므로,  
$x^8$ 이상의 항은 반드시 제거되어야 한다.  
이를 위해 AES는 모듈러 다항식  
$$
m(x) = x^8 + x^4 + x^3 + x + 1
$$
로 나눈 **나머지 연산**을 수행한다.

나머지 연산의 성질에 따라  
$$
x^8 \equiv x^4 + x^3 + x + 1 \pmod{m(x)}
$$
이므로, $x^8$을 없앤다는 것은 곧 $x^8$을  
$x^4 + x^3 + x + 1$로 **대입**한다는 의미이다.

GF(2)에서 덧셈은 mod 2 덧셈, 즉 **XOR 연산**이므로,  
결국 $x^4 + x^3 + x + 1$에 해당하는 비트패턴 `0x1B`를  
현재 값과 XOR하는 것으로 **모듈러 나머지 연산**이 구현된다.  

---

예를 들어, 다음 다항식을 생각해보자.

$$
a(x) = x^8 + x^2 + 1
$$

이를 AES에서 사용하는 모듈러 다항식  
$$
m(x) = x^8 + x^4 + x^3 + x + 1
$$
으로 나누면 다음과 같다.

$$
x^8 + x^2 + 1 
\equiv (x^4 + x^3 + x + 1) + x^2 + 1 
= x^4 + x^3 + x^2 + x
$$

여기서 $x^8$ 항을 제거하고 대신 $x^4 + x^3 + x + 1$을 더해준 것은,  
나머지 연산의 성질에 따라  
$$
x^8 \equiv x^4 + x^3 + x + 1 \pmod{m(x)}
$$
이기 때문이다.

:::important
이 SubBytes 과정 중에 역원을 구하는 로직 때문에 비선형성이 생긴다.
:::

## ShiftRows

16바이트 블록을 4 x 4 행렬로 보고, 각 행마다 0,1,2,3의 Shift를 적용시킨다.  
데이터의 위치를 섞어 확산(diffusion)을 강화한다.

### 구현

다음과 같은 형식으로 바뀐다.
```py
arr = [0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf]
arr = [
    arr[0x0], arr[0x1], arr[0x2], arr[0x3],
    arr[0x5], arr[0x6], arr[0x7], arr[0x4],
    arr[0xa], arr[0xb], arr[0x8], arr[0x9],
    arr[0xf], arr[0xc], arr[0xd], arr[0xe],
]
```

ida decompile 코드는 주로 다음과 같은 형식으로 되어 있다.
```c
void __fastcall ShiftRows(_BYTE *a1)
{
  char v1; // [rsp+14h] [rbp-Ch]
  char v2; // [rsp+14h] [rbp-Ch]
  char v3; // [rsp+14h] [rbp-Ch]
  char v4; // [rsp+15h] [rbp-Bh]
  char v5; // [rsp+15h] [rbp-Bh]
  char v6; // [rsp+16h] [rbp-Ah]
  char v7; // [rsp+16h] [rbp-Ah]
  char v8; // [rsp+17h] [rbp-9h]
  char v9; // [rsp+17h] [rbp-9h]

  v1 = a1[4];
  v6 = a1[6];
  v8 = a1[7];
  a1[4] = a1[5];
  a1[5] = v6;
  a1[6] = v8;
  a1[7] = v1;
  v2 = a1[8];
  v4 = a1[9];
  v9 = a1[11];
  a1[8] = a1[10];
  a1[9] = v9;
  a1[10] = v2;
  a1[11] = v4;
  v3 = a1[12];
  v5 = a1[13];
  v7 = a1[14];
  a1[12] = a1[15];
  a1[13] = v3;
  a1[14] = v5;
  a1[15] = v7;
}
```

위와 같이 다른 인덱스끼리 치환하는 구조가 보인다면 ShiftRows일 확률이 높다.

## MixColumns

블록을 4x4 행렬로 볼 때 **각 열**을 독립적으로 선형 변환하는 과정이다.   
단일 바이트의 변화가 전체 열에 영향을 줘 확산을 담당한다.

### 수식

열 벡터 $[a_0, a_1, a_2, a_3]^T$에 대해서 MixColumns는 다음을 계산한다
$$
\begin{bmatrix}
b_0  \\
b_1  \\
b_2  \\
b_3  \\
\end{bmatrix}
=
\begin{bmatrix} 
02 & 03 & 01 & 01  \\
01 & 02 & 03 & 01  \\
01 & 01 & 02 & 03  \\
03 & 01 & 01 & 02  \\
\end{bmatrix}
\cdot
\begin{bmatrix}
a_0  \\
a_1  \\
a_2  \\
a_3  \\
\end{bmatrix}
$$

여기서 행렬 덧셈은 모두 XOR로 치환된다.
따라서 풀어서 표현해보면 아래와 같다.

$$
b_0 = (2 \cdot a_0) \oplus (3 \cdot a_1) \oplus (1 \cdot a_2) \oplus (1 \cdot a_3) \\
b_1 = (1 \cdot a_0) \oplus (2 \cdot a_1) \oplus (3 \cdot a_2) \oplus (1 \cdot a_3) \\
b_2 = (1 \cdot a_0) \oplus (1 \cdot a_1) \oplus (2 \cdot a_2) \oplus (3 \cdot a_3) \\
b_3 = (3 \cdot a_0) \oplus (1 \cdot a_1) \oplus (1 \cdot a_2) \oplus (2 \cdot a_3) \\
$$

### $GF(2^8)$에서의 곱셈
- `x1`: 그대로
- `x2`: 1bit shl 후, 최상위 비트가 1이면 0x1B로 XOR.(S-box 심화에서 서술)
- `x3`: (x2 결과) $\oplus$ (x1 결과)

### 복호화
복호화 과정에선 역행렬 이용하여 똑같은 방식으로 곱해준다.
$$
\begin{bmatrix} 
0e & 0b & 0d & 09  \\
09 & 0e & 0b & 0d  \\
0d & 09 & 0e & 0b  \\
0b & 0d & 09 & 0e  \\
\end{bmatrix}
$$

### 구현

C로 짠 간단한 구현이다.

```c
void gmix_column(unsigned char *r) {
    unsigned char a[4];  // x1의 열
    unsigned char b[4];  // x2의 열
    unsigned char h;
    for (unsigned char c = 0; c < 4; c++) {
        a[c] = r[c];
        h = (unsigned char)(r[c] >> 7);     // 최상위 비트
        b[c] = (unsigned char)(r[c] << 1);  // ×2
        b[c] ^= (unsigned char)(h * 0x1B);  // 모듈러 다항식 보정
    }
    // 02 03 01 01 행렬 곱 적용
    r[0] = (unsigned char)(b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]); // 2*a0 ^ 3*a1 ^ 1*a2 ^ 1*a3
    r[1] = (unsigned char)(b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]); // 1*a0 ^ 2*a1 ^ 3*a2 ^ 1*a3
    r[2] = (unsigned char)(b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]); // 1*a0 ^ 1*a1 ^ 2*a2 ^ 3*a3
    r[3] = (unsigned char)(b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]); // 3*a0 ^ 1*a1 ^ 1*a2 ^ 2*a3
}

void MixColumns(unsigned char block[16]) {
    unsigned char col[4];
    for (int c = 0; c < 4; ++c) {
        col[0] = block[4*c + 0];
        col[1] = block[4*c + 1];
        col[2] = block[4*c + 2];
        col[3] = block[4*c + 3];
        gmix_column(col);
        block[4*c + 0] = col[0];
        block[4*c + 1] = col[1];
        block[4*c + 2] = col[2];
        block[4*c + 3] = col[3];
    }
}
```

:::important
마지막 라운드에는 MixColumns를 적용하지 않는다.
:::

## AddRoundKey

AddRoundKey는 AES에서 핵심적인 **비밀성 주입** 단계이다.

AddRoundKey는 key를 현재 block에 XOR하는 과정이다.

```c
void AddRoundKey(unsigned char state[16], const unsigned char roundKey[16]) {
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[4*c + r] ^= roundKey[4*c + r];
        }
    }
}
```

## + Key Expansion

AES는 **원본 키**로부터 여러 **라운드 키**를 생성한다.  
각 라운드마다 서로 다른 키를 사용함으로써 암호의 안전성을 강화한다.  
키 확장은 S-box, Rcon, RotWord, SubWord로 이루어진다.  
이 과정을 통해 암호화의 비선형성(nonlinearity)과 확산(diffusion)이 강화된다.

### 개념

| 항목 | 의미 |
|:--|:--|
| 블록 크기 $N_b$ | 4 워드 (16바이트) |
| 키 길이 $N_k$ | AES-128: 4, AES-192: 6, AES-256: 8 |
| 라운드 수 $N_r$ | 10, 12, 14 (각각 키 길이에 따라) |

생성되는 총 워드 수는 다음과 같다.

$$
N_w = N_b \times (N_r + 1)
$$

### 연산

- **RotWord**: 4바이트 워드를 왼쪽으로 1바이트 회전  
  예: `[a0, a1, a2, a3] → [a1, a2, a3, a0]`

- **SubWord**: 워드의 각 바이트에 S-box를 적용  

- **Rcon**: 라운드별 상수.  
  GF(2⁸)에서 2의 거듭제곱으로 생성된다.  
  예: Rcon[1] = 0x01, Rcon[2] = 0x02, Rcon[3] = 0x04, ...

### 구현

```c
void aes_key_expansion(const uint8_t *key, uint8_t *roundKey, int Nk) {
    static const uint8_t Rcon[15] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D};
    extern uint8_t sbox[256];  // 기존 AES S-box 사용   
    int Nr = (Nk == 4 ? 10 : Nk == 6 ? 12 : 14);
    int total = 4 * (Nr + 1);
    memcpy(roundKey, key, 4 * Nk);  
    for (int i = Nk; i < total; i++) {
        uint8_t temp[4];
        for (int j = 0; j < 4; j++) temp[j] = roundKey[4*(i-1)+j];  
        if (i % Nk == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0]=temp[1];
            temp[1]=temp[2];
            temp[2]=temp[3];
            temp[3]=t;
            // SubWord
            for (int j=0;j<4;j++) 
                temp[j]=sbox[temp[j]];
            // XOR with Rcon
            temp[0] ^= Rcon[i/Nk];
        } 
        else if (Nk == 8 && i % Nk == 4) {
            for (int j=0;j<4;j++) temp[j]=sbox[temp[j]];
        }
        for (int j = 0; j < 4; j++)
            roundKey[4*i+j] = roundKey[4*(i-Nk)+j] ^ temp[j];
    }
}
```

| AES 종류 | $N_k$ | $N_r$ | 라운드키 크기
| :-- | :-- | :-- | :-- |
| AES-128 | 4 | 10 | 176B
| AES-192 | 6 | 12 | 208B
| AES-256 | 8 | 14 | 240B

각 라운드 $r$의 키는 `roundKey[16 * r]` 부터 16바이트를 사용한다.

:::tip
Key Expansion은 어떻게 생겼는지만 알고있어도 된다.
:::

# 끝내며

AES의 내용이 너무 방대하여 운용 모드에 관한 내용을 모두 담지 못해서 아쉽지만 다음 포스트에 넣어보도록 노력하겠다.  

AES 이외에도 **ChaCha20**, **RSA**, **SHA hash**과 같은 여러 암호화 알고리즘은 리버싱에 많이 나오니까 학습을 진행하면 실력이 잘 향상될 수 있다고 생각한다.

---

긴 글 읽어주셔서 감사합니다. 좋은 하루 되세요.
