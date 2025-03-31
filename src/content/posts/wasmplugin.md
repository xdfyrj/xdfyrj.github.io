---
title: How to analyze the wasm file
published: 2025-03-13
description: "analyze of wasm with Ghidra"
tags: ["rev", "Ghidra", "wasm"]
category: Reversing
draft: false
---

# Preface

나는 wasm, Web Assembly 문제를 만날 때마다 Ghidra wasm plugin을 사용하여 풀이를 한다.   
하지만, 그 설치가 어려워 wasm 문제에 어려움을 겪는 사람이 많다.   
오늘은 그 설치에 관해서 말해볼까 한다.

:::tip
google에 wasm decompiler라고 검색하여 풀 수 있지만, Ghidra가 더 분석을 잘하고, 무엇보다 편하다.
:::

# How to install Ghidra

[Download from Github](https://github.com/NationalSecurityAgency/ghidra/releases)

ghidra 다운로드 링크이다.   
여기서 11.1 or 11.2를 다운 받아주자.   
Assets 옆의 작은 화살표를 누르고 PUBLIC이 써져있는 zip 폴더를 받으면 된다.

<img src="/wasm/Ghidra.png">

다운을 받았다면 압축을 해제한다.

:::warning
11.1.1 같은 기드라가 있을 것인데 이것은 11.1을 위한 wasm plugin과 호환이 안된다.
정확하게 다운 받아주자.
:::

# How to install wasm plugin

[Download wasm plugin](https://github.com/nneonneo/ghidra-wasm-plugin/releases)

Ghidra wasm plugin 다운로드 링크이다.   
Ghidra 버전에 맞게 잘 다운받아주자. 압축해제는 **안 한다**.

<img src="/wasm/wasm.png">

# Apply plugin

Ghidra, Ghidra wasm plugin을 모두 다운 받았다면 이제 적용을 시킬 차례이다.

다음과 같은 구조로 적용하면 된다.

- Ghidra를 켠 후 File - Install Extensions...를 누른다.
- Install Extensions 창의 우측 상단의 `+` 모양의 버튼을 누른다.
- wasm plugin zip 파일을 선택하고 ok를 눌러준다.

그러면 설치 끝~!   
버전만 잘 맞추면 어려울게 없다.

:::note
Ghidra의 디컴파일을 잘 못할 때가 있다. 그럴 땐 어셈블리 보면 해결된다.
:::

# Additional

추가적으로, wasm plugin 실습을 해보겠다.

문제는 codegate2025 WebBinary 문제이다.   
파일을 얻고 싶다면 디스코드 `sumyr`로 연락하면 된다.

[Write-ups](https://xdfyrj.notion.site/codegate2025-Write-ups-1c5723dbd99380f6a4b5f7dc745946d3?pvs=74)

ghidraRun.bat 파일을 눌러 Ghidra를 키자.

<img src="/wasm/start.png">

그러면 위와 같이 실행되는데 왼쪽 위의 file > New Project를 눌러서 새 프로젝트를 만들어주자.   
Non-shared이고, 경로는 WebBinary의 경로, 이름은 아무거나(나는 wb로 했다)

그 후 prob.wasm 파일을 Ghidra에 드래그 앤 드롭해서 불러온다.   
다 그냥 ok를 누르고, prob.wasm을 더블 클릭하면 켜질 것이다.

**그리고 여기서 아무것도 건들지 않고, Yes와 Analyze를 누르면 된다.**

## 분석

왼쪽 `Symbol Tree`에서 main 함수를 찾을 수 있다.(Namespaces/export/main)

```c
undefined4 export::main(undefined4 param1,undefined4 param2)

{
  undefined4 uVar1;
  
  uVar1 = unnamed_function_7();
  return uVar1;
}
```

`unnamed_function_7`을 분석해보자.

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
  if (local_340 == 0x2b) {
    for (local_33c = 0; local_33c < 0x2c; local_33c = local_33c + 1) {
      if (local_200[local_33c] != local_330[local_33c]) {
        unnamed_function_9(0x10180,0);
        return 0;
      }
    }
    local_370[0] = &local_d0;
    unnamed_function_9(s_codegate2025{%s}_ram_0001016e,local_370);
  }
  else {
    unnamed_function_9(0x10180,0);
  }
  return 0;
}
```

대충 본다면 맨 마지막에 `codegate2025{}` 플래그 포맷과 0x10180(실제로 보면 `Wrong`)을 출력하는 것을 볼 수 있으므로, "플래그 체커구나~" 생각 가능하다.

비교 배열은 `local_330`이다. `memory_copy(0,0,300,0x10000,local_330);`를 코드에서 쉽게 확인 가능하기에 `0x10000`의 0x2b 길이의 배열이 비교 배열이다.

<img src='/wasm/0x10000.png'>

다 드래그 후 우클릭 > Copy Special > Python Byte String으로 추출하면 간편하다.

로직은 base64인데 짭인 base64이다.   
이런 간단하지만 귀찮은 코드는 ChatGPT 돌리면 좋다.

## solve.py
```py
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
```

# Conclusion

Web Assembly는 굉장히 독특하다.   
JS와 소통하는 Assembly 코드라니.   
계속 느끼는 점이지만 해킹이라는 학문이 아주 거미줄처럼 연결되어 있어서, 가끔은 리버서도 웹 공부를 하는 것이 이로운 것 같다고 느낀다.   
아님 말고   

이 글을 읽고 의욕이 생긴다면 아래 연습문제들도 풀어봐라!   

긴 글 읽어주셔서 감사합니다.   
좋은 하루 되세요~ :D

# Practice
- [passcode](https://dreamhack.io/wargame/challenges/228)
- [Reverse Me](https://dreamhack.io/wargame/challenges/1640)
- [[LINE CTF 2021] ultrushawasm](https://dreamhack.io/wargame/challenges/397)
