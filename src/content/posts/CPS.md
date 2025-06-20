---
title: About Continuation-Passing Style
published: 2025-06-20
updated: 2025-06-20
description: 'CPS is so hard'
image: ''
tags: [rev, research, CPS, Python]
category: 'Reversing'
draft: false 
---

# Preface

Python에서 `Lambda` 함수는 타 함수에 비해 사용하기 까다롭다.

항상 Python에서 `lambda` 함수를 사용한 문법이 나오면 코드를 이해할 때 `lambda`의 기능이 직관적으로 뇌에 들어오지 않아 궁금증을 자아냈다.

이러한 이유도 있고, 드림핵의 [CPSython](https://dreamhack.io/wargame/challenges/694) 문제가 재밌게 생겨서 보다 깊게 이해해보고자 이 글을 작성한다.

:::warning 
이 글은 CPSython을 풀이하며 작성한 글입니다. 짜임새가 없어도 이해해주시면 감사하겠습니다. 최대한 이해하기 쉽게 작성하도록 노력하고 있습니다.
:::

:::caution
CPSython을 풀어보고 이 글을 읽는 것을 추천 드립니다.   
아니면 CPS 관련 공부 자료만 보시는 것을 권장 드립니다.
:::

# What is `Python Lambda`?

`Lambda`를 오늘 처음 볼 수도 있다. `lambda`란 무엇일까?

이제부터 편하게 `람다`라고 부르겠다.

**람다**는 Python에 존재하는 **이름 없는 작은 함수**라고 보면 된다.

사용법은 다음과 같다.

```python
# Syntax
lambda arguments : expression
```

아직 이해가 안되었다면 아래 예제들을 보자.

```python
>> add = lambda a, b: a + b  # add
>> print(add(2, 3))
5
>> inv = lambda a, b: pow(a, -1, b)  # modular inverse
>> print(inv(13, 0xfb))
58
```

간단한 함수를 한 줄로 쉽게 표현할 수 있는 장점이 있다.

하지만 한 줄이기 때문에 디버깅에 어려움이 있다. → 분석하기 어려움.

# Why use `Lambda` functions?

그렇다면 람다는 왜 사용할까? 

그냥 함수를 숏코딩하기 위해서 사용하는 것일까?

람다의 진가는 다른 함수 안에 들어가 있을 때 나온다.

# What is meaning of CPSython??

문제를 처음 본 순간부터 **CPSython**의 뜻이 무엇인지 궁금했다.  
실제로 CPS를 구글에 검색해봤고, CPS Energy라는 소득없는 정보만 나올 뿐이었다.  

하지만 구글링을 잘 해보면 CPS가 무엇인지 알 수 있다.  
https://en.wikipedia.org/wiki/Continuation-passing_style

## Continuation-Passing Style

**CPS(Continuation-Passing Style)**이란, 함수형 프로그래밍 언어에서 **계속(Continuation)**이라는 추가 함수로 **제어 흐름을 명시적으로 넘기는** 프로그래밍 스타일을 말한다. 

일반적으로 함수 호출(Direct style)에서는 함수가 값을 계산한 뒤 호출자에게 *리턴*하지만, CPS에서는 함수 호출할 때 **결과를 처리할 다른 함수(continuation)**를 인자로 전달하고,  함수가 결과를 얻으면 그 값을 리턴 대신 그 **continuation 함수에게 넘겨 실행**한다.(!!)

~~이게 무슨 소린가 싶다.~~

하지만 Continuation이란 단어를 Callback으로 바꾼다면 CPS가 무엇인지 쉽게 짐작할 수 있게 된다.   
Callback-passing style, Callback 함수를 전달하는 방식을 의미한다.

## Compare with the Direct style

CPS를 더 잘 이해하기 위해 Direct Style과 비교를 해보자.

### direct style

```py
def factorial_direct(n):
    if n == 0:
        return 1
    return n * factorial_direct(n - 1)

print(factorial_direct(5))
```
팩토리얼을 직접적으로 숫자를 계산하고 리턴하는 방식을 구현한 Python 코드이다.

### CPS

```py
def factorial_cps(n, cont):
    if n == 0:
        return cont(1)
    else:
        return factorial_cps(n - 1, lambda result: cont(n * result))

def print_result(x):
    print(x)

factorial_cps(5, print_result)
```
팩토리얼 수의 계산을 함수로 묶어 전달하는 방식으로 구현한 Python 코드이다.

이렇게 봐서 감이 잡힌다면 best이다.  
하지만 이걸 봐도 이해가 안될 수도 있다.  

사실 CPS 코드는 정확히 이해하는 것보단 대충 감을 통해 이해하는 것이 효과적이고,  
분석에 큰 지장이 갈 정도는 아니기에 이론적으로 너무 파고 들어가지 않고 분석으로 넘어가도 된다.


# What about this?

```python
# functional.py
import sys,resource
resource.setrlimit(resource.RLIMIT_STACK,[0x80000000,resource.RLIM_INFINITY])
sys.setrecursionlimit(0x10000000)
A = lambda a:a(a)
B = lambda b:A(lambda c:b(lambda *d:c(c)(*d)))
C = lambda a,b,c:c(lambda d:d(a,b))
D = lambda a,b:a(lambda c,d:b(c))
E = lambda a,b:a(lambda c,d:b(d))
F = lambda a:exit(a)
G = (lambda a:lambda b:(lambda c:C(c[0],None,b)if(c)else(F(1)))(a(1)))(sys.stdin.buffer.read)
H = (lambda a:lambda b,c:D(b,lambda d:(a(bytes([d])),E(b,c))))(sys.stdout.buffer.write)
I = B(lambda a:lambda b,c:c(None)if(b==0)else(G(lambda d:D(d,lambda e:a(b-1,lambda f:C(e,f,c))))))
J = lambda a,b:B(lambda c:lambda d:b()if(d==None)else(H(d,lambda e:c(e))))(a)
K = lambda a,b,c:B(lambda d:lambda e,f:c(e)if(f==0)else(E(e,lambda g:d(g,f-1))))(a,b)
L = lambda a,b,c:K(a,b,lambda d:D(d,c))
M = B(lambda a:lambda b,c,d:d(None)if(c==0)else(b(lambda e,f:a(f,c-1,lambda g:C(e,g,d)))))
N = lambda a,b,c,d:K(a,b,lambda e:M(e,c,d))
O = lambda a,b:B(lambda c:lambda d,e:b(e)if(d==None)else(E(d,lambda f:c(f,e+1))))(a,0)
P = B(lambda a:lambda b,c,d:d(c)if(b==None)else(b(lambda e,f:a(f,c,lambda g:C(e,g,d)))))
Q = lambda a,b:B(lambda c:lambda d,e:b(e)if(d==None)else(d(lambda f,g:C(f,e,lambda h:c(g,h)))))(a,None)
R = lambda a,b,c:B(lambda d:lambda e,f,g:g(None)if(e==None)else(e(lambda h,i:b(h,f,lambda j:d(i,f+1,lambda k:C(j,k,g))))))(a,0,c)
S = lambda a,b,c:B(lambda d:lambda e,f,g:c((g)and(e==None)and(f==None))if((e==None)or(f==None))else(e(lambda h,i:f(lambda j,k:d(i,k,(g)and(h==j))))))(a,b,True)
T = B(lambda a:lambda b,c:c(0)if(b==None)else(b(lambda d,e:a(e,lambda v:c(d|(v<<8))))))
U = B(lambda a:lambda b,c,d:d(None)if(c==0)else(a(b>>8,c-1,lambda e:C(b&0xff,e,d))))
del sys,resource
all=(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U)
```

CPSython의 functional.py 파일이다.  
진짜 난해하다.

```python
# main.py
(lambda A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U:B(lambda r:lambda i,a:C(i,a,lambda a:r(i+1,a))if(i<256)else(Q(a,lambda a:R(a,(lambda b,d:lambda e,i,c:d(e,99,lambda v:B(lambda r:lambda i,v:b(e,i,lambda v2:d(v,v2,lambda v3:r(i+1,v3)))if(i<=5)else(c(v)))(2,v)))(lambda x,i,c:c((x<<i|x>>8-i)&255),lambda v1,v2,c:c(v1^v2)),lambda f:C(238,None,lambda c:C(63,c,lambda c:C(100,c,lambda c:C(254,c,lambda c:C(254,c,lambda c:C(113,c,lambda c:C(32,c,lambda c:C(123,c,lambda c:C(127,c,lambda c:C(38,c,lambda c:C(54,c,lambda c:C(125,c,lambda c:C(64,c,lambda c:C(215,c,lambda c:C(9,c,lambda c:C(139,c,lambda c:T(c,lambda g:I(64,lambda h:B(lambda j:lambda k,l:N(h,k*16,16,lambda m:B(lambda n:lambda o,m:R(m,lambda e,i,c:L(f,e,c),lambda m:N(m,0,7,lambda b0:N(m,7,9,lambda b1:P(b1,b0,lambda m:T(m,lambda p:U(p*g,16,lambda m:R(m,lambda e,i,c:c(e+i*i+23&255),lambda m:n(o+1,m))))))))if(o<16)else(P(l,m,lambda l:j(k+1,l))))(0,m))if(k<4)else(C(123,None,lambda s:C(72,s,lambda s:C(68,s,lambda s:C(10,None,lambda e:C(125,e,lambda e:C(182,None,lambda c:C(160,c,lambda c:C(106,c,lambda c:C(148,c,lambda c:C(161,c,lambda c:C(133,c,lambda c:C(162,c,lambda c:C(122,c,lambda c:C(77,c,lambda c:C(23,c,lambda c:C(118,c,lambda c:C(130,c,lambda c:C(200,c,lambda c:C(90,c,lambda c:C(66,c,lambda c:C(24,c,lambda c:C(210,c,lambda c:C(74,c,lambda c:C(91,c,lambda c:C(225,c,lambda c:C(193,c,lambda c:C(9,c,lambda c:C(219,c,lambda c:C(121,c,lambda c:C(177,c,lambda c:C(72,c,lambda c:C(70,c,lambda c:C(201,c,lambda c:C(5,c,lambda c:C(59,c,lambda c:C(7,c,lambda c:C(134,c,lambda c:C(25,c,lambda c:C(18,c,lambda c:C(8,c,lambda c:C(53,c,lambda c:C(22,c,lambda c:C(104,c,lambda c:C(170,c,lambda c:C(72,c,lambda c:C(167,c,lambda c:C(68,c,lambda c:C(48,c,lambda c:C(250,c,lambda c:C(11,c,lambda c:C(220,c,lambda c:C(144,c,lambda c:C(25,c,lambda c:C(183,c,lambda c:C(180,c,lambda c:C(164,c,lambda c:C(227,c,lambda c:C(15,c,lambda c:C(200,c,lambda c:C(148,c,lambda c:C(139,c,lambda c:C(109,c,lambda c:C(253,c,lambda c:C(152,c,lambda c:C(135,c,lambda c:C(230,c,lambda c:C(191,c,lambda c:C(121,c,lambda c:C(82,c,lambda c:S(c,l,lambda q:J(s,lambda:J(h,lambda:J(e,lambda:F(0))))if(q)else(F(1))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))(0,None)))))))))))))))))))))))(0,None))(*__import__('functional').all)
```

CPSython 문제의 main.py 파일이다.  
역시 난해하다.  
차근 차근 분석해보자.

## 분석 계획

워게임을 풀어내기 위해선 일단 목표와 그 목표를 달성하기 위한 방법을 명확히 해야한다.   
그냥 쌩으로 코드만 보는 것은 변태들이나 하는 일이다.

일단 `functional.py`가 있고 `main.py` 파일이 있다. main 파일에서 함수를 활용하기 때문에 대조하며 보면 쉽게 읽어낼 수 있다.

1. 실행해보기
2. 코드 분석
3. 익스코드 작성

방식으로 해보자.

## 실행

실행하면 아무것도 안 뜬다. ~~ctrl+C를 누르면 엄청난 것을 목격할 수 있다~~  
아무거나 입력해본다면 조금 이후에 프로그램이 종료되며 실패가 뜬다.  
몇 번 입력해보면 코드를 안 보고도 64개의 입력을 받는다는 것을 알 수 있다.  
이제 코드로 넘어가자.

## 분석

일단 main 파일 전체를 ChatGPT를 이용하여 '읽기 쉽게 리팩토링 해줘.'라고 말하여 좀 더 구조적으로 볼 수 있다.

<img src='/CPS/fixed_main.png'>

일단 가장 쉬운 함수 `F`를 보면 그냥 `exit`인것을 알 수 있다.  
exit(0)은 성공, exit(1)은 실패를 나타내므로 main 코드의 성공, 실패를 읽어낼 수 있다.

따라서 `F(0)` 부분을 주의해서 볼 필요가 있는 것이다.  
`F` 함수 앞에 시선을 강탈하는 C chain이 보인다.  
긴 체인을 잘 보면 `s`로 묶이는 것과, `c`로 묶이는 것과, `e`로 있는 것을 볼 수 있는데, `s`는 `DH{`, `e`는 `}`이므로 `c`는 비교 배열인 것을 추측할 수 있다. 

```py
C(123,None,lambda s:C(72,s,lambda s:C(68,s,lambda s:C(10,None,lambda e:C(125,e,lambda e:C(182,None,lambda c:C(160,c, ... )))))))
```

이정도 분석했다면 CPS에 눈이 익어 다른 코드들도 쉽게 읽어낼 수 있다.  
C chain은 배열을 구성한다.  
입력은 `I` 함수로 받는다.

이런 식으로 함수를 분석해 낼 수 있다.

여기서 추가적으로 [SKI Combinator Calculus](https://en.wikipedia.org/wiki/SKI_combinator_calculus)를 배워 쉽게 읽을 수 있지만 글이 너무 길어지니 다음에 다루기로 하겠다.

일단 SKI Combinator 관점으로 함수를 정리 해보았다.

---

### A = `lambda a: a(a)`

- **SKI 개념**: 자기 적용 함수 (**`U` 콤비네이터**와 유사)
- **의의**: 고정점 계산을 위한 핵심. 이는 Y 콤비네이터의 기본 구조이기도 함.

### B = `lambda b: A(lambda c: b(lambda *d: c(c)(*d)))`

- **의의**: `A`로 자기 자신을 인자로 받아 `b`를 재귀적으로 호출할 수 있게 함.
- **SKI 대응**: `B b`는 `b`의 재귀 버전을 반환하는 고정점 생성기 → **Y 콤비네이터**

### C = `lambda a,b,c: c(lambda d: d(a,b))`

- **설명**: a와 b를 클로저 형태로 캡처해서 `c`에 넘김
- **역할**: 일종의 `Pair (a,b)` 생성기, SKI에는 직접 대응은 없지만, Church encoding에서 `PAIR a b = λf. f a b`와 유사함

### D = `lambda a,b: a(lambda c,d: b(c))`

- **설명**: `a`는 pair, 그 중 첫 번째 값만 `b`에 넘김
- **역할**: `fst(pair)`, 즉 첫 번째 요소 추출
- **SKI 스타일**: `K`가 `K x y = x`인 것과 비슷한 구조

### E = `lambda a,b: a(lambda c,d: b(d))`

- **설명**: `snd(pair)` – 두 번째 요소 추출
- **SKI 스타일**: `K*` 스타일, 두 번째 인자 반환

### F = `lambda a: exit(a)`

- **역할**: 명령형 효과 삽입. 계산을 중단함 → 실제 SKI에서는 없지만 환경 제어

### G = `(lambda a:lambda b:(lambda c:C(c[0],None,b)if(c)else(F(1)))(a(1)))(sys.stdin.buffer.read)`

- **설명**: 입력 처리기. STDIN에서 바이트를 읽고 첫 번째 값만 추출해 `C`로 래핑
- **역할**: 입력이 없으면 종료, 있으면 계속 진행
- **SKI 개념**: 외부 환경과의 인터페이스

### H = `(lambda a:lambda b,c:D(b,lambda d:(a(bytes([d])),E(b,c))))(sys.stdout.buffer.write)`

- **설명**: 출력 래퍼. 한 바이트 출력 후, `E`로 다음 단계로 진행
- **역할**: STDOUT 처리기

이 부분은 **SKI의 자기 적용** + `S` 콤비네이터 스타일로 조합된 고차 연산자들이야.

### I = `B(lambda a: lambda b,c: c(None) if (b==0) else (...))`

- **설명**: `b`가 0이면 종료, 아니면 `G`를 호출하여 읽기 계속
- **역할**: 루프 생성기 (재귀로 입력 반복)
- **SKI 개념**: `Y (λr. λn. if n=0 then z else r(n-1))`과 구조적으로 유사

### J = `lambda a,b: B(lambda c: lambda d: b() if d == None else H(d, lambda e: c(e)))(a)`

- **설명**: 리스트가 끝났으면 종료, 아니면 `H`를 통해 출력하고 재귀
- **역할**: 리스트 출력기

다음 함수들은 데이터를 SKI 스타일로 표현된 구조로 처리해.

### K = `lambda a,b,c: B(lambda d:lambda e,f: c(e) if f==0 else E(e, lambda g: d(g, f-1)))(a,b)`

- **설명**: 리스트 순회 (카운트 다운)

### L = `lambda a,b,c: K(a,b,lambda d: D(d,c))`

- **설명**: 리스트를 순회하며 각 요소에 대해 `c`를 적용

### M, N = 리스트 처리 (지도 + 필터 조합)

### T = 바이트 스트림을 정수로 (big endian)

- Church encoding과 유사하게, 재귀적으로 왼쪽 쉬프트하면서 값 누적

### U = 정수를 바이트로 (역방향)

- 하위 바이트부터 추출해서 리스트 생성

---

### 코드 루틴

함수를 알아냈으니 암호화 루틴 과정을 분석 가능하다.

## 1. S-Box 및 상수 준비

`g`: 16바이트 상수 리스트 -> 상수로 변환  
`Sbox`: `Sbox[e] = (e ^ 99) ^ rol(e,2) ^ rol(e,3) ^ rol(e,4) ^ rol(e,5)`

## 2. 블록당 16라운드 암호화

1. 인덱스 기반 덧셈  
    인덱스에 따라 `+ i*i + 23`을 함.

2. 정수 변환 & 곱셈  
    16 바이트를 리틀엔디안 정수로 보고 `* g` 수행

3. 블록 순환 분할,병합
4. S-Box 치환
5. 최종 병합  
    4개 블록을 순서대로 이어붙여 64 바이트 암호문 리스트 `l` 완성
6. 비교
    `c`와 `l`을 비교
7. 같으면 `DH{ + l + }` 출력 후 `exit(0)`

# 소감

이렇게 방대한 지식을 이용하여 문제를 만드신 분이 존경스러울 따름이다..  
문제를 푸는 것보다 문제를 만드는 것이 훨씬 어려웠을 것이라 체감된다.  
문제 제작자께 감사드립니다.  


# Reference

Python 람다 사용법: https://www.w3schools.com/python/python_lambda.asp

람다 대수: https://namu.wiki/w/%EB%9E%8C%EB%8B%A4%20%EB%8C%80%EC%88%98

함수형 프로그래밍: https://namu.wiki/w/%ED%95%A8%EC%88%98%ED%98%95%20%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%98%EB%B0%8D#s-2

https://www.geeksforgeeks.org/functional-programming-paradigm/