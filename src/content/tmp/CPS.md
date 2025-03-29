---
title: About Continuation-Passing Style
published: 2024-05-01
updated: 2024-11-29
description: ''
image: ''
tags: [rev, research, CPS, Python]
category: 'Reversing'
draft: false 
---

# Preface

Python에서 `Lambda` 함수는 타 함수에 비해 사용하기 까다롭다.

항상 Python에서 `lambda` 함수를 사용한 문법이 나오면 코드를 이해할 때 `lambda`의 기능이 직관적으로 뇌에 들어오지 않아 궁금증을 자아냈다.

이러한 이유도 있고, 드림핵의 [CPSython](https://dreamhack.io/wargame/challenges/694) 문제가 재밌게 생겨서 GPT 없이 완벽하게 자력으로 이해해보고자 이 글을 작성한다.

:::warning 
이 글은 CPSython을 풀이하며 작성한 글입니다. 짜임새가 없어도 이해해주시면 감사하겠습니다. 최대한 이해하기 쉽게 작성하도록 노력하고 있습니다.
:::

# Index

- 람다란?
- 람다를 사용하는 이유
- CPS란?

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

하지만 방금 CPS가 무엇인지 알아내었다.

---

https://en.wikipedia.org/wiki/Continuation-passing_style

---

## Continuation-Passing Style

**Continuation-passing style(CPS)**이란, 함수형 프로그래밍 언어에서 **계속(Continuation)**이라는 추가 함수로 **제어 흐름을 명시적으로 넘기는** 프로그래밍 스타일을 말한다. 

일반적으로 함수 호출(Direct style)에서는 함수가 값을 계산한 뒤 호출자에게 *리턴*하지만, CPS에서는 함수 호출할 때 **결과를 처리할 다른 함수(continuation)**를 인자로 전달하고,  함수가 결과를 얻으면 그 값을 리턴 대신 그 **continuation 함수에게 넘겨 실행**한다.(!!)

~~이게 뭔 개소린가 싶다.~~

하지만 Continuation이란 단어를 Callback으로 바꾼다면 CPS가 무엇인지 쉽게 짐작할 수 있게 된다. Callback-passing style, Callback 함수를 전달하는 방식을 의미한다.

## Compare with the Direct style

CPS를 더 잘 이해하기 위해 Direct Style과 비교를 해보자.

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

차근차근 완전 정복을 한다는 느낌으로 분석을 해보겠다.

```python
# main.py
(lambda A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U:B(lambda r:lambda i,a:C(i,a,lambda a:r(i+1,a))if(i<256)else(Q(a,lambda a:R(a,(lambda b,d:lambda e,i,c:d(e,99,lambda v:B(lambda r:lambda i,v:b(e,i,lambda v2:d(v,v2,lambda v3:r(i+1,v3)))if(i<=5)else(c(v)))(2,v)))(lambda x,i,c:c((x<<i|x>>8-i)&255),lambda v1,v2,c:c(v1^v2)),lambda f:C(238,None,lambda c:C(63,c,lambda c:C(100,c,lambda c:C(254,c,lambda c:C(254,c,lambda c:C(113,c,lambda c:C(32,c,lambda c:C(123,c,lambda c:C(127,c,lambda c:C(38,c,lambda c:C(54,c,lambda c:C(125,c,lambda c:C(64,c,lambda c:C(215,c,lambda c:C(9,c,lambda c:C(139,c,lambda c:T(c,lambda g:I(64,lambda h:B(lambda j:lambda k,l:N(h,k*16,16,lambda m:B(lambda n:lambda o,m:R(m,lambda e,i,c:L(f,e,c),lambda m:N(m,0,7,lambda b0:N(m,7,9,lambda b1:P(b1,b0,lambda m:T(m,lambda p:U(p*g,16,lambda m:R(m,lambda e,i,c:c(e+i*i+23&255),lambda m:n(o+1,m))))))))if(o<16)else(P(l,m,lambda l:j(k+1,l))))(0,m))if(k<4)else(C(123,None,lambda s:C(72,s,lambda s:C(68,s,lambda s:C(10,None,lambda e:C(125,e,lambda e:C(182,None,lambda c:C(160,c,lambda c:C(106,c,lambda c:C(148,c,lambda c:C(161,c,lambda c:C(133,c,lambda c:C(162,c,lambda c:C(122,c,lambda c:C(77,c,lambda c:C(23,c,lambda c:C(118,c,lambda c:C(130,c,lambda c:C(200,c,lambda c:C(90,c,lambda c:C(66,c,lambda c:C(24,c,lambda c:C(210,c,lambda c:C(74,c,lambda c:C(91,c,lambda c:C(225,c,lambda c:C(193,c,lambda c:C(9,c,lambda c:C(219,c,lambda c:C(121,c,lambda c:C(177,c,lambda c:C(72,c,lambda c:C(70,c,lambda c:C(201,c,lambda c:C(5,c,lambda c:C(59,c,lambda c:C(7,c,lambda c:C(134,c,lambda c:C(25,c,lambda c:C(18,c,lambda c:C(8,c,lambda c:C(53,c,lambda c:C(22,c,lambda c:C(104,c,lambda c:C(170,c,lambda c:C(72,c,lambda c:C(167,c,lambda c:C(68,c,lambda c:C(48,c,lambda c:C(250,c,lambda c:C(11,c,lambda c:C(220,c,lambda c:C(144,c,lambda c:C(25,c,lambda c:C(183,c,lambda c:C(180,c,lambda c:C(164,c,lambda c:C(227,c,lambda c:C(15,c,lambda c:C(200,c,lambda c:C(148,c,lambda c:C(139,c,lambda c:C(109,c,lambda c:C(253,c,lambda c:C(152,c,lambda c:C(135,c,lambda c:C(230,c,lambda c:C(191,c,lambda c:C(121,c,lambda c:C(82,c,lambda c:S(c,l,lambda q:J(s,lambda:J(h,lambda:J(e,lambda:F(0))))if(q)else(F(1))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))(0,None)))))))))))))))))))))))(0,None))(*__import__('functional').all)
```

CPSython 문제의 main.py 파일이다.

역시 난해하다.

이것도 차근 차근 분석해보겠다.

# Reference

Python 람다 사용법: https://www.w3schools.com/python/python_lambda.asp

람다 대수: https://namu.wiki/w/%EB%9E%8C%EB%8B%A4%20%EB%8C%80%EC%88%98

함수형 프로그래밍https://namu.wiki/w/%ED%95%A8%EC%88%98%ED%98%95%20%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%98%EB%B0%8D#s-2

https://www.geeksforgeeks.org/functional-programming-paradigm/