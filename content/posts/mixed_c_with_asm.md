---
title: "Mixed_c_with_asm"
date: 2023-09-25T11:31:57+08:00
draft: false
tags: ["c", "asm"]
categories: ["code"]
---

前几天群里提到的问题，简单记录下查阅到的方法。

## 在C中调用汇编中定义的函数

以Linux x86为例，用汇编语言编写一个hello_world函数，输出”Hello, World!\n”为例，其不需要任何参数，同时也没有返回值，相应的汇编代码如下：

```c
.globl hello_world
.type hello_world, @function
.section .data
message: .ascii "Hello, World!\n"
length: .int . - message
.section .text
hello_world:
  mov $4, %eax
  mov $1, %ebx
  mov $message, %ecx
  mov length, %edx
  int $0x80
  ret
```

由于使用gcc进行编译，因此汇编代码中使用AT&T语法。如果在用gcc编译时加上`-masm=intel`
选项，则可以使用intel语法。当然，也可以使用nasm对汇编语言进行汇编。

然后编写一个C程序调用该函数，如下：

```c
// gcc -m32 hello_world.c hello_world.s -o hello_world
extern void hello_world();
 
void main()
{
  hello_world();
}
```

下面通过参数传递将”Hello World!”传入到汇编代码中，修改如下：

```c
.globl hello_world
.type hello_world, @function
.section .text
hello_world:
  mov $4, %eax
  mov $1, %ebx
  mov 4(%esp), %ecx
  mov $0xd, %edx
  int $0x80
  ret
```

对应的C程序如下：

```c
extern void hello_world(char* value);
 
void main()
{
  hello_world("Hello World!\n");
}
```

### 在汇编中调用C中的函数

以`printf`为例，通过在汇编代码中调用`printf()`函数，示例代码如下：

```c
.extern printf
.globl main
.section .data
message: .ascii "hello,world!\n"
format: .ascii "%s"
.section .text
main:
    push $message
    push $format
    mov $0, %eax
    call printf
    add $0x8, %esp
    ret
```

1. 使用gcc编译汇编代码时，开始符号不再是_start而是main。由于main是一个函数，所以在最后必须要有`ret`指令；
2. 在调用函数之前，寄存器`eax`/`rax`的值必须设为0。

## 在C中嵌入汇编

```c
#include <stdio.h>
 
int sum(int a, int b)
{
  asm("addl %edi, %esi");
  asm("movl %esi, %eax");
}
 
int main()
{
  printf("%d\n", sum(2, 3));
  return 0;
}
```

在上面的示例代码中，也可以将多条汇编指令写在一起，如下：

```c
asm(
    "addl %edi, %esi\n\r"
    "movl %esi, %eax\n\r"
    );
```
