---
title: "Apk杂记"
date: 2024-02-19T11:27:06+08:00
draft: false
tags: ["adb"]
categories: ["pwn"]
---

## adb

```c
adb devices # 查看设备
adb shell
```

## ida调试so

一般断在Jni_onload

```c
adb forward tcp:23946 tcp:23946
adb shell
```

```c
cd /data/local/tmp
./androidserver
```

androidserver的位数应该和so对应，不过跑以下看能不能搜到进程就知道了。

ida侧选择Debugger->attach->Remote ARM Linux/Android debugger，选择attach，找到app进程attach上就行。

## jdwp

```c
am start -D -n  com.bin.MathGame/.MainActivity
```

在手机上执行

```c
ps -ef | grep mathgame # getpid
```

```c
adb forward tcp:8700 jdwp:{pid}
jdb -connect “com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700”
```

## jeb

https://bbs.pediy.com/thread-268316.htm

## frida

### frida-hexdump

用来dump运行时的dex，常用于脱壳。

```bash
pip3 install frida-dexdump
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043
# 运行app
frida-dexdump -FU
```

使用d2j_dex2jar反编译，然后拖入jadx分析。

## frida_hook_libart

https://github.com/lasting-yang/frida_hook_libart

可以查看动态注册的jni_onload
```bash
frida -U -f package_name -l hook_RegisterNatives.js
```