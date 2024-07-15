---
title: "Misc"
date: 2023-09-25T11:22:31+08:00
draft: false
tags: ["misc"]
categories: ["misc"]
---

## exp template

```python
from pwn import *
import sys
context.log_level = "debug"

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    p = remote("",)
    libc = ELF("./libc-2.31.so")

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a, b)
uu32 = lambda x   : u32(x.ljust(4, b'\0'))
uu64 = lambda x   : u64(x.ljust(8, b'\0'))
p32s = lambda *xs : flat([p32(x) for x in xs])
p64s = lambda *xs : flat([p64(x) for x in xs])

def debugf(b=0):
    if debug:
        if b:
            gdb.attach(p,"b *$rebase({b})".format(b = hex(b)))
        else:
            gdb.attach(p)
#context.terminal = ['tmux', 'splitw', '-h']

p.interactive()
```

## strace/socat

```
strace -fi /bin/socat 8899 ./challenge
```

## 查找错误git commit

```c
git bisect
```

## Debug Multithreading

```jsx
# gdb
set follow-fork-mode [parent|child]		# 设置调试[父进程/子进程]
set detach-on-fork [on|off]				# 未调试进程[继续执行/block在fork位置]
show follow-fork-mode
show detach-on-fork
info inferiors				# 查看正在调试的进程信息
info threads				# 查询线程
thread <thread number>		# 切换线程
```

```jsx
strace -ff -o test.txt ./your_binary
```

## hex dump

```c
void hexdump(const void *data, size_t size) 
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) 
    {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') 
        {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else 
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) 
        {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) 
            {
                dprintf(2, "|  %s \n", ascii);
            } 
            else if (i + 1 == size) 
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) 
                {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) 
                {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}
```

## ropper

```bash
ropper --file ./vmlinux --nocolor > gadgets.txt
```

## pow

```c
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <stdint.h>
#include <openssl/sha.h>
#define PREFIX_LEN 10
int main(int argc, char const *argv[])
{
	if (argc != 2 || strlen(argv[1]) != PREFIX_LEN)
		return -1;
	uint8_t buf[32];
	uint8_t out[SHA256_DIGEST_LENGTH];
	memcpy(buf, argv[1], PREFIX_LEN);
	for (uint64_t i = 0; i < 0xffffffffffff; ++i)
	{
		sprintf(buf + PREFIX_LEN, "%lu", i);
		SHA256(buf, strlen(buf), out);
		if (out[0] == 0 && out[1] == 0 && out[2] == 0 && (out[3] >> 5) == 0)
		{
			printf("%s\n", buf+10);
			break;
		}
	}
	return 0;
}

// gcc -O2 pow.c -lcrypto && ./a.out pzlYZX5ZEb && rm ./a.out
```

[pow](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7114b46c-fb76-4773-a514-f9cc8eeae1b4/pow.txt)

```python
from Crypto.Util.number import getPrime,bytes_to_long
from pwn import *
import urllib.parse as parse
from pwnlib.util.iters import bruteforce
from hashlib import sha256

def brute_force(prefix,s):
    return bruteforce(lambda x:sha256((x+prefix).encode()).hexdigest()==s,string.ascii_letters+string.digits,length=4,method='fixed')

p=remote('202.112.238.82', 10010)
p.recvuntil(b"sha256(XXXX+")
prefix = p.recvn(16).decode()
p.recvuntil(b") == ")
s = p.recvn(64).decode()
log.warning(prefix)
log.warning(s)
p.sendline(brute_force(prefix,s))

p.interactive()
```

## docker

```jsx
docker rm -f `docker ps -a -q`
```

### 自定义传参规则

```bash
void __usercall xxxxx(char* a1@<rdi>)
```

### 修改ida字符串显示

```bash
# puts(aStr) ---> puts("str")
change str seg -> r_x
```

## musl-gcc for kernel

```bash
# we cannot compile the exploit using musl-gcc, which produces small binary. The problem is that it seems that musl-gcc cannot find the <linux/xxx.h> header files. I solved this by preprocessing exploit using gcc -E and compiling the preprocessing output using musl-gcc
gcc -E exp.c -o fs/exp.c
musl-gcc -static fs/exp.c -o fs/exp
```

## remote exp upload

```bash
from pwn import *
import base64
context.log_level = "debug"

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

def do_pow(r):
    cmd = r.recvline()[:-1]
    rr = os.popen(cmd.decode())
    r.sendline(rr.read())

p = remote('babypf.seccon.games',9009)

do_pow(p)
try_count = 1
while True:
    log.info("no." + str(try_count) + " time(s)")
    p.sendline()
    p.recvuntil("/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1

    for i in range(count):
        p.recvuntil("/ $")

    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")
    randomization = (try_count % 1024) * 0x100000
    log.info('trying randomization: ' + hex(randomization))
    if not p.recvuntil(b"Rebooting in 1 seconds..", timeout=20):
        break
    log.warn('failed!')
    try_count += 1

log.success('success to get the root shell!')
p.interactive()
```

## debug

```bash
# debug.sh
gdb qemu-system-x86_64 --pid `ps -ef | grep qemu | awk '{print $2}' | head -n 1` -x ./debug.source
```

```bash
# debug.source
b *addr
c
```

## tmux

```jsx
set-option -g mouse on                  # 开启鼠标支持
setw -g mode-keys vi                    # 支持vi模式
set-option -s set-clipboard on          # 开启系统剪切板支持

## 鼠标滚轮模拟
# Emulate scrolling by sending up and down keys if these commands are running in the pane
tmux_commands_with_legacy_scroll="nano less more man"
bind-key -T root WheelUpPane \
    if-shell -Ft= '#{?mouse_any_flag,1,#{pane_in_mode}}' \
        'send -Mt=' \
        'if-shell -t= "#{?alternate_on,true,false} || echo \"#{tmux_commands_with_legacy_scroll}\" | grep -q \"#{pane_current_command}\"" \
            "send -t= Up Up Up" "copy-mode -et="'
bind-key -T root WheelDownPane \
    if-shell -Ft = '#{?pane_in_mode,1,#{mouse_any_flag}}' \
        'send -Mt=' \
        'if-shell -t= "#{?alternate_on,true,false} || echo \"#{tmux_commands_with_legacy_scroll}\" | grep -q \"#{pane_current_command}\"" \
            "send -t= Down Down Down" "send -Mt="'
```

## patchelf

```c
patchelf --set-interpreter ld_path xxx
patchelf --set-rpath libc_dir xxx
```

## ubuntu
```bash
export DEBIAN_FRONTEND=noninteractive

sudo apt update
sudo apt install -y ca-certificates

#replace ubuntu source
sudo sed -i "s@http://.*archive.ubuntu.com@https://mirrors.bfsu.edu.cn@g" /etc/apt/sources.list
sudo sed -i "s@http://.*security.ubuntu.com@https://mirrors.bfsu.edu.cn@g" /etc/apt/sources.list

#install many tools
sudo apt update
sudo apt install -y net-tools python3 python3-pip python-is-python3 git vim zsh gdb gdb-multiarch ipython3 musl-tools curl libc6-dbg
sudo apt remove unattended-upgrades

#replace pip source
pip config set global.index-url https://mirrors.bfsu.edu.cn/pypi/web/simple
python -m pip install --upgrade pip

#install pwntools
pip3 install pwntools

#install pwndbg
cd ~ && git clone https://github.com/pwndbg/pwndbg.git
cd ~/pwndbg && ./setup.sh

#install pwngdb
# cd ~ && git clone https://github.com/MrRtcl/Pwngdb.git
# user='mrr'
# pwndbg='/home/'$user'/pwndbg'
# pwngdb='/home/'$user'/Pwngdb/pwndbg'
# cp $pwngdb/pwngdb.py $pwndbg/pwndbg/pwngdb.py
# cp $pwngdb/angelheap.py $pwndbg/pwndbg/angelheap.py
# cp $pwngdb/commands/pwngdb.py $pwndbg/pwndbg/commands/pwngdb.py
# cp $pwngdb/commands/angelheap.py $pwndbg/pwndbg/commands/angelheap.py
# sed -i -e '/import pwndbg.commands.xor/a \ \ \ \ import pwndbg.commands.pwngdb' $pwndbg/pwndbg/commands/__init__.py
# sed -i -e '/import pwndbg.commands.xor/a \ \ \ \ import pwndbg.commands.angelheap' $pwndbg/pwndbg/commands/__init__.py

# install angr
pip3 install angr
pip3 install z3-solver

# #install iTermBackend
# git clone https://github.com/DarkEyeR/iTermBackend.git
# cd ~/iTermBackend && ./setup.sh

# #ddns-go
# mkdir ddns-go
# wget https://github.com/jeessy2/ddns-go/releases/download/v4.5.6/ddns-go_4.5.6_linux_x86_64.tar.gz -O ./ddns-go/ddns-go.tar.gz
# cd ddns-go && tar -zxvf ddns-go.tar.gz

install oh-my-zsh
sudo apt install -y zsh wget
sh -c "$(wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"
```