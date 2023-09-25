---
title: "Adb"
date: 2023-09-25T11:27:06+08:00
draft: false
---

## USE ADB in WSL

```bash
# ADB
export PATH="$PATH:/mnt/d/Tools/Android/SDK/platform-tools"
alias adb="/mnt/d/Tools/Android/SDK/platform-tools/adb.exe"
```

由于将adb的路径alias后，默认在sh中是找不到的，若想在sh脚本中使用ADB，需在脚本前添加以下代码:

```bash
#!/bin/bash -i
shopt -s expand_aliases
```

## Usage

```bash
adb push ready_to_push path
adb pull path_to_want
# if read-only system
adb remout
```