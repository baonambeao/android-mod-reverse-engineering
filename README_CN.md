---
title: "技术报告：绕过 Android 应用中的服务器身份验证与防篡改机制"
date: "2026-04-22"
tags: ["逆向工程", "Android", "ARM64", "Smali", "IDA Pro", "网络安全"]
description: "详细说明了在目标 Android 应用程序中绕过服务器身份验证并禁用内部防篡改层的分析步骤、工作流程及使用的工具。"
---

# 技术报告：绕过 Android 应用中的服务器身份验证与防篡改机制

本文档提供了关于绕过目标 Android 应用程序（Mod Menu 模组菜单）中的服务器身份验证机制并禁用其内部防篡改层的全面技术总结。

本流程涵盖了从 Java 层的初步反编译分析，到使用 ARM64 汇编语言对 C/C++（Native）层进行深度修补，以及最终安全部署修补后 APK 的高级技术。

---

## 阶段 1：反编译与 Java/Smali 分析

首要目标是了解应用程序的结构并定位核心身份验证机制。

### 1. APK 提取与反编译
* **使用工具：** `apktool`
* **操作：** 运行 `apktool d <apk-file>` 将原始 APK（`Minionscheats V3 VN 4.3 64Bit.apk`）反编译为 Smali 代码、XML 清单文件和资源文件。此步骤允许我们读取和分析 Java 层的源代码（已编译为 Dalvik 字节码）。

### 2. 定位身份验证机制
* **目标：** 准确找到应用程序将许可证密钥（账号/密码）发送到服务器的位置。
* **分析过程：** 通过在 Smali 源码中搜索 `http`、`login` 和 `Check` 等关键字，我们成功隔离了 `com.rubel.kutta.Launcher` 类。
* **识别出的工作流：**
    1. 应用程序从 UI 接收账号/密码字符串。
    2. 调用位于共享库 `libKuttaVai.so` 中的 Native（C/C++）函数 `native_Check(String user, String pass)`。
    3. 该 Native 函数负责向硬编码的服务器发起网络请求以验证密钥，随后返回一个结果字符串（例如 `"OK"`）。
    4. Java 层实现了一个回调（`Launcher$100000003`）来接收此字符串。如果返回的字符串完全匹配 `"OK"`，应用程序将继续初始化菜单。

### 3. Java 层干预（Smali 修补）
* **初步操作：** 修改了 `Launcher$100000003` 类的 Smali 代码。
* **修改内容：** 将条件判断 `if (result.equals("OK"))` 更改为始终计算为 `True` 的无条件跳转（绕过了 `user or game not registered` 错误块）。
* **结果：** 菜单 UI 成功出现。然而，内部功能（如 ESP 和 Aimbot）完全无法运行，且游戏频繁崩溃。
* **结论：** 主要的安全检查并不在 Java 层，而是深深嵌入在 Native（C/C++）层中。

---

## 阶段 2：Native 层分析与修补（C/C++）

由于 Java 层的修补不够充分，我们使用 **IDA Pro** 深入分析 `libKuttaVai.so` 库的 ARM64 机器码。该层包含了 Mod 的核心逻辑及其主要的防篡改机制。

### 1. 修复初始化崩溃（SIGILL）
* **问题：** 将 `.so` 库加载到内存时，游戏立即因 SIGILL（非法指令）信号而崩溃。
* **分析：** 崩溃日志（`crash_log.txt`）指向地址 `0x5f3470`。该函数位于 `.init_array` 段中（在 `JNI_OnLoad` 之前自动执行）。它包含库完整性检查，如果检测到任何修改，会故意触发崩溃。
* **修补方案：** 使用 `RET`（返回）指令覆盖整个函数，强制其立即退出而不执行任何检查。
* **注入的 Hex 代码：** `C0 03 5F D6`（等同于 ARM64 的 `RET`）。

### 2. 分析 `native_Check` 与“总开关”标志位
* **问题：** 为什么菜单出现了，但 ESP 拒绝渲染？
* **分析：** `native_Check` 函数（位于 `0xF922C`）不仅仅处理网络身份验证；它还充当整个系统的**“总开关”**（Master Switch）。
    * 在获得成功的服务器响应后，它会将值 `1` 写入全局变量 `byte_B242A0` 中。
    * 然后它分配内存并在 `qword_B24150` 和 `qword_B24168` 处填充两个区域 Token 字符串。
    * 所有功能模块（ESP，Aimbot）不断轮询 `byte_B242A0`。如果该值保持为 `0`，它们将立即停止执行。因为我们最初的 Smali 修补仅强制 Java 层忽略验证失败，Native 层从未被正确初始化。

### 3. 绕过 ESP 防篡改检查（`memcmp`）
* **分析 ESP 渲染函数（`sub_E2004`）：** 该函数包含一个安全循环。它反复使用系统 `.memcmp` 函数对两个字符串变量 `qword_B24150` 和 `qword_B24168` 执行逐字节比较。如果这些字符串不同（或未正确初始化大小），则中止 ESP 渲染。
* **绕过策略（Mocking 模拟）：** 我们没有逆向工程复杂的 Token 生成算法，而是选择了“模拟”方法：
    * 强制两个变量的大小均为 `8`。
    * 不提供任何数据。因此，两个内存区域仅包含 NULL 字节（`0x00`）。
    * *原理：* 当 `.memcmp` 比较两个大小相同的 NULL 字符串时，它返回 `0`（完全匹配）。这成功欺骗了防篡改循环。

### 4. 重写 `native_Check` 函数（汇编语言）
结合上述分析，我直接在 `native_Check` 函数的入口点（地址 `0xF922C`）注入了新的 ARM64 机器码：

```assembly
# 1. 启用总开关 (byte_B242A0 = 1)
MOV W10, #1
ADRP X9, 0xB242A0
ADD X9, X9, 0x2A0
STRB W10, [X9]

# 2. 模拟 Token 1 (大小 = 8，内容 = NULL)
ADRP X9, 0xB24150
ADD X9, X9, 0x150
MOV W10, #8
STRB W10, [X9]

# 3. 模拟 Token 2 (大小 = 8，内容 = NULL)
ADRP X9, 0xB24168
ADD X9, X9, 0x168
STRB W10, [X9]

# 4. 将字符串 "OK" 返回给 Java 层
# (使用 JNIEnv 指针调用 NewStringUTF)
LDR X8, [X0]           # 获取 JNIEnv*
ADRP X1, 0x304000      # 指向保存字符串 "OK\0" 的地址
ADD X1, X1, 0xF00
LDR X8, [X8, 0x538]    # 从 JNIEnv 加载 NewStringUTF 函数指针
BR X8                  # 分支跳转到函数并返回结果
