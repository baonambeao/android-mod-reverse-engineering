---
title: "Bypassing Server Authentication  Android Apps"
date: "2026-04-22"
tags: ["Reverse Engineering", "Android", "ARM64", "Smali", "IDA Pro", "Cybersecurity"]
description: "A comprehensive technical summary of the workflow, tools, and analytical steps taken to bypass server authentication and disable internal anti-tamper layers within a target Android application."
---

---

## Phase 1: Decompilation and Java/Smali Analysis

Our first goal is to understand the application's structure and locate the core authentication mechanism. 

### 1. APK Extraction and Decompilation
The journey begins with extracting the target APK (`Minionscheats V3 VN 4.3 64Bit.apk`).
* **Tool Used:** `apktool`
* **Action:** By running `apktool d <apk-file>`, we decompiled the original APK into Smali code, XML manifests, and resources. This crucial step allowed us to read and analyze the Java-layer source code, which is compiled as Dalvik bytecode.

### 2. Locating the Authentication Mechanism
* **Objective:** Pinpoint exactly where the application sends the license key (User/Pass) to its server.
* **Analysis:** I searched through the Smali source using keywords like `http`, `login`, and `Check`. This led me to isolate the `com.rubel.kutta.Launcher` class.
* **Identified Flow:**
    1. The app receives the User/Pass string from the UI.
    2. It invokes a Native (C/C++) function named `native_Check(String user, String pass)`, located inside the `libKuttaVai.so` shared library.
    3. This Native function makes a network request to a hardcoded server to validate the key and returns a result string (e.g., `"OK"`).
    4. The Java layer uses a Callback (`Launcher$100000003`) to receive this string. If it exactly matches `"OK"`, the Menu initializes.

### 3. Java-Layer Intervention (Smali Patching)
* **Initial Action:** I modified the Smali code of the `Launcher$100000003` class.
* **Modification:** I changed the conditional check `if (result.equals("OK"))` to an unconditional jump that always evaluates to `True`, effectively bypassing the `user or game not registered` error block.
* **Result:** The Menu UI successfully appeared! However, the internal features (like ESP and Aimbot) were completely non-functional, and the game suffered frequent crashes. 
* **Conclusion:** The primary security checks were *not* residing in the Java layer. They were deeply embedded in the Native (C/C++) layer.

---

## Phase 2: Native Layer Analysis and Patching (C/C++)

Since the Java patch was insufficient, it was time to dive into the `libKuttaVai.so` library using **IDA Pro** to analyze the ARM64 machine code. This layer contains the core logic and the primary anti-tampering mechanisms.

### 1. Fixing the Initialization Crash (SIGILL)
* **Issue:** Loading the `.so` library into memory caused the game to immediately crash with a SIGILL (Illegal Instruction) signal.
* **Analysis:** Crash logs (`crash_log.txt`) pointed directly to address `0x5f3470`. This function resides in the `.init_array` section (which executes automatically before `JNI_OnLoad`). It contains integrity checks designed to intentionally trigger a crash if any modifications are detected.
* **The Patch:** I overwrote the entire function with a `RET` (Return) instruction. This forces the function to exit immediately without ever executing the checks.
* **Injected Hex:** `C0 03 5F D6` (ARM64 equivalent to `RET`).

### 2. Analyzing `native_Check` and the "Master Switch"
* **Issue:** Why did the Menu appear earlier, but the ESP refused to draw?
* **Analysis:** The `native_Check` function (at `0xF922C`) does much more than handle network auth; it acts as a **"Master Switch"** for the whole system.
    * Upon a successful server response, it writes the value `1` to a global variable: `byte_B242A0`.
    * It allocates memory and populates two Region Token strings at `qword_B24150` and `qword_B24168`.
    * All functional modules (ESP, Aimbot, etc.) continuously poll `byte_B242A0`. If it remains `0`, they halt execution. Because our initial Smali patch only bypassed the Java UI check, this Native initialization never occurred.

### 3. Bypassing the ESP Anti-Tamper Check (`memcmp`)
* **Analyzing the ESP Rendering Function (`sub_E2004`):** This function contains a strict security loop. It repeatedly uses the system `.memcmp` function to perform a byte-by-byte comparison of the two token strings (`qword_B24150` and `qword_B24168`). If they differ or have the wrong size, ESP rendering aborts.
* **Bypass Strategy (Mocking the Tokens):** Instead of reverse-engineering the complex Token generation algorithm, I opted for a simpler "Mocking" approach:
    * Forced the size of both variables to `8`.
    * Provided no data, leaving both memory regions filled with NULL bytes (`0x00`).
    * *Why this works:* When `.memcmp` compares two identically sized NULL strings, it returns `0` (Exact Match), successfully deceiving the anti-tamper loop.

### 4. Rewriting the `native_Check` Function (Assembly)
Combining all the findings, I injected new ARM64 machine code directly at the entry point of the `native_Check` function (at `0xF922C`):

```assembly
# 1. Enable Master Switch (byte_B242A0 = 1)
MOV W10, #1
ADRP X9, 0xB242A0
ADD X9, X9, 0x2A0
STRB W10, [X9]

# 2. Mock Token 1 (Size = 8)
ADRP X9, 0xB24150
ADD X9, X9, 0x150
MOV W10, #8
STRB W10, [X9]

# 3. Mock Token 2 (Size = 8)
ADRP X9, 0xB24168
ADD X9, X9, 0x168
STRB W10, [X9]

# 4. Return the string "OK" to the Java layer
# (Uses the JNIEnv pointer to invoke NewStringUTF)
LDR X8, [X0]           # Get JNIEnv*
ADRP X1, 0x304000      # Point to the address holding the string "OK\0"
ADD X1, X1, 0xF00
LDR X8, [X8, 0x538]    # Load NewStringUTF function pointer from JNIEnv
BR X8                  # Branch to function and Return result
