---
title: "Crushing a Mod Menu's Server Auth & Anti-Tamper Checks (Android RE Write-up)"
date: "2026-04-22"
tags: ["Reverse Engineering", "Android", "ARM64", "Smali", "IDA Pro", "Writeup"]
---

# How I Crushed a Mod Menu's Server Auth & Anti-Tamper Checks

Hey everyone. I recently spent some time tearing down an Android Mod Menu APK (`MNS V3 4.3`). The goal was simple on paper: bypass the server-side license checks and disable the internal anti-tamper mechanisms so the mod could run offline and unrestricted. 

What started as a basic Java-layer edit quickly turned into a deep dive into ARM64 assembly and native library patching. Here’s the step-by-step write-up of how I pulled it off.

---

## The Trap: Java-Layer Smali Patching

I started with the usual approach: throwing the APK into `apktool` to see what the Java layer was doing. 

I was looking for the authentication mechanism, so I grepped the decompiled Smali code for the usual suspects—`http`, `login`, `Check`. This led me straight to a class called `com.rubel.kutta.Launcher`.

**Here’s how the auth flow looked:**
1. The app grabs the Username/Password from the UI.
2. It passes them to a native C/C++ function called `native_Check()` inside `libKuttaVai.so`.
3. The native function hits a hardcoded server, validates the key, and returns a string.
4. Back in the Java layer, a callback (`Launcher$100000003`) checks if the string exactly equals `"OK"`.

I thought, *"Sweet, easy win."* I jumped into the Smali code for that callback and changed the `if (result.equals("OK"))` check into an unconditional jump. Basically, no matter what the server said, the app would act like it got an "OK".

I repacked it, ran it, and the Menu UI popped up perfectly. But there was a catch. 

None of the actual features (like ESP or Aimbot) worked, and the game kept crashing. The Java patch was basically a placebo. The *real* security checks were buried deep inside the native C/C++ layer.

---

## Down the Rabbit Hole: Native Layer Analysis

Alright, time to open up `libKuttaVai.so` in **IDA Pro** and look at the ARM64 machine code. 

### 1. Fixing the Auto-Crash (SIGILL)
The first massive headache was that just loading the `.so` library into memory caused a hard crash via a SIGILL (Illegal Instruction) signal. 

Looking at the crash logs, the game was dying at memory address `0x5f3470`. I checked IDA, and this function was sitting in the `.init_array` section. For those who don't know, `.init_array` executes *before* `JNI_OnLoad`. The devs had put integrity checks in there designed to intentionally nuke the app if it detected any tampering.

Instead of trying to untangle their logic, I just nuked the function back. I overwrote the start of the function with a `RET` instruction (`C0 03 5F D6` in hex). The function now immediately exits without running a single check. Crash fixed.

### 2. The "Master Switch"
Now the game booted, the menu showed up, but the ESP still wouldn't draw on screen. Why?

I went back to that `native_Check` function (at `0xF922C`). It turns out it wasn't just doing a network request. It was acting as a master switch for the entire mod. 
* If auth succeeds, it writes a `1` to a global variable (`byte_B242A0`).
* It then generates two memory "Tokens" (`qword_B24150` and `qword_B24168`).
* Every single cheat module (ESP, Aimbot) constantly polls that global variable. If it's `0`, they refuse to run. 

Because my earlier Smali patch only lied to the Java UI, the native layer never flipped this switch.

### 3. Deceiving the Anti-Tamper Loop
I dug into the ESP rendering function and found a nasty little security loop. It was constantly using the system's `.memcmp` function to compare those two memory Tokens byte-by-byte. If they didn't match perfectly, it aborted the ESP.

I really didn't want to reverse-engineer their entire cryptographic token generation algorithm. So, I used a mocking technique. 
I forced both variables to have a size of `8`, but I didn't give them any data. This left both memory regions filled entirely with NULL bytes (`0x00`). 

When `.memcmp` compares two identically sized strings of NULL bytes, it returns `0` (an exact match). The anti-tamper loop was completely fooled.

### 4. Writing the Custom ARM64 Patch
With the logic figured out, I wrote a custom assembly patch and injected it right at the entry point of `native_Check`:

```assembly
# 1. Flip the Master Switch to ON (byte_B242A0 = 1)
MOV W10, #1
ADRP X9, 0xB242A0
ADD X9, X9, 0x2A0
STRB W10, [X9]

# 2. Mock Token 1 (Size = 8, content = NULL)
ADRP X9, 0xB24150
ADD X9, X9, 0x150
MOV W10, #8
STRB W10, [X9]

# 3. Mock Token 2 (Size = 8, content = NULL)
ADRP X9, 0xB24168
ADD X9, X9, 0x168
STRB W10, [X9]

# 4. Return "OK" to Java (using JNIEnv)
LDR X8, [X0]           # Grab JNIEnv*
ADRP X1, 0x304000      # Point to "OK\0" stored in .bss
ADD X1, X1, 0xF00
LDR X8, [X8, 0x538]    # Load NewStringUTF pointer
BR X8                  # Branch and return
