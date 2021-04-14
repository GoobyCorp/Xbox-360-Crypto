# Xbox 360 Crypto

A collection of tools I've written for the Xbox 360

Most things work across Windows, macOS, and Linux but anything that requires packing or unpacking the CE/SE/5BL will only work on Windows.

This tool suite is BYOK (Bring Your Own Keys), you can verify your keys with [verify_keys.py](verify_keys.py)

### [XeCrypt.py](XeCrypt.py)
A library that includes most of the Xbox 360's cryptographic library.

### [harness.py](harness.py)
A script to test XeCrypt to make sure it's functioning properly.

### [shadowboot.py](shadowboot.py)
A shadowboot builder and extractor script.

### [kv_checker.py](kv_checker.py)
A script that checks KV's to see if they're banned or unbanned.

### [kv_tool.py](kv_tool.py)
A script to encrypt a KV and generate fuses for a zero fuse console.

### [nand_tool.py](nand_tool.py)
A script that allows for modifying a NAND image for the Xbox 360, it automatically recalculates ECC bits and has address translation support.

### [patch_parser.py](patch_dumper.py)
A script that attempts to dump patch binaries to assembly.

### [xdk_extract.py](xdk_extract.py)
A script to dump XDK and recovery images to cabinet files.

### [STFS.py](STFS.py)
My attempt at a STFS library in python.

### [xval.py](xval.py)
It's xval but in python, it checks to see if your console is possibly flagged.

### [xkelib_exports.py](xkelib_exports.py)
This script was made to automate the SDK dumping process so that I can dynamically update exports for xkelib.

### [xcp.py](xcp_dumper.py)
A script made to decrypt XCP files delivered by the Xbox 360 CDN.

### [hvx_signer.py](hvx_signer.py)
A script that can sign HvKeysExecute payloads.

### [xextool.py](xextool.py)
My attempt at making an xextool entirely in python, it didn't go so well :cry:

### [cpu_key.py](cpu_key.py)
A script that can generate valid CPU keys.

### [assembler.py](assembler.py)
An interactive script that assembles PPC ASM to bytes in realtime.

### [patch_build_task.py](patch_build_task.py)
This script runs three scripts for building a zero fuse image:
* [patch_compile.py](patch_compile.py) - This script compiles patches for the zero fuse 4BL and 5BL.
* [se_patcher.py](se_patcher.py) - This script patches the 4BL/5BL with the patches generated with the compiler.
* [patch_checker.py](patch_checker.py) - This script checks the patches to make sure there's no address conflicts.

### [exp_build_task.py](exp_build_task.py)
This script builds the HV Peek/Poke expansion and outputs to a .h file, it uses:
* [build_lib.py](build_lib.py) - This script contains assemble_patch which is useful for assembling PPC assembly.
* [exp_signer.py](exp_signer.py) - A script to sign HV expansions, this works on test kits using the 11775.3 recovery without modifications to the HV.
* [bin2lang.py](bin2lang.py) - A script to convert binaries into a format readable by a few programming languages.