@echo off
xenon-as.exe -be -many %1 -o compiled.elf
xenon-objcopy.exe compiled.elf -O binary patches.bin
del compiled.elf
echo Done!