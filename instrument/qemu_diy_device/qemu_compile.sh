cd ~/Desktop/vm_qemu/qemu_fuzzer/instrument
cp ./sanitize_converage.o ../../qemu-5.0.0/
cd ~/Desktop/vm_qemu/qemu-5.0.0/
./configure --cc="/usr/bin/clang-sp" --extra-cflags="-fsanitize-coverage=trace-pc-guard -fPIE"
make -j14 CFLAGS="/home/fuzzing/Desktop/vm_qemu/qemu-5.0.0/sanitize_converage.o -Wunknow-warning-option"
