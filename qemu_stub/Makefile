
CLANG = clang
CLANGPP = clang++

all:
	${CLANG} --static stub.c ../fuzzer/fuzzer_mutite.c -o stub -I../kvm_hypercall -I../fuzzer

clean:
	rm -rf stub

