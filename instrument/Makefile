
CLANG = clang-sp

obj-m += kvm_hypercall.o

all:
	${CLANG}  -g -fsanitize-coverage=trace-pc-guard sanitize_converage.c -c 
	${CLANG}  -g example1.c sanitize_converage.o -fsanitize-coverage=trace-pc-guard -o example1
	${CLANG}  -g example2.c sanitize_converage.o -fsanitize-coverage=trace-pc-guard -o example2
	${CLANG}  -g example3.c sanitize_converage.o -fsanitize-coverage=trace-pc-guard -o example3
	${CLANG}  -g fuzzer.c -o fuzzer

clean:
	rm -rf sanitize_converage.o
	rm -rf example1
	rm -rf example2
	rm -rf example3
	rm -rf fuzzer
	rm -rf temp_*

