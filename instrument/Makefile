
obj-m += kvm_hypercall.o

all:
	clang -g -fsanitize-coverage=trace-pc-guard sanitize_converage.c -c
	clang example1.c sanitize_converage.o -fsanitize-coverage=trace-pc-guard -o example1
	clang example2.c sanitize_converage.o -fsanitize-coverage=trace-pc-guard -o example2
	clang example3.c sanitize_converage.o -fsanitize-coverage=trace-pc-guard -o example3
	clang -g fuzzer.c -o fuzzer

clean:
	rm -rf sanitize_converage.o
	rm -rf example1
	rm -rf example2
	rm -rf example3
	rm -rf fuzzer

