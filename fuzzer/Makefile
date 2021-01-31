
all:
	clang++ -g -fsanitize=address fuzzer.cc fuzzer_mutite.c -o fuzzer -I../kvm_hypercall -I../instrument -pthread

clean:
	rm -rf fuzzer

