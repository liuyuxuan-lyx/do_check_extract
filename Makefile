all: do_check_extract.bc klee_main.bc

do_check_extract.bc:
	clang -I. -Iinclude -I../klee-workdir/klee/include -emit-llvm -g -c -o do_check_extract.bc do_check_extract.c

klee_main.bc:
	clang -I. -Iinclude -I../klee-workdir/klee/include -emit-llvm -g -c -o klee_main.bc klee_main.c

.PHONY: clean
clean:
	rm *.bc *.o