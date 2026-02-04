include Makefile.vars

# make all
.PHONY: all
all: install vmlinux libbpf monitor.bpf.o

# install required package
.PHONY: install
install:
#	apt update
#	apt upgrade // if want to upgrade, import this option
	apt install libbpf-dev -y
	apt-get install libelf-dev -y
	apt-get install llvm -y
	apt-get install clang -y
	apt install linux-cloud-tools-generic -y
	apt install linux-tools-common -y
	apt install linux-tools-generic -y
# TODO: change below line
	apt install linux-tools-5.15.0-89-generic -y

# make vmlinux.h in this directory
.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# update libbpf libbpf directory
LIBBPF = $(CURDIR)/libbpf
.PHONY: libbpf
libbpf:
	git submodule update --init --recursive

# make monitor.bpf.o
.PHONY: monitor.bpf.o
monitor.bpf.o: monitor.c vmlinux.h
	clang $(KF) -Xclang -disable-llvm-passes -c $< -o - | opt -O2 -mtriple=bpf-pc-linux | llvm-dis | llc -march=bpf -mcpu=probe -filetype=obj -o $@

# delete all object file and vmlinux.h
.PHONY: clean
clean:
	rm -rf *.o vmlinux.h