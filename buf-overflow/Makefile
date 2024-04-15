CFLAGS := -I /usr/include/x86_64-linux-gnu -m32 -std=gnu99 -g -O0 -fno-stack-protector -fno-PIE -fno-pie -z execstack

ALL := shellcode.bin buf-overflow

all: $(ALL)

buf-overflow: buf-overflow.c
	$(CC) $(CFLAGS) -o $@ $<

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

%.bin: %.o
	objcopy -S -O binary -j .text $< $@

test: $(ALL)
	bash -c '(cat shellcode.bin; echo; cat) | strace -e execve ./buf-overflow'

run: $(ALL)
	bash -c '(cat shellcode.bin; echo; cat) | ./buf-overflow'
clean:
	rm -f $(ALL)