CFLAGS = -DNETFILTER_VERSION=\"1.1.1\" -fPIC

libipt_ULOG.so: libipt_ULOG_sh.o
	ld -shared libipt_ULOG_sh.o -o libipt_ULOG.so

libipt_ULOG_sh.o: libipt_ULOG.c 
	gcc $(CFLAGS) -c libipt_ULOG.c -o libipt_ULOG_sh.o

clean: 
	rm -f libipt_ULOG_sh.o libipt_ULOG.so
