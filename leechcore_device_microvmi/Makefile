CC=gcc
CFLAGS  += -I. -I../includes -D LINUX -shared -fPIC -fvisibility=hidden
LDFLAGS += -g -shared -lmicrovmi
DEPS = 
OBJ = leechcore_device_microvmi.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechcore_device_microvmi: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o leechcore_device_microvmi.so $(LDFLAGS)
	rm *.o
	mkdir -p ../files
	mv leechcore_device_microvmi.so ../files/

clean:
	rm -f *.o
