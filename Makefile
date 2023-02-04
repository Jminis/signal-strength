LDLIBS += -lpcap

all: signal-strength

signal-strength: signal-strength.c

clean:
	rm -f signal-strength *.o
