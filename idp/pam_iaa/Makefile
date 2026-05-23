CC      = gcc
CFLAGS  = -Wall -Wextra -fPIC -shared -O2
LDFLAGS = -lpam -lcurl
TARGET  = /lib/security/pam_vpnmfa.so
SRC     = src/pam_vpnmfa.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "Installed to $(TARGET)"

clean:
	rm -f $(TARGET)
