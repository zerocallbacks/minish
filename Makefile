CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c99 -pedantic -Os
TARGET = minish
SRC = shell.c
DESTDIR ?=
PREFIX ?= /usr

.PHONY: all static install uninstall test deb rpm clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
	strip --strip-all $(TARGET) 2>/dev/null || true

static: $(SRC)
	@if $(CC) $(CFLAGS) -static $(SRC) -o $(TARGET) 2>/dev/null; then \
		echo "[+] Built static binary $(TARGET)"; \
	else \
		echo "[!] Static build failed, building optimized dynamic binary"; \
		$(CC) $(CFLAGS) $(SRC) -o $(TARGET); \
	fi
	strip --strip-all $(TARGET) 2>/dev/null || true

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	@# On non-UsrMerge systems where /bin is distinct from /usr/bin, create symlink
	@if [ -d "$(DESTDIR)/bin" ] && [ ! -L "$(DESTDIR)/bin" ] && [ ! -e "$(DESTDIR)/bin/$(TARGET)" ]; then \
		ln -sf $(PREFIX)/bin/$(TARGET) $(DESTDIR)/bin/$(TARGET); \
		echo "Created compatibility symlink /bin/$(TARGET)"; \
	fi
	@if [ -z "$(DESTDIR)" ] && [ -f /etc/shells ]; then \
		for sh_path in /bin/$(TARGET) $(PREFIX)/bin/$(TARGET); do \
			if ! grep -q "^$$sh_path$$" /etc/shells; then \
				echo "$$sh_path" >> /etc/shells; \
				echo "Registered $$sh_path in /etc/shells"; \
			fi; \
		done; \
	fi

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	@if [ -L "$(DESTDIR)/bin/$(TARGET)" ]; then \
		rm -f $(DESTDIR)/bin/$(TARGET); \
	fi
	@if [ -z "$(DESTDIR)" ] && [ -f /etc/shells ]; then \
		grep -v "$(TARGET)$$" /etc/shells > /etc/shells.tmp || true; \
		mv /etc/shells.tmp /etc/shells; \
		echo "Deregistered $(TARGET) from /etc/shells"; \
	fi

test: $(TARGET)
	./$(TARGET) test_suite.sh

deb:
	chmod +x package_deb.sh
	./package_deb.sh

rpm:
	chmod +x package_rpm.sh
	./package_rpm.sh

clean:
	rm -f $(TARGET) minish_static minish_dbg *.o *.deb *.rpm
	rm -rf build_deb rpmbuild minish-1.0.0
