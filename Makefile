all: list-cng-rng-providers.zip.sha256

list-cng-rng-providers.exe: main.c
	gcc -o $@ -std=gnu99 -pedantic -Os -Wall -m64 -municode /c/windows/system32/bcrypt.dll main.c
	strip $@

list-cng-rng-providers.zip: list-cng-rng-providers.exe
	zip -9 $@ $<

list-cng-rng-providers.zip.sha256: list-cng-rng-providers.zip
	sha256sum $< >$@

clean:
	rm -f list-cng-rng-providers.*

.PHONY: all clean
