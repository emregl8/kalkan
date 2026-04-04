run: build
	sudo -v && python3 kalkan

build:
	gcc -O2 -Wall -o modules/clevis_bind_helper modules/clevis_bind_helper.c
	chmod 700 modules/clevis_bind_helper
	sudo apt-get install -y -q pkg-config libgtk-4-dev libssl-dev
	gcc -O2 -Wall -o modules/grub_password_helper modules/grub_password_helper.c \
		$$(pkg-config --cflags --libs gtk4) -lcrypto
	chmod 700 modules/grub_password_helper

deps:
	sudo apt-get install -y python3-gi gir1.2-gtk-4.0 gir1.2-gdk-4.0 dbus-x11

.PHONY: run build deps