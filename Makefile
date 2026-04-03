run: build
	sudo -v && python3 kalkan

build:
	gcc -O2 -Wall -o modules/clevis_bind_helper modules/clevis_bind_helper.c
	chmod 700 modules/clevis_bind_helper

deps:
	sudo apt-get install -y python3-gi gir1.2-gtk-4.0 gir1.2-gdk-4.0 dbus-x11

.PHONY: run build deps