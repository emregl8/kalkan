run:
	sudo -v && python3 kalkan

deps:
	sudo apt-get install -y python3-gi gir1.2-gtk-4.0 gir1.2-gdk-4.0 dbus-x11

.PHONY: run deps