.PHONY: all install

INSTALL_DIR := /usr/lib/go-luks-suspend

all: go-luks-suspend initramfs-suspend

update-version:
ifdef VERSION
	/usr/bin/sed -i "s/^const Version = .*/const Version = \"$(VERSION)\"/" pkg/goLuksSuspend/version.go
endif

go-luks-suspend: update-version
	go build ./pkg/goLuksSuspend/cmd/go-luks-suspend

initramfs-suspend: update-version
	go build ./pkg/goLuksSuspend/cmd/initramfs-suspend

install: all
	install -Dm755 go-luks-suspend "$(DESTDIR)$(INSTALL_DIR)/go-luks-suspend"
	install -Dm755 initramfs-suspend "$(DESTDIR)$(INSTALL_DIR)/initramfs-suspend"
	install -Dm644 initcpio-hook "$(DESTDIR)/usr/lib/initcpio/install/suspend"
	install -Dm644 go-luks-suspend.service "$(DESTDIR)/usr/lib/systemd/system/go-luks-suspend.service"

clean:
	rm -f go-luks-suspend initramfs-suspend

# vim:set sw=4 ts=4 noet:
