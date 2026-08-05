# connect-check — корневой Makefile
#
#   make / make package — метаданные пакета (resources.conf, VERSION)
#   make gui            — GUI текущей ОС (движок in-process)
#   make release        — GUI all + dist/ (GUI-only)
#   make cli            — отладочный CLI/probes (не в релизе)
#   make version / clean / help

.PHONY: all cli package gui release dist version clean help

all: package

cli:
	$(MAKE) -f Makefile.diagnose all
	$(MAKE) -f Makefile.probes all

package:
	$(MAKE) -f Makefile.package

gui:
	$(MAKE) -f Makefile.gui

dist:
	$(MAKE) -f Makefile.package dist

release:
	@test -f VERSION || { echo "нет VERSION"; exit 1; }
	@ver=$$(tr -d '[:space:]' < VERSION); \
	  echo "$$ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "VERSION должен быть semver X.Y.Z, сейчас: $$ver"; exit 1; }; \
	  echo "release connect-check $$ver (GUI-only)"
	$(MAKE) -f Makefile.package
	$(MAKE) -f Makefile.gui package-all
	$(MAKE) -f Makefile.package dist
	@test -d bin/ConnectCheck-mac.app || { echo "release: нет mac GUI — abort"; exit 1; }
	@test -f bin/connect-check-gui-win.exe || { echo "release: нет win GUI — abort"; exit 1; }
	@test -x bin/connect-check-gui-linux || { echo "release: нет linux GUI — abort"; exit 1; }
	@test -f bin/resources.conf || { echo "release: нет resources.conf — abort"; exit 1; }

version:
	@echo "connect-check $$(tr -d '[:space:]' < VERSION)"

clean:
	$(MAKE) -f Makefile.diagnose clean
	$(MAKE) -f Makefile.probes clean
	$(MAKE) -f Makefile.gui clean
	$(MAKE) -f Makefile.package clean-package
	rm -rf build dist

help:
	@echo "connect-check  version=$$(cat VERSION 2>/dev/null || echo '?')"
	@echo "  make / make package   — resources.conf + VERSION в bin/"
	@echo "  make gui              — GUI текущей ОС (движок встроен)"
	@echo "  make release          — GUI all + dist/ архивы (GUI-only)"
	@echo "  make dist             — архивы (нужен собранный GUI)"
	@echo "  make cli              — отладочный connect-check + probe-* (не в релизе)"
	@echo "  make clean"
	@echo "См. docs/VERSIONING.md и .cursor/rules/"
