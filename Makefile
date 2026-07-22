# connect-check — корневой Makefile
#
#   make              — CLI (host) + package в bin/
#   make cli          — только connect-check + probe-*
#   make package      — bin/{mac,linux,win}
#   make gui          — GUI текущей ОС
#   make release      — проверка VERSION + package (+ gui если возможно)
#   make version      — показать версию
#   make clean        — артефакты сборки

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
	  echo "release connect-check $$ver"
	$(MAKE) -f Makefile.package
	-$(MAKE) -f Makefile.gui
	$(MAKE) -f Makefile.package dist
	@test -x bin/linux/connect-check || { echo "release: нет linux — abort"; exit 1; }

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
	@echo "  make / make package   — CLI в bin/{mac,linux,win}"
	@echo "  make dist             — package + архивы в dist/ для GitHub Release"
	@echo "  make cli              — бинарники в корне (для отладки)"
	@echo "  make gui              — GUI текущей ОС"
	@echo "  make release          — package + gui + dist (linux обязателен)"
	@echo "  make clean"
	@echo "См. docs/VERSIONING.md и .cursor/rules/"
