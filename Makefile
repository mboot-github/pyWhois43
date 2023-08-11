WHAT		= pyWhois43
WHAT_LOWER	= pywhois43

BLACK		= black --line-length=160
PYLAMA		= pylama
MYPY		= mypy --install-types --strict

VERSION		= $( hatch version )

all: simple simpleTest version build

simple:
	$(BLACK) *.py $(WHAT)
	$(PYLAMA) *.py $(WHAT)
	$(MYPY) *.py $(WHAT)

version:
	hatch version

simpleTest:
	python3 $(WHAT)/pyWhoisClient.py

build:
	python -m build
	# actually the resulting files in dist are lowercase
	# tar tvzf dist/$(WHAT_LOWER)-$$(hatch version ).tar.gz
	unzip -v dist/$(WHAT_LOWER)-$$( hatch version )-py3-none-any.whl

test:
	pip3 uninstall -y pywhois43
	pip3 install dist/$(WHAT_LOWER)-$$( hatch version )-py3-none-any.whl

