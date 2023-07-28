#
WHAT = pyWhois43
WHAT_LOWER = pywhois43
VERSION=$( hatch version )

all: simple build

simple:
	black $(WHAT)
	pylama $(WHAT)
	mypy --install-types --strict $(WHAT)
	# mypy --install-types --strict --no-incremental $(WHAT)

	python3 $(WHAT)/pyWhoisClient.py google.com 2>2 | tee 1
	hatch version

build:
	python -m build
	# actually the resulting files in dist are lowercase
	# tar tvzf dist/$(WHAT_LOWER)-$$(hatch version ).tar.gz
	unzip -v dist/$(WHAT_LOWER)-$$( hatch version )-py3-none-any.whl
test:
	pip3 install dist/testpy-1.0.0-py3-none-any.whl

