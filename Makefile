#
WHAT = pyWhois43
VERSION=$( hatch version )

simple:
	black $(WHAT)
	pylama $(WHAT)
	python3 $(WHAT)/pyWhoisClient.py google.com 2>2 | tee 1
	hatch version

build:
	python -m build
	tar tvzf dist/*gz

test:
	pip3 install dist/testpy-1.0.0-py3-none-any.whl

