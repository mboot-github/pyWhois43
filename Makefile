

simple:
	black .
	pylama .
	python3 pyWhoisClient.py google.com 2>2 | tee 1
