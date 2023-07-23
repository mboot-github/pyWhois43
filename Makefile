

simple:
	black .
	pylama .
	python3 pyWhoisClient.py 2>2 | tee 1
