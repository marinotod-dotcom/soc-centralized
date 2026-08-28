PYTHON   = python3
SRC      = src/

.PHONY: lint pylint flake8 test #clean

lint: pylint flake8   

pylint:          
	$(PYTHON) -m pylint $(SRC)

flake8:             
	$(PYTHON) -m flake8 $(SRC)

test:                
	$(PYTHON) -m pytest tests -s

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete