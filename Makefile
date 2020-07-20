env:
	virtualenv -p python3 .env \
	&& . .env/bin/activate \
	&& pip install -r requirements.txt

lint:
	. .env/bin/activate \
	&& pylint webcve.py

tests:
	python ./webcve.py --list group
	python ./webcve.py --list type
	python ./webcve.py -v --status-code 406 --url $(TEST_TARGET)

clean:
	rm -rf .env