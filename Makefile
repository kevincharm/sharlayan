clean:
	rm -rf ./bin/*

build:
	gcc main.c -o ./bin/sharlayan -std=c11

run:
	sudo ./bin/sharlayan
