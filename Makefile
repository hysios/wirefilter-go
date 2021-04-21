build:
	@go build .

dbuild:
	@docker build -t wirefilter . 

dev:
	@docker run -it -v $(shell pwd):/go/src/app wirefilter bash 

main.o:
	@gcc -c main.c -I./

main: main.o
	@gcc -o main main.o -L./lib -lwirefilter_ffi

clean: 
	@rm main main.o
