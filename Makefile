build:
	@go build .

dbuild:
	@docker build -t wirefilter . 

dev:
	@docker run -it -v $(shell pwd):/go/src/app wirefilter bash 