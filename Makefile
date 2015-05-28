NAME = i2p-tools
DOCKER_IMAGE = mdrollette/$(NAME)
 
all: build
 
.build: .
	docker pull golang:1.4.2
	docker pull progrium/busybox:latest
	docker build -t $(NAME) .
	docker inspect -f '{{.Id}}' $(NAME) > .build
 
build: .build
 
release: build
	cd release && docker run --rm --entrypoint /bin/sh $(NAME) -c 'tar cf - /$(NAME)' | tar xf -
	docker build --rm -t $(DOCKER_IMAGE) release

push: release
	docker push $(DOCKER_IMAGE)
 
clean:
	rm -f .build release/i2p-tools
 
.PHONY: push release build all clean
