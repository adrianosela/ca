NAME:=$(shell basename `git rev-parse --show-toplevel`)
HASH:=$(shell git rev-parse --verify --short HEAD)

ifeq ($(AWS_PROFILE),)
	DOCKER_ENV := -e AWS_PROFILE=default
else
	DOCKER_ENV := -e AWS_PROFILE=$(AWS_PROFILE)
endif

ifeq ($(AWS_REGION),)
	# No changes if AWS_REGION is empty
else
	DOCKER_ENV += -e AWS_REGION=$(AWS_REGION)
endif

all: docker-run

docker-run: docker-build docker-teardown
	docker run -v ~/.aws:/root/.aws $(DOCKER_ENV) -d --name $(NAME)_service -p 8080:80 $(NAME)

docker-teardown:
	@(docker stop $(NAME)_service > /dev/null 2>&1 || true) && (docker rm $(NAME)_service > /dev/null 2>&1 || true)

docker-build:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(HASH)" -o $(NAME)
	docker build -t $(NAME) .

build:
	go build -ldflags "-X main.version=$(HASH)" -o $(NAME)
