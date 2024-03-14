.PHONY: deps build run lint mocks run-mainnet-online run-mainnet-offline run-testnet-online \
	run-testnet-offline check-comments add-license check-license shorten-lines test \
	coverage spellcheck salus build-local coverage-local format check-format

ADDLICENSE_CMD=go run github.com/google/addlicense
ADDLICENCE_SCRIPT=${ADDLICENSE_CMD} -c "Coinbase, Inc." -l "apache" -v
SPELLCHECK_CMD=go run github.com/client9/misspell/cmd/misspell
GOLINES_CMD=go run github.com/segmentio/golines
GOLINT_CMD=go run golang.org/x/lint/golint
GOVERALLS_CMD=go run github.com/mattn/goveralls
GOIMPORTS_CMD=go run golang.org/x/tools/cmd/goimports
GO_PACKAGES=./services/... ./indexer/... ./komodo/... ./komodod/... ./komodoutil/... ./configuration/...
GO_FOLDERS=$(shell echo ${GO_PACKAGES} | sed -e "s/\.\///g" | sed -e "s/\/\.\.\.//g")
TEST_SCRIPT=go test ${GO_PACKAGES}
LINT_SETTINGS=golint,misspell,gocyclo,gocritic,whitespace,goconst,gocognit,bodyclose,unconvert,lll,unparam
PWD=$(shell pwd)
GZIP_CMD=$(shell command -v pigz || echo gzip)
NOFILE=100000
# DeckerSU <deckersu@protonmail.com> https://keys.openpgp.org/vks/v1/by-fingerprint/FD9A772C7300F4C894D1A819FE50480862E6451C
KOMODOD_MAINTAINER_KEYS?=FD9A772C7300F4C894D1A819FE50480862E6451C
KOMODO_COMMITTISH?=v0.8.2-beta1
DOCKER_IMAGE_NAME?=deckersu/rosetta-komodo

deps:
	go get ./...

build:
	docker build --pull -t rosetta-komodo:latest https://github.com/DeckerSU/rosetta-komodo

build-local:
	docker build --pull --build-arg KOMODO_COMMITTISH=${KOMODO_COMMITTISH} -t rosetta-komodo:latest .

build-release:
	# make sure to always set version with vX.X.X
	docker build --pull --no-cache --build-arg IS_RELEASE=true --build-arg KOMODOD_MAINTAINER_KEYS="${KOMODOD_MAINTAINER_KEYS}" --build-arg KOMODO_COMMITTISH=${KOMODO_COMMITTISH} -t rosetta-komodo:$(version) .;
	docker save rosetta-komodo:$(version) | ${GZIP_CMD} > rosetta-kmd-$(version).tar.gz;
	@echo $(DOCKER_WRITER_PASSWORD) | docker login -u $(DOCKER_WRITER_USERNAME) --password-stdin;
	docker tag rosetta-komodo:$(version) ${DOCKER_IMAGE_NAME}:latest
	docker push ${DOCKER_IMAGE_NAME}:latest;
	docker tag rosetta-komodo:$(version) ${DOCKER_IMAGE_NAME}:$(version)
	docker push ${DOCKER_IMAGE_NAME}:$(version);

run-mainnet-online:
	docker container rm rosetta-kmd-mainnet-online || true
	docker run --rm -v "${PWD}/komodo-data:/data" ubuntu:18.04 bash -c 'chown -R nobody:nogroup /data';
	docker run -d --name=rosetta-kmd-mainnet-online --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/komodo-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 7771:7771 rosetta-komodo:latest;

run-mainnet-offline:
	docker container rm rosetta-kmd-mainnet-offline || true
	docker run -d --name=rosetta-kmd-mainnet-offline -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-komodo:latest

run-testnet-online:
	docker container rm rosetta-kmd-testnet-online || true
	docker run --rm -v "${PWD}/komodo-data-testnet:/data" ubuntu:18.04 bash -c 'chown -R nobody:nogroup /data';
	docker run -d --name=rosetta-kmd-testnet-online --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/komodo-data-testnet:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 19033:19033 rosetta-komodo:latest;

run-testnet-offline:
	docker container rm rosetta-kmd-testnet-offline || true
	docker run -d --name=rosetta-kmd-testnet-offline -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-komodo:latest

train:
	./zstd-train.sh $(network) transaction $(data-directory)

check-comments:
	${GOLINT_CMD} -set_exit_status ${GO_FOLDERS} .

lint: | check-comments
	golangci-lint run --timeout 2m0s -v -E ${LINT_SETTINGS},gomnd

add-license:
	${ADDLICENCE_SCRIPT} .

check-license:
	${ADDLICENCE_SCRIPT} -check .

shorten-lines:
	${GOLINES_CMD} -w --shorten-comments ${GO_FOLDERS} .

format:
	gofmt -s -w -l .
	${GOIMPORTS_CMD} -w .

check-format:
	! gofmt -s -l . | read
	! ${GOIMPORTS_CMD} -l . | read

test:
	${TEST_SCRIPT}

coverage:
	if [ "${COVERALLS_TOKEN}" ]; then ${TEST_SCRIPT} -coverprofile=c.out -covermode=count; ${GOVERALLS_CMD} -coverprofile=c.out -repotoken ${COVERALLS_TOKEN}; fi

coverage-local:
	${TEST_SCRIPT} -cover

salus:
	docker run --rm -t -v ${PWD}:/home/repo coinbase/salus

spellcheck:
	${SPELLCHECK_CMD} -error .

mocks:
	rm -rf mocks;
	mockery --dir indexer --all --case underscore --outpkg indexer --output mocks/indexer;
	mockery --dir services --all --case underscore --outpkg services --output mocks/services;
	${ADDLICENCE_SCRIPT} .;
