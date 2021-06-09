#
# Copyright 2016 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# set default shell
SHELL = bash -e -o pipefail

# Variables
VERSION                    ?= $(shell cat ./VERSION)

# tool containers
VOLTHA_TOOLS_VERSION ?= 2.4.0

GO                = go
GOLANGCI_LINT     = golangci-lint
GO_JUNIT_REPORT   = go-junit-report
GOCOVER_COBERTURA = gocover-cobertura

xGO_JUNIT_REPORT   = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-go-junit-report go-junit-report
xGOCOVER_COBERTURA = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-gocover-cobertura gocover-cobertura

# This should to be the first and default target in this Makefile
help:
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@echo "build                : Build the library"
	@echo "clean                : Remove files created by the build"
	@echo "distclean            : Remove build and testing artifacts and reports"
	@echo "lint                 : Shorthand for format + lint-code + lint-mod"
	@echo "format               : Verify code is properly gofmt-ed"
	@echo "lint-code           : Verify that 'go vet' doesn't report any issues"
	@echo "lint-mod             : Verify the integrity of the 'mod' files"
	@echo "mod-update           : Update go.mod and the vendor directory"
	@echo "test                 : Generate reports for all go tests"
	@echo

## build the library
build:
	${GO} build ./...

## lint and unit tests

format:
	@echo "Running go fmt..."
	@${GO} fmt ./...

lint-code:
	@echo "Running lint check..."
	@${GO} vet ./...

lint-mod:
	@echo "Running dependency check..."
	@${GO} mod verify
	@echo "Dependency check OK. Running vendor check..."
	@git status > /dev/null
	@git diff-index --quiet HEAD -- go.mod go.sum vendor || (echo "ERROR: Staged or modified files must be committed before running this test" && echo "`git status`" && exit 1)
	@[[ `git ls-files --exclude-standard --others go.mod go.sum vendor` == "" ]] || (echo "ERROR: Untracked files must be cleaned up before running this test" && echo "`git status`" && exit 1)
	${GO} mod tidy
	${GO} mod vendor
	@git status > /dev/null
	@git diff-index --quiet HEAD -- go.mod go.sum vendor || (echo "ERROR: Modified files detected after running go mod tidy / go mod vendor" && echo "`git status`" && exit 1)
	@[[ `git ls-files --exclude-standard --others go.mod go.sum vendor` == "" ]] || (echo "ERROR: Untracked files detected after running go mod tidy / go mod vendor" && echo "`git status`" && exit 1)
	@echo "Vendor check OK."

lint: format lint-code lint-mod

get-golangci-lint:
	# binary will be $(go env GOPATH)/bin/golangci-lint
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.40.1

get-go-junit-report:
	go get -u github.com/jstemmer/go-junit-report

get-gocover-cobertura:
	go get github.com/t-yuki/gocover-cobertura

get-tools: get-golangci-lint get-go-junit-report get-gocover-cobertura

golangci-lint:
	rm -rf ./sca-report
	@mkdir -p ./sca-report
	- ${GOLANGCI_LINT} run --out-format junit-xml ./... | tee ./sca-report/sca-report.xml
	- ${GOLANGCI_LINT} run --out-format line-number ./... | tee ./sca-report/sca-report.txt

test:
	rm -rf ./tests
	@mkdir -p ./tests
	@${GO} test -v -coverprofile ./tests/go-test-coverage.out -covermode count ./... 2>&1 | tee ./tests/go-test-results.out
	${GO_JUNIT_REPORT} < ./tests/go-test-results.out > ./tests/go-test-results.xml ;\
	${GOCOVER_COBERTURA} < ./tests/go-test-coverage.out > ./tests/go-test-coverage.xml ;\

clean: distclean

distclean:
	rm -rf ./sca-report ./tests

mod-update:
	${GO} mod tidy
	${GO} mod vendor
