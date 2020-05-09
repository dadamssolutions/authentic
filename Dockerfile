FROM golang:latest

RUN curl -s https://codecov.io/bash > codecov.sh
RUN chmod +x codecov.sh

RUN go get github.com/axw/gocov/gocov

RUN curl -s -L https://codeclimate.com/downloads/test-reporter/test-reporter-latest-linux-amd64 -o cc-reporter
RUN chmod +x cc-reporter