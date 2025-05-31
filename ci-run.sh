#!/bin/bash

set -e

gem install bundler
ruby -v | grep jruby && apt update && apt install -y gcc
bundle check || bundle install
bundle exec rake ci
