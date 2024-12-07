#!/bin/bash

set -e

gem install bundler
bundle check || bundle install
bundle exec rake ci
