#!/usr/bin/env rake
# -*- ruby encoding: utf-8 -*-
# vim: syntax=ruby

require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs << "test"
  t.test_files = FileList['test/**/test_*.rb']
  t.verbose = true
end

task :default => :test
