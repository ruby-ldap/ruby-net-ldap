# Local OpenLDAP Integration Testing

Set up a [Vagrant](http://www.vagrantup.com/) VM to run integration tests against OpenLDAP locally.

To run integration tests locally:

``` bash
# start VM (from the correct directory)
$ cd test/support/vm/openldap/
$ vagrant up

# get the IP address of the VM
$ ip=$(vagrant ssh -- "ifconfig eth1 | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1")

# change back to root project directory
$ cd ../../../..

# run all tests, including integration tests
$ time INTEGRATION=openldap INTEGRATION_HOST=$ip bundle exec rake

# run a specific integration test file
$ time INTEGRATION=openldap INTEGRATION_HOST=$ip bundle exec ruby test/integration/test_search.rb

# run integration tests by default
$ export INTEGRATION=openldap
$ export INTEGRATION_HOST=$ip

# now run tests without having to set ENV variables
$ time bundle exec rake
```

You may need to `gem install vagrant` first in order to provision the VM.
