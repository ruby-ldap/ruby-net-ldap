require "rubygems"
require "rake/gempackagetask"
require "rake/rdoctask"

require "rake/testtask"
Rake::TestTask.new do |t|
  t.libs << "test"
  t.test_files = FileList["test/test_*.rb"]
  t.verbose = true
end

require 'spec/rake/spectask'
Spec::Rake::SpecTask.new

task :default => ["test", 'spec']

# This builds the actual gem. For details of what all these options
# mean, and other ones you can add, check the documentation here:
#
#   http://rubygems.org/read/chapter/20
#
spec = Gem::Specification.new do |s|

  # Change these as appropriate
  s.name              = "net-ldap"
  s.version           = "0.1.0"
  s.summary           = "Net::LDAP is an LDAP support library written in pure Ruby. It supports most LDAP client features and a subset of server features as well."
  s.authors = [
    "Francis Cianfrocca", 
    "Austin Ziegler", 
    "Emiel van de Laar", 
    "Rory O\'Connell",
    "Kaspar Schiess"]
  
  s.description       = "Pure Ruby LDAP library"
  
  # Add any extra files to include in the gem
  s.files             = %w(COPYING History.txt LICENSE Rakefile README.txt) + Dir.glob("{spec,test,lib/**/*}")
  s.require_paths     = ["lib"]
end

# This task actually builds the gem. We also regenerate a static
# .gemspec file, which is useful if something (i.e. GitHub) will
# be automatically building a gem for this project. If you're not
# using GitHub, edit as appropriate.
#
# To publish your gem online, install the 'gemcutter' gem; Read more 
# about that here: http://gemcutter.org/pages/gem_docs
Rake::GemPackageTask.new(spec) do |pkg|
  pkg.gem_spec = spec

  # Generate the gemspec file for github.
  file = File.dirname(__FILE__) + "/#{spec.name}.gemspec"
  File.open(file, "w") {|f| f << spec.to_ruby }
end

# Generate documentation
Rake::RDocTask.new do |rd|
  rd.main = "README.txt"
  rd.rdoc_files.include("README.txt", "lib/**/*.rb")
  rd.rdoc_dir = "rdoc"
end

desc 'Clear out RDoc and generated packages'
task :clean => [:clobber_rdoc, :clobber_package] do
  rm "#{spec.name}.gemspec"
end
