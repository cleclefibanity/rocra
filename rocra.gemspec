# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rocra/version'

Gem::Specification.new do |gem|
  gem.name          = "rocra"
  gem.version       = Rocra::VERSION
  gem.authors       = ["Phil Hofmann"]
  gem.email         = ["phil@branch14.org"]
  gem.description   = %q{An OCRA (RFC 6287) implementation in Ruby}
  gem.summary       = %q{An OCRA (RFC 6287) implementation in Ruby}
  gem.homepage      = "https://github.com/branch14/rocra"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_development_dependency 'rspec'
end
