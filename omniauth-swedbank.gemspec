# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/swedbank/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-swedbank'
  spec.version       = Omniauth::Swedbank::VERSION
  spec.authors       = ['Mitigate', 'Jānis Kiršteins', 'Kristaps Ērglis']
  spec.email         = ['admin@mitigate.dev', 'janis@montadigital.com', 'kristaps.erglis@gmail.com' ]
  spec.description   = %q{OmniAuth strategy for Swedbank Banklink}
  spec.summary       = %q{OmniAuth strategy for Swedbank Banklink}
  spec.homepage      = 'https://github.com/mitigate-dev/omniauth-swedbank'
  spec.license       = 'MIT'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.2.2'

  spec.add_runtime_dependency 'omniauth', '~> 2.1'
  spec.add_runtime_dependency 'i18n'

  spec.add_development_dependency 'rack', '~> 2.0'
  spec.add_development_dependency 'rack-test'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
end
