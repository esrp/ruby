lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'esrp/version'

Gem::Specification.new do |spec|
  spec.name          = 'esrp'
  spec.version       = ESRP::Version::STRING
  spec.authors       = ['Andriy Savchenko']
  spec.email         = ['andrey@aejis.eu']
  spec.summary       = %q{Enhanced SRP-6a auth}
  spec.description   = %q{Secure Remote Password protocol}
  spec.homepage      = 'https://github.com/Ptico/esrp'
  spec.license       = 'MIT'

  spec.files         = Dir['lib/**/*.rb']
  spec.test_files    = Dir['spec/**/*.rb']
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.14'
  spec.add_development_dependency 'thor'
  spec.add_development_dependency 'rspec', '~> 3.6.0'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'inch'
  spec.add_development_dependency 'rbnacl'
  spec.add_development_dependency 'rbnacl-libsodium'
end
