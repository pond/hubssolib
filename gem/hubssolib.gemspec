require 'rake'

spec = Gem::Specification.new do |s|
  s.platform = Gem::Platform::RUBY
  s.name     = 'hubssolib'

  s.version  = '3.0.3'
  s.author   = 'Andrew Hodgkinson and others'
  s.email    = 'ahodgkin@rowing.org.uk'
  s.homepage = 'http://pond.org.uk/'
  s.summary  = 'Cross-application single sign-on support library.'
  s.license  = 'MIT'

  s.description = <<-EOF
    The Hub SSO Library supports single sign-on across multiple Rails
    applications on the same host. The Hub application provides account
    management facilities (sign up, log in, etc.). The library provides
    read-only access to data set up by the application. Using the library,
    external applications can see whether or not someone is logged in via
    Hub and see what their assigned roles are. Each application determines
    its own mappings between roles and permissions.
  EOF

  s.files = FileList['lib/**/*.rb', '[A-Z]*'].to_a
  s.required_ruby_version = '>= 3.0.0' # Not tested on earlier versions

  s.add_dependency 'drb',    '~> 2.2'
  s.add_dependency 'base64', '~> 0.2'

  s.add_development_dependency 'debug',       '~> 1.1'
  s.add_development_dependency 'simplecov',   '~> 0.22'
  s.add_development_dependency 'doggo',       '~> 1.4'
  s.add_development_dependency 'rspec',       '~> 3.13'
  s.add_development_dependency 'rspec-mocks', '~> 3.13'
end
