require 'rake'

spec = Gem::Specification.new do |s|
  s.platform = Gem::Platform::RUBY
  s.name     = 'hubssolib'

  s.version  = '2.0.0'
  s.author   = 'Andrew Hodgkinson and others'
  s.email    = 'ahodgkin@rowing.org.uk'
  s.homepage = 'http://hub.pond.org.uk/'
  s.date     = File.ctime('VERSION')
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
  s.required_ruby_version = '>= 2.5.3' # Not tested on earlier versions

  s.add_development_dependency 'simplecov',   '~> 0.16'
  s.add_development_dependency 'rspec',       '~> 3.8'
  s.add_development_dependency 'rspec-mocks', '~> 3.8'
end
