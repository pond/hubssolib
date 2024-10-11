require_relative 'boot'

require "rails"
# Pick the frameworks you want:
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_mailer/railtie"
require "action_view/railtie"
require "rails/test_unit/railtie"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

# Administrator e-mail address to use as the 'From' address in account
# notification e-mail messages, for development and production respectively.
#
EMAIL_ADMIN_DEVELOPMENT = 'info@riscosopen.org'
EMAIL_ADMIN_PRODUCTION  = 'info@riscosopen.org'

# Time limit, *in seconds*, for password reset e-mail codes in development
# and production respectively. Codes persist in the database indefinitely
# but will be rejected if too old when someone tries to use one.
#
RESET_TIME_LIMIT_DEVELOPMENT = 2 * 24 * 60 * 60
RESET_TIME_LIMIT_PRODUCTION  = 2 * 24 * 60 * 60

module Hub
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 7.0

    # Settings in config/environments/* take precedence over those specified here.
    # Application configuration can go into files in config/initializers
    # -- all .rb files in that directory are automatically loaded after loading
    # the framework and any gems in your application.

    config.time_zone = "UTC"
    config.active_record.default_timezone = :utc

    config.active_record.observers = :user_observer
    config.hosts << "epsilon.arachsys.com"

    config.force_ssl = true if Rails.env.production?
  end
end
