# frozen_string_literal: true

Sentry.init do |config|
  config.breadcrumbs_logger = [:active_support_logger]
  config.dsn = ENV['SENTRY_DSN']
  config.enable_tracing = true
end

if ENV['SENTRY_DSN'].present?
  Sentry.init do |config|
    config.dsn                = ENV['SENTRY_DSN']
    config.breadcrumbs_logger = [:active_support_logger, :http_logger]

    # Set traces_sample_rate to 1.0 to capture 100% of transactions for tracing.
    # Set profiles_sample_rate to profile 100% of sampled transactions.
    #
    if Rails.env.production?
      config.traces_sample_rate   = 0.2
      config.profiles_sample_rate = 1.0 # I.e. profile all of the 20% of traced transactions
    else
      config.traces_sample_rate   = 1.0
      config.profiles_sample_rate = 1.0
    end

    # Filter out secrets. Since config/initializers runs in alphabetical order,
    # "filter_parameter_logging.rb" runs before "sentry.rb".
    #
    filter = ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters)
    config.before_send = lambda { |event, _hint| { filter.filter(event.to_hash) }
  end
else
  Sentry.init do |config|
    config.enabled_environments = ['this_matches_none']
  end
end
