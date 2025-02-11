require "active_support/core_ext/integer/time"

# See "config/application.rb".
#
EMAIL_ADMIN      = EMAIL_ADMIN_DEVELOPMENT
RESET_TIME_LIMIT = RESET_TIME_LIMIT_DEVELOPMENT

Rails.application.configure do
  # Settings specified here will take precedence over those in config/application.rb.

  # Make code changes take effect immediately without server restart.
  config.enable_reloading = true

  # Eager load code on boot, to detect issues early.
  config.eager_load = true

  # Show full error reports.
  config.consider_all_requests_local = true

  # Enable server timing.
  config.server_timing = true

  # Enable/disable Action Controller caching. By default Action Controller caching is disabled.
  # Run rails dev:cache to toggle Action Controller caching.
  if Rails.root.join("tmp/caching-dev.txt").exist?
    config.action_controller.perform_caching = true
    config.action_controller.enable_fragment_cache_logging = true
    config.public_file_server.headers = { "cache-control" => "public, max-age=#{2.days.to_i}" }
  else
    config.action_controller.perform_caching = false
  end

  # Change to :null_store to avoid any caching.
  config.cache_store = :memory_store

  # Don't care if the mailer can't send.
  config.action_mailer.raise_delivery_errors = false

  # Make template changes take effect immediately.
  config.action_mailer.perform_caching = false

  # Set localhost to be used by links generated in mailer templates.
  # config.action_mailer.default_url_options = { host: "localhost", port: 3000 }

  # Support MailCatcher -  https://mailcatcher.me
  #
  if ENV['MAILCATCHER_ENABLED'].present?
    config.action_mailer.delivery_method = :smtp
    config.action_mailer.smtp_settings = { :address => '127.0.0.1', :port => 1025 }
  end

  # Print deprecation notices to the Rails logger.
  config.active_support.deprecation = :log

  # Raise an error on page load if there are pending migrations.
  config.active_record.migration_error = :page_load

  # Highlight code that triggered database queries in logs.
  config.active_record.verbose_query_logs = true

  # Append comments with runtime information tags to SQL queries in logs.
  config.active_record.query_log_tags_enabled = true

  # Highlight code that enqueued background job in logs.
  config.active_job.verbose_enqueue_logs = true

  # Raises error for missing translations.
  # config.i18n.raise_on_missing_translations = true

  # Do not annotate rendered view with file names.
  config.action_view.annotate_rendered_view_with_filenames = false

  # Raise error when a before_action's only/except options reference missing actions.
  config.action_controller.raise_on_missing_callback_actions = true
end
