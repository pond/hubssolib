# This configuration file will be evaluated by Puma. The top-level methods that
# are invoked here are part of Puma's configuration DSL. For more information
# about methods provided by the DSL, see https://puma.io/puma/Puma/DSL.html.

# Puma can serve each request in a thread from an internal thread pool.
# The `threads` method setting takes two numbers: a minimum and maximum.
# Any libraries that use thread pools should be configured to match
# the maximum value specified for Puma. Default is set to 5 threads for minimum
# and maximum; this matches the default thread size of Active Record.
max_threads_count = ENV.fetch("RAILS_MAX_THREADS") { 5 }
min_threads_count = ENV.fetch("RAILS_MIN_THREADS") { max_threads_count }
threads min_threads_count, max_threads_count

# Specifies that the worker count should equal the number of processors in production.
if ENV["RAILS_ENV"] == "production"
  require "concurrent-ruby"
  worker_count = Integer(ENV.fetch("WEB_CONCURRENCY") { Concurrent.physical_processor_count })
  workers worker_count if worker_count > 1
end

# Specifies the `worker_timeout` threshold that Puma will use to wait before
# terminating a worker in development environments.
worker_timeout 3600 if ENV.fetch("RAILS_ENV", "development") == "development"

# Specifies the `port` that Puma will listen on to receive requests; default is 3000.
# Must use custom env var PUMA_PORT, as if the Puma-known PORT is used, for some
# reason it ignores the "bind" below and latches onto 127.0.0.1 only, so the server
# is not visible outside localhost (if that is required, e.g. by binding to 0.0.0.0).
#
base_port = (ENV.fetch("PUMA_PORT") { 3000 }).to_i
bind "tcp://127.0.0.1:#{base_port}"

# Enable SSL on "ENV[PORT] + 1" or 443. For 443, you must run via `sudo`, e.g.:
#
#   sudo USE_SUDO_SSL=true bundle exec rails server
#
# ...which is obviously a security risk, so only use it for short periods. This
# is needed for the mobile app & the Apple App Site Association file used for
# universal links, as non-standard ports are prohibited by that system.
#
# If using SSL on another port, then the traditional arrangement of normal HTTP
# on the configured port and SSL one port higher is used - by default, 3000 and
# 3001.
#
ssl_port = if ENV['USE_SSL'].present?
  base_port + 1
elsif ENV['USE_SUDO_SSL'].present?
  443
else
  nil
end

unless ssl_port.nil?
  ssl_bind(
    '0.0.0.0',
    ssl_port,
    {
      key:         Rails.root.join('config', 'developer_certificates', 'epsilon.privkey.pem'),
      cert:        Rails.root.join('config', 'developer_certificates', 'epsilon.fullchain.pem'),
      verify_mode: 'none'
    }
  )
end

# Specifies the `environment` that Puma will run in.
environment ENV.fetch("RAILS_ENV") { "development" }

# Specifies the `pidfile` that Puma will use.
pidfile ENV.fetch("PIDFILE") { "tmp/pids/server.pid" }

# Allow puma to be restarted by `bin/rails restart` command.
plugin :tmp_restart
