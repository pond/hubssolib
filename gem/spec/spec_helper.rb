# ============================================================================
# Configure test environment
# ============================================================================

require 'byebug'

# Configure the code coverage analyser

require 'simplecov'

SimpleCov.start do
  add_filter '/spec/'
end

# Wake up Hub

require 'hub_sso_lib'

# Configure RSpec

RSpec.configure do | config |

  config.color = true
  config.tty   = true
  config.order = :random

  Kernel.srand config.seed

  config.before( :suite ) do
    ENV['HUB_QUIET_SERVER'] = 'yes'
  end

  config.after( :suite ) do
  end

  config.before( :each ) do
  end

  config.after( :each ) do
  end
end
