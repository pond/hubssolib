# ============================================================================
# Configure test environment
# ============================================================================

# Configure the code coverage analyser

require 'simplecov'

SimpleCov.start do
  add_filter '/spec/'
end

# Configure RSpec

RSpec.configure do | config |

  config.color = true
  config.tty   = true
  config.order = :random

  Kernel.srand config.seed

  config.before( :suite ) do
  end

  config.after( :suite ) do
  end

  config.before( :each ) do
  end

  config.after( :each ) do
  end
end

# ============================================================================
# Wake up Hub
# ============================================================================

# Set the random file environment variable to a full path to the given
# leaf inside the "files" subdirectory.
#
def spechelper_set_random_file(leaf = "random.bin")
  ENV[ 'HUB_RANDOM_FILE' ] = File.join( File.dirname( __FILE__ ), 'files', leaf )
end

spechelper_set_random_file()
require 'hub_sso_lib'
