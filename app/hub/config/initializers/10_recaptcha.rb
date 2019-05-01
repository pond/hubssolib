########################################################################
# File::    01_recaptcha.rb
# (C)::     Hipposoft 2011
#
# Purpose:: Configure Ambethia Recaptcha, which is installed as a plugin:
#
#             https://github.com/ambethia/recaptcha
# ----------------------------------------------------------------------
#           30-Aug-2011 (ADH): Created.
########################################################################

Recaptcha.configure do |config|
  config.public_key  = 'set-key-here'
  config.private_key = 'set-key-here'
end
