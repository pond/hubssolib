#######################################################################
# Server:  hub_sso_server.rb                                          #
#          (C) Hipposoft 2006-2025                                    #
#                                                                     #
# Purpose: Cross-application same domain single sign-on support:      #
#          RAM cache based authorisation server, a DRb server that    #
#          stores session details for Hub clients.                    #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 26-Oct-2006 (ADH): Created.                                #
#######################################################################

require 'rubygems'
require 'drb'
require 'base64'
require 'hub_sso_lib'

include HubSsoLib::Server

# Unbuffered I/O - anything streaming out logs will see output immediately.
#
$stdout.sync = true
$stderr.sync = true

hubssolib_launch_server()
