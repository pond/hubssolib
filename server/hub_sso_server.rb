#######################################################################
# Server:  hub_sso_server.rb                                          #
#          (C) Hipposoft 2006-2011                                    #
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
require 'hub_sso_lib'

include HubSsoLib::Server

hubssolib_launch_server()
