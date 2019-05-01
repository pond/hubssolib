#######################################################################
# File:    application_controller.rb                                  #
#          (C) Hipposoft 2006-2011                                    #
#                                                                     #
# Purpose: Hub core. Does little other than manage the interface into #
#          the DRb server via the Hub gem.                            #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 31-Jan-2011 (ADH): Comment header added; prior history     #
#                             not recorded.                           #
#######################################################################

class ApplicationController < ActionController::Base

  protect_from_forgery # See ActionController::RequestForgeryProtection for details

  before_action :set_email_host

  require 'hub_sso_lib'
  include HubSsoLib::Core

  before_action :hubssolib_beforehand
  after_action  :hubssolib_afterwards

private

  # TODO: Happily this is all now outdated, with mailers using views etc.
  # TODO: Fix ASAP.

  # Rather annoyingly, ActionMailer templates have no knowledge of the context
  # in which they are invoked, unlike normal view templates. This is strange
  # and, at least for Hub, unhelpful. We could insist that the system installer
  # configures some static value for the default host for links, but that's a
  # horrible kludge - once the application is running it always knows its host
  # via the "request" object.
  #
  # This filter patches around this Rails hiccup by wasting a few CPU cycles on
  # auto-setup of the e-mail host.
  #
  def set_email_host
    unless ( ActionMailer::Base.default_url_options.has_key?( :host ) )
      ActionMailer::Base.default_url_options[ :host ] = request.host_with_port
    end
  end
end
