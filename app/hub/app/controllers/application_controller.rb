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
  include Pagy::Backend

  protect_from_forgery # See ActionController::RequestForgeryProtection for details

  before_action :set_email_host

  require 'hub_sso_lib'
  include HubSsoLib::Core

  before_action :hubssolib_beforehand
  after_action  :hubssolib_afterwards

  # ============================================================================
  # PROTECTED INSTANCE METHODS
  # ============================================================================
  #
  protected

    # Run pagy() on a given ActiveRecord scope/collection, with a default
    # limit of 20 items per page overridden by the 'default_limit' parameter,
    # or by query parameter 'items', the latter taking precedence but being
    # capped to a list size of 200 to keep server resource usage down.
    #
    # https://github.com/ddnexus/pagy
    #
    def pagy_with_params(scope:, default_limit: 20)
      page = params[:page]&.to_i
      page = 1 if page.blank? || page < 1

      if default_limit == :all
        pagy_options = { page: 1, limit: scope.count }
      else
        limit        = params[:items]&.to_i || default_limit
        limit        = limit.clamp(1, 200)
        pagy_options = { page: page, limit: limit }
      end

      pagy(scope, **pagy_options)
    end

  # ============================================================================
  # PRIVATE INSTANCE METHODS
  # ============================================================================
  #
  private

    # Hackery run on a global before-action.
    #
    # ActionMailer doesn't know the host under which an application runs, since
    # it isn't handling a request. But Hub never sends any e-mail without a
    # request being handled first, so we can set it here. It's wasteful, but it
    # works.
    #
    def set_email_host
      Rails.application.config.action_mailer.default_url_options[:host] = request.host_with_port
    end

end
