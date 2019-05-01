#######################################################################
# File:    stylesheets_controller.rb                                  #
#          (C) Hipposoft 2011                                         #
#                                                                     #
# Purpose: Render stylesheets via ERB for position independence.      #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 31-Jan-2011 (ADH): Created.                                #
#######################################################################

class StylesheetsController < ApplicationController

  skip_before_action :hubssolib_login_required
  skip_before_action :hubssolib_beforehand
  skip_after_action  :hubssolib_afterwards

  # Security - only allow specific "IDs" to be used.

  ALLOWED_IDS = [ :hub, :shared ];

  def show
    respond_to do | format |
      format.css do
        id = params[ :id ].to_sym

        if ( ALLOWED_IDS.include?( id ) )
          render :template => "stylesheets/#{ id }.css.erb", :layout => false
        else
          render :text => "401 Forbidden", :status => 401
        end
      end
    end
  end
end
