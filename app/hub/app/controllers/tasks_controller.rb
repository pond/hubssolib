#######################################################################
# File:    tasks_controller.rb                                        #
#          (C) Hipposoft 2006                                         #
#                                                                     #
# Purpose: Provide hub user account high-level task management.       #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 17-Oct-2006 (ADH): Adapted from Clubhouse.                 #
#######################################################################

class TasksController < ApplicationController
  helper :Tasks
  layout 'application'

  skip_before_action :hubssolib_beforehand, only: :service
  skip_after_action  :hubssolib_afterwards, only: :service

  def index
    # Generate a list of available tasks.

    @title = 'Control panel'
  end

  def service
    # Warn that there is a service problem.

    @title          = 'Service failure'
    @exception_data = hubssolib_get_exception_message(params[:id])
    @service_fault  = true # To tell the template not to talk to Hub
  end
end
