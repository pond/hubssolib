#######################################################################
# File:    tasks_helper.rb                                            #
#          (C) Hipposoft 2006                                         #
#                                                                     #
# Purpose: Helper functions for the Tasks view.                       #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 17-Oct-2006 (ADH): Adapted from Clubhouse.                 #
#######################################################################

module TasksHelper
  def exception_info
    data = '<div class="exception">'.html_safe()

    if (defined?(@exception_data) && @exception_data && !@exception_data.empty?)
      data << "<p /><b>Technical data:</b><p /><tt>#{h(@exception_data)}</tt>".html_safe()
    else
      data << "<p />Further technical information on this failure is not available.".html_safe()
    end

    return data + '</div>'.html_safe()
  end
end
