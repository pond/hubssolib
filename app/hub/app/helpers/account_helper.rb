module AccountHelper

  # Return a table cell with class 'yes' or 'no' and text contents 'Yes' or
  # 'No' according to "if (value) 'yes' else 'no'".
  #
  def boolean_cell(value)
    if (value)
      content_tag( :td, :class => 'yes' ) { 'Yes' }
    else
      content_tag( :td, :class => 'no' ) { 'No' }
    end
  end

  # Return a table cell with class 'yes', 'no' or 'expired' and text contents
  # 'Yes', 'No' or 'Expired' according to whether or not the given value is
  # set and less than "Time.now.utc".
  #
  def expired_cell(value)
    if (value)
      if (Time.now.utc >= value)
        content_tag( :td, :class => 'expired' ) { 'Expired' }
      else
        content_tag( :td, :class => 'yes' ) { 'Yes' }
      end
    else
      content_tag( :td, :class => 'no' ) { 'No' }
    end
  end

  # Return a table cell containing a series of actions to perform from a list
  # of user accounts. The cell will have class name 'actions'. Pass the user
  # object for which the actions should be generated.
  #
  def list_actions(user)
    content_tag( :td, :class => 'actions' ) do
      concat(
        button_to('Details', { :action => 'show',    :id => user.id })
      )
      concat(
        button_to('Delete',  { :action => 'destroy', :id => user.id }, :confirm => "Are you absolutely sure you want to permanently delete this account?")
      )
    end
  end

  # Output a selection list for roles. Pass the name of the parent
  # object, the name of the field to take the selected value, an array
  # of option values for the selection list and the associated roles
  # string. Must be followed by a code block that translates its given
  # argument into a printable string for the selection menu. Multiple
  # selections will be allowed.
  #
  def create_roles_selector(name, field, values, roles)
    roles = roles.to_authenticated_roles
    str   = "<select multiple name=\"%s[%s][]\" id=\"%s_%s\">\n" % [ name, field, name, field ]

    for value in values
      str += '                <option value="%s"' % value
      str += ' selected' if (roles.include? value)
      str += '>' + yield(value) # Call the code block the caller set up
      str += "</option>\n"
    end

    str += "              </select>\n"

    return str
  end

end
