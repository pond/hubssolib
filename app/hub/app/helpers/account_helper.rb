module AccountHelper

  # Return a table cell with class 'yes' or 'no' and text contents 'Yes' or
  # 'No' according to "if (value) 'yes' else 'no'".
  #
  def boolean_cell(value)
    if (value)
      tag.td( 'Yes', :class => 'yes' )
    else
      tag.td( 'No', :class => 'no' )
    end
  end

  # Return a table cell with class 'yes', 'no' or 'expired' and text contents
  # 'Yes', 'No' or 'Expired' according to whether or not the given value is
  # set and less than "Time.now.utc".
  #
  def expired_cell( value )
    if ( value )
      if (Time.now.utc >= value)
        tag.td( 'Expired', :class => 'expired' )
      else
        tag.td( 'Yes', :class => 'yes' )
      end
    else
      tag.td( 'No', :class => 'no' )
    end
  end

  # Return a table cell containing a series of actions to perform from a list
  # of user accounts. The cell will have class name 'actions'. Pass the user
  # object for which the actions should be generated.
  #
  def list_actions( user )
    tag.td(class: 'actions') do
      concat(
        button_to('Details', { action: 'show', id: user.id })
      )
      concat(
        button_to(
          'Delete',
          { action: 'destroy', id: user.id },
          confirm: "Are you absolutely sure you want to permanently delete this account?"
        )
      )
    end
  end

  # Output a selection list for roles. Pass a form object, from e.g. the
  # likes of "form_for( @user ) do | form | ... end" and the target User.
  # Its "roles" attribute is deserialised to an array in passing.
  #
  def create_roles_selector( form, user )
    role_names = HubSsoLib::Roles.get_role_symbols()

    form.select(
      'roles_array',
      role_names.map { | role_name | [ HubSsoLib::Roles.get_display_name( role_name ), role_name ] },
      { include_hidden: false },
      { multiple:       true  }
    )
  end

end
