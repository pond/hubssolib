#######################################################################
# File:    account_controller.rb                                      #
#          (C) Hipposoft 2006-2011                                    #
#                                                                     #
# Purpose: Hub account management.                                    #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 31-Jan-2011 (ADH): Comment header added; prior history     #
#                             not recorded.                           #
#######################################################################

require 'will_paginate/array'

class AccountController < ApplicationController

  layout 'application'

  # Cache the logged in and out PNG images in RAM; they're only small.

  @@logged_in_image  = File.read("#{Rails.root}/app/assets/images/icons/logged_in.png")
  @@logged_out_image = File.read("#{Rails.root}/app/assets/images/icons/logged_out.png")

  # Action permissions for this class as a class variable, exposed
  # to the public through a class method.

  @@hubssolib_permissions = HubSsoLib::Permissions.new({
                              :change_password => [ :admin, :webmaster, :privileged, :normal ],
                              :change_details  => [ :admin, :webmaster, :privileged, :normal ],
                              :delete          => [ :admin, :webmaster, :privileged, :normal ],
                              :delete_confirm  => [ :admin, :webmaster, :privileged, :normal ],
                              :list            => [ :admin, :webmaster, :privileged ],
                              :enumerate       => [ :admin, :webmaster ],
                              :show            => [ :admin, :webmaster ],
                              :edit_roles      => [ :admin ],
                              :destroy         => [ :admin ]
                            })

  def AccountController.hubssolib_permissions
    @@hubssolib_permissions
  end

  # HTTPS enforcement for all methods, except the login indicator; if someone
  # is on an HTTP page, the login indicator needs to be fetched by HTTP too so
  # it can show "logged out" as the secure-only cookies won't get sent. It is
  # very confusing to be on an HTTP page, apparently fetching the indicator by
  # HTTP, only to have the image fetch quietly redirect behind the scenes, go
  # to HTTPS, and say you're logged in - when everyone else thinks you're not.

  require 'hub_sso_lib'
  include HubSsoLib::Core

  before_action :hubssolib_ensure_https, :except => :login_indication

  # The "proper" login method
  #
  def login
    @title = 'Log in'
    return unless request.post?

    @email = params[:email]
    self.hubssolib_current_user = from_real_user(User.authenticate(@email, params[:password]))

    if (self.hubssolib_current_user and self.hubssolib_current_user != :false)
      hubssolib_set_last_used(Time.now.utc)

      privileges = hubssolib_get_user_roles.to_human_s.downcase
      hubssolib_set_flash(
        :notice,
        "Logged in successfully. Welcome, #{hubssolib_get_user_name}. " <<
        "You have #{privileges} privileges."
      )

      hubssolib_redirect_back_or_default(:controller => 'tasks', :action => nil)
    else
      hubssolib_set_flash(:alert, 'Incorrect e-mail address or password.')
    end
  end

  # Log out the user and redirect to the Tasks controller.
  #
  def logout
    @title = 'Log out'
    hubssolib_log_out()
    hubssolib_set_flash(:attention, 'You are now logged out.')
    redirect_to :controller => 'tasks', :action => nil
  end

  def signup
    @title = 'Sign up'
    return unless request.post?

    @user = User.new(allowed_user_params())

    if ( @user.email.downcase.ends_with?( '.kr' ) || @user.email.downcase.ends_with?( '.cn' ) )
      hubssolib_set_flash(:attention, 'Due to overwhelming spam volumes from some locations, self-signups for those locations are blocked. Please contact ROOL for assistance.')
      redirect_to :controller => 'tasks', :action => nil
      return
    end

    # Are there any users yet? If not, grant this user admin permissions.
    # Administrators are for just this application; whether or not admin
    # privileges affect other applications depends on the level of external
    # SSO integration.

    if (User.count.zero?)

      @user.roles = HubSsoLib::Roles.new(true).to_s
      @user.save!
      @user.activate
      self.hubssolib_current_user = from_real_user(@user)

      hubssolib_set_flash(
        :notice,
        'Thanks for signing up. You are now the system administrator ' <<
        'and your account has been automatically activated.'
      )

    else

      # Have to do the captcha verification explicitly before trying to save
      # the model, as verification is not done as part of validation and we
      # don't want to successfully save a model only to find that the captcha
      # text is incorrect.

      begin
        success = verify_recaptcha(
          :model   => @user,
          :message => "The reCaptcha challenge wasn't happy with the response. Please try again or contact #{ INSTITUTION_NAME_LONG } for assistance."
        )
      rescue => e
        Rails.logger.error(e.inspect)
        hubssolib_set_flash(:attention, 'The reCaptcha system is currently not available and cannot verify signups. Please try again later.')
        redirect_to :controller => 'tasks', :action => nil
        return
      end

      raise ActiveRecord::RecordInvalid.new(@user) if not success

      @user.roles = HubSsoLib::Roles.new(false).to_s
      @user.save!

      hubssolib_set_flash(
        :notice,
        'Thanks for signing up. Your site account must be activated ' <<
        'before you can use it - please check your e-mail account '   <<
        'for a message which tells you what you should do next.'
      )

    end

    redirect_to :controller => 'tasks', :action => nil

  rescue ActiveRecord::RecordInvalid
    render :action => 'signup'
  end

  def activate
    activation_code = params[:activation_code] || params[:id]

    unless activation_code.nil?
      @user = User.find_by_activation_code(activation_code)

      if @user and @user.activate
        self.hubssolib_current_user = from_real_user(@user)

        hubssolib_set_flash(
          :notice,
          "Your #{INSTITUTION_NAME_LONG} web site account is now active."
        )

        hubssolib_redirect_back_or_default(:controller => 'tasks', :action => nil)
      else
        hubssolib_set_flash(
          :alert,
          "Unable to activate your #{INSTITUTION_NAME_LONG} web site account. "                <<
          'Is the activation code correct, or has it already been used? '                      <<
          "If in doubt please try to sign up again. Contact #{INSTITUTION_NAME_SHORT} if you " <<
          'keep having trouble.'
        )

        redirect_to :controller => 'account', :action => 'signup'
      end
    else
      redirect_to :controller => 'account', :action => 'signup'
    end
  end

  def change_password
    @title = 'Change password'
    return unless request.post?

    user = to_real_user(self.hubssolib_current_user)

    if User.authenticate(user.email, params[:old_password])
      if (params[:password] == params[:password_confirmation])
        user.password_confirmation = params[:password_confirmation]
        user.password = params[:password]
        save_password_and_set_flash(user)
        self.hubssolib_current_user = from_real_user(user)

        redirect_to :controller => 'tasks', :action => nil
      else
        set_password_mismatch_flash
        @old_password = params[:old_password]
      end
    else
      hubssolib_set_flash(:alert, 'Incorrect current password.')
    end
  end

  def change_details
    @title     = 'Update account details'
    @user      = to_real_user(self.hubssolib_current_user)
    @real_name = @user ? @user.real_name || '' : ''

    return unless request.post?

    if (params[:real_name])
      @user.real_name = @real_name = params[:real_name]
      @user.save!
      self.hubssolib_current_user = from_real_user(@user)

      hubssolib_set_flash(:notice, 'Account details updated successfully.')
      redirect_to :controller => 'tasks', :action => nil
    end
  end

  def forgot_password
    @title = 'Forgotten password'
    return unless request.post?

    @user = User.find(:first, :conditions => ["LOWER(email) = ?", params[:email].downcase])

    unless @user.nil?
      @user.forgot_password
      @user.save!

      hubssolib_set_flash(
        :notice,
        'An e-mail message which tells you how to reset your ' <<
        'account password has been set to your e-mail address.'
      )

      redirect_to :controller => 'tasks', :action => nil
    else
      hubssolib_set_flash(
        :alert,
        'No account was found for the given e-mail address.'
      )
    end
  end

  def reset_password
    @title = 'Reset password'

    if params[:id].nil?
      hubssolib_redirect_back_or_default(:controller => 'tasks', :action => nil)
      return
    end

    @user = User.find_by_password_reset_code(params[:id])

    if (@user.nil?)
      hubssolib_set_flash(
        :alert,
        'Invalid reset code. Did your e-mail client break up the reset '   <<
        'link so it spanned more than one line? If so, please try again, ' <<
        'copying all of the link in the message however many lines it spans.'
      )

      hubssolib_redirect_back_or_default(:controller => 'tasks', :action => nil)
      return
    end

    t = Time.now.utc
    if (t >= (@user.password_reset_code_expires_at || t)) # Allows for 'nil' in expiry field
      hubssolib_set_flash(
        :alert,
        'The reset code has expired. Please try your reset request again.'
      )
      redirect_to :controller => 'account', :action => 'forgot_password'
      return
    end

    unless params[:password]
      hubssolib_set_flash(:alert, 'Reset your password using the form below.')
      return
    end

    if (params[:password] == params[:password_confirmation])
      @user.password_confirmation = params[:password_confirmation]
      @user.password = params[:password]
      @user.reset_password
      save_password_and_set_flash(@user)
      self.hubssolib_current_user = from_real_user(@user)
      redirect_to :controller => 'tasks', :action => nil
      return
    else
      set_password_mismatch_flash
      return
    end
  end

  def delete
    hubssolib_set_flash(:alert, 'Are you sure?')
    title = 'Delete account: Are you sure?'
  end

  def delete_confirm
    me = to_real_user(self.hubssolib_current_user)
    hubssolib_log_out()
    me.destroy

    hubssolib_clear_flash()
    hubssolib_set_flash(:attention, 'Your account has been deleted.')
    redirect_to :controller => 'tasks', :action => nil
  end

  def list
    @title = 'List of user accounts'

    # Page zero means 'all'.

    if (params.has_key?(:page) && params[:page] == '0' )
      page     = 1
      per_page = User.count
    else
      page     = params[:page]
      per_page = 20
    end

    @users = User.paginate(
      :page     => page,
      :per_page => per_page
    ).order( 'created_at DESC' )
  end

  # Enumerate active users (those users known to the DRb server).
  #
  def enumerate
    @title = 'Active users'
    @users = hubssolib_enumerate_users
    @users = [] if @users.nil?

    # Map the user objects returned from the HubSsoLib Gem to
    # internal users.

    @users.map! { |user| to_real_user(user, true) }
    @users.compact!

    # Page number zero is magic; it indicates "all items".

    if (params.has_key?(:page) && params[:page] == '0' )
      page     = 1
      per_page = @users.count
    else
      page     = params[:page]
      per_page = 20
    end

    @users.sort! { | x, y | y.created_at <=> x.created_at }
    @users = @users.paginate(
      :page     => page,
      :per_page => per_page
    )
  end

  # Show details of a specific user account.
  #
  def show
    @title    = 'User account details'
    @user     = User.find(params[:id])
    @referrer = request.env["HTTP_REFERER"]
    @referrer = nil unless (@referrer && !@referrer.empty?)
  end

  def edit_roles
    @title = 'Edit account roles'

    # We must have a valid ID

    unless (request.post?) and (params[:id]) and (@user = User.find(params[:id]))
      redirect_to :controller => 'tasks', :action => nil
      return
    end

    # If 'commit' is present, the form was submitted with details rather than
    # visited from a list or account details view.

    return unless (params[:commit])

    # Validate the result

    roles = (params[:user] ? params[:user][:roles_array] : '').to_authenticated_roles

    unless (roles.validate)
      hubssolib_set_flash(
        :alert,
        'At least one role must be chosen from the list.'
      )

      return # NOTE EARLY EXIT
    end

    editing_own_roles = (hubssolib_get_user_id == @user.id)

    if (editing_own_roles && ! roles.include?(:admin))
      hubssolib_set_flash(
        :alert,
        'You cannot revoke your own administrator privileges. Create a new administrator account first, then use it to revoke permissions from your old account.'
      )

      return # NOTE EARLY EXIT
    end

    @user.roles = roles.to_s
    @user.save!

    if (editing_own_roles)
      self.hubssolib_current_user = from_real_user(@user)
    end

    hubssolib_set_flash(:notice, 'Account roles updated successfully.')
    redirect_to :action => 'show', :id => @user.id
  end

  def destroy
    user = User.find(params[:id])

    if (hubssolib_get_user_id == user.id)
      hubssolib_set_flash(
        :alert,
        'Please use the normal control panel below to delete your own account.'
      )
      redirect_to root_path
      return
    elsif (user.roles.to_authenticated_roles.include?(:admin))
      hubssolib_set_flash(
        :alert,
        'You cannot destroy an administrator account from here! ' <<
        'You can only do that at the control panel when '         <<
        'logged into the account, or at the database level.'
      )
    else
      user.destroy
      hubssolib_set_flash(:alert, 'The account has been deleted.')
    end

    redirect_to :action => 'list'
  end

  # The login_indication method is unusual; it returns data for an image,
  # with no-cache parameters set, to indicate whether or not the user is
  # logged in. It does not render a view.
  #
  # The idea is that a caller which caches HTML can include an image tag
  # that points its source data to this method; the image will be updated
  # even if the HTML stays cached.
  #
  def login_indication
    headers['Pragma']        = 'no-cache'
    headers['Cache-Control'] = 'no-cache, must-revalidate'

    send_data hubssolib_logged_in? ? @@logged_in_image : @@logged_out_image,
              :type        => 'image/png',
              :disposition => 'inline'
  end

  # A supporting unusual method is login_conditional, which redirects to
  # the login page if the user is logged out or the tasks page if the user
  # is logged in. It explicitly clears a return-to link, if there is one,
  # so that the user doesn't drop out of Hub. This is useful if the page
  # from which the user came cannot support (for example) the Flash display
  # because of, say, caching.
  #
  def login_conditional
    if (hubssolib_ensure_https) # Redirect back to here using HTTPS, if not already
      hubssolib_store_location(nil)

      if (hubssolib_logged_in?)
        redirect_to :controller => 'tasks', :action => nil
      else
        redirect_to :action => 'login'
      end
    end
  end

protected

  # Pass a HubSsoLib::User object. Returns an equivalent User Model object.
  # If the optional second parameter is 'true' (default 'false'), a failure
  # to find a user in the local database results in 'nil' being returned;
  # otherwise an exception is thrown.
  #
  def to_real_user(user, allow_nil = false)
    return nil if user.nil?
    raise 'Incorrect argument class' unless (user.class == HubSsoLib::User or user.class == DRbObject)

    # Unpleasant "user_" prefix in HubSsoLib::User field names is to avoid
    # collisions (e.g. of "id") with DRbObject.

    real_user = User.find_by_id(user.user_id)

    unless real_user
      raise 'No equivalent real user' if allow_nil == false
      return nil
    end

    real_user.activated_at                   = Time.zone.parse(user.user_activated_at)
    real_user.activation_code                =                 user.user_activation_code
    real_user.created_at                     = Time.zone.parse(user.user_created_at)
    real_user.crypted_password               =                 user.user_crypted_password
    real_user.email                          =                 user.user_email
    real_user.member_id                      =                 user.user_member_id
    real_user.password_reset_code            =                 user.user_password_reset_code
    real_user.password_reset_code_expires_at = Time.zone.parse(user.user_password_reset_code_expires_at)
    real_user.real_name                      =                 user.user_real_name
    real_user.remember_token                 =                 user.user_remember_token
    real_user.remember_token_expires_at      = Time.zone.parse(user.user_remember_token_expires_at)
    real_user.roles                          =                 user.user_roles
    real_user.salt                           =                 user.user_salt
    real_user.updated_at                     = Time.zone.parse(user.user_updated_at)

    return real_user
  end

  # Pass a User Model object. Returns an equivalent HubSsoLib::User object.
  #
  def from_real_user(real_user)
    return nil if real_user.nil?
    raise 'Incorrect argument class' unless real_user.class == User

    user = HubSsoLib::User.new

    user.user_activated_at                   = real_user.activated_at.to_s
    user.user_activation_code                = real_user.activation_code
    user.user_created_at                     = real_user.created_at.to_s
    user.user_crypted_password               = real_user.crypted_password
    user.user_email                          = real_user.email
    user.user_id                             = real_user.id
    user.user_member_id                      = real_user.member_id
    user.user_password_reset_code            = real_user.password_reset_code
    user.user_password_reset_code_expires_at = real_user.password_reset_code_expires_at.to_s
    user.user_real_name                      = real_user.real_name
    user.user_remember_token                 = real_user.remember_token
    user.user_remember_token_expires_at      = real_user.remember_token_expires_at.to_s
    user.user_roles                          = real_user.roles
    user.user_salt                           = real_user.salt
    user.user_updated_at                     = real_user.updated_at.to_s

    return user
  end

  def save_password_and_set_flash(user)
    if ( user.save )
      hubssolib_set_flash(:notice, 'Your password has been changed.')
    else
      hubssolib_set_flash(:alert, 'Sorry, your password could not be changed.')
    end
  end

  def set_password_mismatch_flash
    hubssolib_set_flash(
      :alert,
      'The new password differed from the password confirmation you entered.'
    )
  end

  def allowed_user_params
    params.require(:user).permit(:email, :real_name, :password, :password_confirmation)
  end
end