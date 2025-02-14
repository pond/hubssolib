#######################################################################
# File:    account_controller.rb                                      #
#          (C) Hipposoft 2006-2020                                    #
#                                                                     #
# Purpose: Hub account management.                                    #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 31-Jan-2011 (ADH): Comment header added; prior history     #
#                             not recorded.                           #
#          11-Apr-2020 (ADH): Rewrote #signup (as #new and #create).  #
#######################################################################

require 'open3'
require 'shellwords'

class AccountController < ApplicationController
  layout 'application'

  # HTTPS enforcement for all methods, except the login indicator; if someone
  # is on an HTTP page, the login indicator needs to be fetched by HTTP too so
  # it can show "logged out" as the secure-only cookies won't get sent. It is
  # very confusing to be on an HTTP page, apparently fetching the indicator by
  # HTTP, only to have the image fetch quietly redirect behind the scenes, go
  # to HTTPS, and say you're logged in - when everyone else thinks you're not.

  require 'hub_sso_lib'
  include HubSsoLib::Core

  before_action :hubssolib_ensure_https

  invisible_captcha(
    honeypot: User::CAPTCHA_HONEYPOT,
    only:     :create,
    scope:    :user,
    on_spam:  :spam_bail
  )

  PROHIBITED_EMAIL_DOMAINS = %w{
    .cn
    .kr
    .ru
  }

  GOOGLE_EMAIL_DOMAINS = %w{
    gmail.com
    googlemail.com
    google.com
  }

  PROHIBITED_GOOGLE_PREFIXES = %w{
    johnnyjohnson3445
    ryangooseman2
    jameswoodsiiiiv
    martinelena086
  }

  LOGGED_IN_IMAGE  = File.read("#{Rails.root}/app/assets/images/account/logged_in.png")
  LOGGED_OUT_IMAGE = File.read("#{Rails.root}/app/assets/images/account/logged_out.png")

  # Action permissions for this class as a class variable, exposed
  # to the public through a class method.
  #
  HUBSSOLIB_PERMISSIONS = HubSsoLib::Permissions.new(
    {
      change_password: [ :admin, :webmaster, :privileged, :normal ],
      change_details:  [ :admin, :webmaster, :privileged, :normal ],
      delete:          [ :admin, :webmaster, :privileged, :normal ],
      delete_confirm:  [ :admin, :webmaster, :privileged, :normal ],
      list:            [ :admin, :webmaster, :privileged          ],
      enumerate:       [ :admin, :webmaster                       ],
      show:            [ :admin, :webmaster                       ],
      edit_roles:      [ :admin                                   ],
      destroy:         [ :admin                                   ],
    }
  )

  def self.hubssolib_permissions
    HUBSSOLIB_PERMISSIONS
  end

  # The "proper" login method
  #
  def login
    @title        = 'Log in'
    return_to_url = params[:return_to_url] || hubssolib_get_return_to() || session[:return_to_url]

    session.delete(:return_to_url)

    # GET methods just show the login screen. Dump all known application
    # cookies at this point, since they can be stale and logins might not
    # be recognised properly otherwise.
    #
    unless request.post?
      self.clear_all_known_session_related_cookies()
      session[:return_to_url] = return_to_url
      return
    end

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

      if return_to_url.present?
        redirect_to(return_to_url)
      else
        redirect_to(root_path())
      end

    else
      hubssolib_set_flash(:alert, 'Incorrect e-mail address or password.')

    end
  end

  # Log out the user and redirect to the Tasks controller.
  #
  def logout
    @title = 'Log out'
    hubssolib_log_out()
    self.clear_all_known_session_related_cookies()

    hubssolib_set_flash(:attention, 'You are now logged out.')
    redirect_to root_path()
  end

  def new
    @user  = User.new
    @title = 'Sign up'

    set_maths_question()
  end

  def create
    @user = User.new(allowed_user_params())

    if @user.email.present?
      @user.email = @user.email.strip()
      return if redirect_if_prohibited!(@user.email) # NOTE EARLY EXIT
    end

    # A simple home-brew maths sort-of-captcha on top of the honeypot.
    #
    correct_answer = get_maths_answer()
    actual_answer  = params.delete(:answer)&.to_i

    set_maths_question()

    if correct_answer != actual_answer
      hubssolib_set_flash(:alert, t('signup.wrong_answer'))
      render :new

      return # NOTE EARLY EXIT
    end

    # Are there any users yet? If not, grant this user admin permissions.
    # Administrators are for just this application; whether or not admin
    # privileges affect other applications depends on the level of external
    # SSO integration.
    #
    is_admin = User.count.zero?

    @user.roles = HubSsoLib::Roles.new(is_admin).to_s
    @user.save

    if @user.errors.present?
      render :new

    else
      if is_admin
        @user.activate
        self.hubssolib_current_user = from_real_user(@user)
        hubssolib_set_flash(:notice, t('signup.success_admin'))
      else
        hubssolib_set_flash(:notice, t('signup.success_normal'))
      end

      redirect_to root_path()

    end
  end

  def activate
    activation_code = params[:activation_code] || params[:id]

    unless activation_code.nil?
      @user = User.find_by_activation_code(activation_code)

      if @user and @user.activate
        self.hubssolib_current_user = from_real_user(@user)

        hubssolib_set_flash(
          :notice,
          t(
            'activate.activated',
            institution_name_long: INSTITUTION_NAME_LONG
          )
        )

        hubssolib_redirect_back_or_default(root_path())
      else
        hubssolib_set_flash(
          :alert,
          t(
            'activate.failed',
            institution_name_long:  INSTITUTION_NAME_LONG,
            institution_name_short: INSTITUTION_NAME_SHORT
          )
        )

        redirect_to :controller => 'account', :action => 'new'
      end
    else
      redirect_to :controller => 'account', :action => 'new'
    end
  end

  # GET to render the form, POST to reset.
  #
  def change_password
    @title = 'Change password'
    @user  = to_real_user(self.hubssolib_current_user)

    return unless request.post? # NOTE EARLY EXIT

    if params[:password].blank? || params[:password_confirmation].blank?
      hubssolib_set_flash(:alert, 'Please enter both a new password and a password confirmation.')
      return # NOTE EARLY EXIT
    end

    if User.authenticate(@user.email, params[:old_password])
      @user.password_confirmation = params[:password_confirmation]
      @user.password              = params[:password]
      success                     = self.save_password_and_set_flash(@user)

      if success
        self.hubssolib_current_user = from_real_user(@user)
        redirect_to root_path()
      else
        self.set_password_bad_flash()
      end
    else
      hubssolib_set_flash(:alert, 'Incorrect current password.')
    end
  end

  def change_details
    @title = 'Update account details'
    @user  = to_real_user(self.hubssolib_current_user)

    return if request.get? # NOTE EARLY EXIT

    success           = false
    email_changed     = false
    real_name_changed = false
    old_email         = @user.email
    old_real_name     = @user.real_name
    old_unique_name   = "#{old_real_name} (#{@user.id})"
    new_email         = (params.dig(:user, :email    ) || old_email    ).strip
    new_real_name     = (params.dig(:user, :real_name) || old_real_name).strip
    new_unique_name   = "#{new_real_name} (#{@user.id})"

    User.transaction do
      @user.email       = new_email
      @user.real_name   = new_real_name
      real_name_changed = @user.real_name_changed?
      email_changed     = @user.email_changed?

      # This might invoke a redirection...
      #
      if email_changed && redirect_if_prohibited!(@user.email)
        raise ActiveRecord::Rollback # NOTE TRANSACTION ROLLBACK AND BLOCK EXIT
      end

      success = @user.save

      if success && (real_name_changed || email_changed)
        successful_commands = []

        hubssolib_registered_user_change_handlers().each do | app_name, details |
          command_root = details['root']
          command_task = details['task']

          # THIS ORDERING IS IMPORTANT AND MUST BE PRESERVED else dependent
          # Rake tasks will break. Rake only supports positional arguments.
          #
          rake_task_args_string = [
            old_email,
            old_unique_name,
            new_email,
            new_unique_name
          ].join(', ')

          stdout = ''
          stderr = ''
          status = nil

          Bundler.with_clean_env do
            stdout, stderr, status = Open3.capture3(
              'bundle',
              'exec',
              'rake',
              "#{command_task}[#{rake_task_args_string}]",

              chdir: command_root
            )
          end

          if status.exitstatus == 0
            successful_commands << app_name.inspect
          else
            message = "When updating details of Hub user ID #{@user.id} to #{new_email.inspect} and #{new_unique_name}, task #{command_task.inspect} for #{app_name.inspect} failed with stderr #{stderr.inspect} and stdout #{stdout.inspect}. "

            if successful_commands.empty?
              message << 'No other commands ran beforehand (manual clean-up is not required).'
            else
              message << "WARNING: Manual clean-up requried - previously successful command(s) were run for: #{successful_commands.join(', ')}."
            end

            raise message
          end
        end

        if email_changed
          hubssolib_log_out()
          self.clear_all_known_session_related_cookies()
          hubssolib_set_flash(:attention, 'You are now logged out because your account needs reactivation. Please check your new e-mail address for instructions.')
        else
          self.hubssolib_current_user = from_real_user(@user)
          hubssolib_set_flash(:notice, 'Account details updated successfully.')
        end

        redirect_to root_path()
      end

    rescue ActiveRecord::Rollback
      #
      # Do nothing - let the block exit. This is only here because of the broad
      # exception handler below. Without that, Rollback exceptions are trapped
      # by ActiveRecord and exit quietly anyway - that's what they're for.

    rescue => e
      Sentry.configure_scope do |scope|
        scope.set_context(
          'hub_user_details_changed',
          {
            old_email:            old_email,
            new_email:            new_email,
            old_unique_real_name: "#{old_real_name} (#{@user.id})",
            new_unique_real_name: "#{new_real_name} (#{@user.id})",
          }
        )

        Sentry.capture_exception(e)

        hubssolib_set_flash(
          :alert,
          "An internal error occurred and your details could not be changed. #{INSTITUTION_NAME_LONG} should be aware of the error, but if in doubt, please send an e-mail to #{INSTITUTION_NAME_EMAIL}."
        )

        redirect_to root_path()
        raise ActiveRecord::Rollback
      end
    end

    # If we get here, there might have been a redirection to root for either
    # various success or failure cases - or nothing, yet. In that case the
    # form is just rendered normally, for simple validation error cases.
    #
  end

  def forgot_password
    @title = 'Forgotten password'
    return unless request.post?

    @user = User.where("LOWER(email) = ?", params[:email]&.downcase).first

    unless @user.nil?
      @user.forgot_password
      @user.save!
    end

    hubssolib_set_flash(
      :notice,
      'If that account exists, then an e-mail message which tells you how to ' <<
      'reset your password has been sent to you.'
    )
  end

  # GET to render the form, POST to reset.
  #
  def reset_password
    @title = 'Reset password'

    if params[:id].nil?
      hubssolib_redirect_back_or_default(root_path())
      return # NOTE EARLY EXIT
    end

    @user = User.find_by_password_reset_code(params[:id])

    if (@user.nil?)
      hubssolib_set_flash(
        :alert,
        'Invalid reset code. Did your e-mail client break up the reset '   <<
        'link so it spanned more than one line? If so, please try again, ' <<
        'copying all of the link in the message however many lines it spans.'
      )

      hubssolib_redirect_back_or_default(root_path())
      return # NOTE EARLY EXIT
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

    unless request.post?
      hubssolib_set_flash(:alert, 'Reset your password using the form below.')
      return # NOTE EARLY EXIT
    end

    # This will save the password if valid and clear the reset code, else it
    # will leave @user marked with validation errors.
    #
    success = @user.attempt_password_reset(
      params[:password],
      params[:password_confirmation]
    )

    if success
      self.save_password_and_set_flash(@user) # (a redundant, but harmless #save happens inside here)
      self.hubssolib_current_user = from_real_user(@user)
      redirect_to root_path()
    else
      self.set_password_bad_flash()
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
    redirect_to root_path()
  end

  def list
    scope  = User.all
    @title = 'List of user accounts'
    search = params[:q]

    if (search.present?)
      text  = "%#{ ActiveRecord::Base.sanitize_sql_like(search) }%"
      scope = scope.where("real_name ILIKE ? OR email ILIKE ?", text, text)
    end

    scope = scope.order('created_at DESC')
    limit = params[:page] == 'all' ? :all : 20

    @user_pages, @users = pagy_with_params(scope: scope, default_limit: limit)
  end

  # Enumerate active users (those users known to the DRb server).
  #
  def enumerate
    @title = 'Active users'

    users = hubssolib_enumerate_users
    users = [] if users.nil?

    # Map the user objects returned from the HubSsoLib Gem to
    # internal user IDs.
    #
    users.map! { |user| to_real_user(user, true)&.id }
    users.compact!
    users.uniq!

    # Turn that into an ordered ActiveRecord::Relation.
    #
    scope = User.where(id: users).order('created_at DESC')
    @user_pages, @users = pagy_with_params(scope: scope)
  end

  # Show details of a specific user account.
  #
  def show
    @title    = 'User account details'
    @user     = User.find(params[:id])
    @referrer = request.referrer

    # This is usually accessed via the list which might be on any page. If
    # we use 'referrer' (as the "show" view code does) in a "go back to list"
    # option, then the page is maintained. But if we've just come from e.g.
    # the "edit roles" form, the referrer would be the form URL which isn't
    # what we want.
    #
    @referrer = nil unless @referrer&.include?(list_account_path())
  end

  def edit_roles
    @title = 'Edit account roles'

    # We must have a valid ID

    unless (params[:id]) and (@user = User.find(params[:id]))
      redirect_to root_path()
      return
    end

    # This is fetched via a protected (non-simple-spider) POST rather than GET
    # for the form presentation, but form *submissions* - processed after this
    # - use PATCH.
    #
    return unless request.patch?

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

  # Typically only used via the HubSsoLib::Core#hubssolib_account_link helper.
  #
  # Redirects to the login page if the user is logged out or the tasks page if
  # the user is logged in. It explicitly clears a return-to link, if there is
  # one, so that the user doesn't drop out of Hub. This is useful if the page
  # from which the user came cannot support (for example) the Flash display
  # because of, say, caching.
  #
  def login_conditional
    if (hubssolib_ensure_https) # Redirect back to here using HTTPS, if not already
      if (hubssolib_logged_in?)
        hubssolib_store_location(nil)
        redirect_to root_path()
      else
        hubssolib_store_location(request.referrer)
        redirect_to login_account_path()
      end
    end
  end

  # Typically only used via the HubSsoLib::Core#hubssolib_account_link helper,
  # and intended to be rendered only by NOSCRIPT browsers usually.
  #
  # Returns a 2x density ("high DPI") PNG of size 180x44 physical pixels for
  # intended rendering at half that, i.e. 90x22 "web pixels", which indicates
  # a logged in or logged out state.
  #
  # This image has a no-cache header, so inclusion in a wider cached page will
  # not result in a stale login indication, as might otherwise be the case.
  #
  # JavaScript-enabled clients ought to work entirely locally, using cookies to
  # determine login state at runtime and adjusting the page markup accordingly.
  # This removes the need for an image fetch to this endpoint on every page.
  #
  # This endpoint only exists because the RISC OS Open web site is known to be
  # visited by browsers without JavaScript support.
  #
  def login_indication
    headers['Pragma']        = 'no-cache'
    headers['Cache-Control'] = 'no-cache, must-revalidate'

    send_data(
      hubssolib_logged_in? ? LOGGED_IN_IMAGE : LOGGED_OUT_IMAGE,
      type:        'image/png',
      disposition: 'inline'
    )
  end

  # ============================================================================
  # PRIVATE INSTANCE METHODS
  # ============================================================================
  #
  private

    # Dump all known application cookies; they can be stale and logins might
    # not be recognised properly otherwise, or the user might've just logged
    # out.
    #
    def clear_all_known_session_related_cookies
      cookies.delete(HubSsoLib::HUB_COOKIE_NAME)
      cookies.delete(HubSsoLib::HUB_LOGIN_INDICATOR_COOKIE)

      cookies.to_h.keys.each do | key |
        cookies.delete(key) if key.end_with?('app_session') # E.g. 'hubapp_session', 'beastapp_session'
      end
    end

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

    # If the given e-mail address is in any of the prohibition lists, redirect
    # to root with an appropriate Flash warning and return +true+, else return
    # +false+.
    #
    def redirect_if_prohibited!(intended_email)
      lower_email      = intended_email.strip.downcase()
      is_prohibited    = PROHIBITED_EMAIL_DOMAINS.any? { | domain | lower_email.end_with?(domain) }
      is_google_domain =     GOOGLE_EMAIL_DOMAINS.any? { | domain | lower_email.end_with?(domain) } unless is_prohibited

      if is_google_domain
        canonical_lower_email = lower_email.gsub('.', '')
        lower_email_prefix    = canonical_lower_email.gsub(/[+@].*$/, '')
        is_prohibited         = PROHIBITED_GOOGLE_PREFIXES.any? { | prefix | prefix == lower_email_prefix }
      end

      if is_prohibited
        hubssolib_set_flash(
          :attention,
          t('signup.blocked', institution_name_short: INSTITUTION_NAME_SHORT)
        )

        redirect_to root_path()
        return true
      else
        return false
      end
    end

    def save_password_and_set_flash(user)
      success = user.save()

      if success
        hubssolib_set_flash(:notice, 'Your password has been changed.')
      else
        self.set_password_bad_flash()
      end

      return success
    end

    def set_password_bad_flash
      hubssolib_set_flash(
        :alert,
        "The password differed from the password confirmation, or was too short. Passwords must be at least #{User::MIN_PW_LENGTH} letters long."
      )
    end

    def allowed_user_params
      params.require(:user).permit(
        :email,
        :real_name,
        :password,
        :password_confirmation
      )
    end

    def set_maths_question
      session[:num1] = (2..9).to_a.sample
      session[:num2] = (2..9).to_a.sample
      session[:op  ] = %w{+ - *}.sample
    end

    def get_maths_answer
      num1   = session[:num1].to_i
      num2   = session[:num2].to_i
      answer = case session[:op]
        when '+'
          num1 + num2
        when '-'
          num1 - num2
        when '*'
          num1 * num2
      end

      return answer
    end

    def spam_bail
      hubssolib_set_flash(
        :alert,
        "Sorry, we didn't understand that sign-up attempt. Please try again."
      )

      redirect_to signup_account_path()
    end

end
