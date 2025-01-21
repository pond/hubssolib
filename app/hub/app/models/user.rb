require 'digest/sha1'

class User < ActiveRecord::Base

  CAPTCHA_HONEYPOT  = :birth_year

  MIN_PW_LENGTH     = 10
  MAX_PW_LENGTH     = 200
  PW_LENGTH_RANGE   = (MIN_PW_LENGTH..MAX_PW_LENGTH)

  MIN_MAIL_LENGTH   = 6
  MAX_MAIL_LENGTH   = 200
  MAIL_LENGTH_RANGE = (MIN_MAIL_LENGTH..MAX_MAIL_LENGTH)

  MIN_NAME_LENGTH   = 3
  MAX_NAME_LENGTH   = 200
  NAME_LENGTH_RANGE = (MIN_NAME_LENGTH..MAX_NAME_LENGTH)

  attr_accessor :password # Virtual attribute for the unencrypted password

  validates_length_of       :password, within: PW_LENGTH_RANGE, if: :password_validation_required?
  validates_confirmation_of :password,                          if: :password_validation_required?

  validates_length_of       :email,     within: MAIL_LENGTH_RANGE
  validates_length_of       :real_name, within: NAME_LENGTH_RANGE

  validates_uniqueness_of   :email, case_sensitive: false

  before_create        :set_activation_code
  before_create        :set_salt
  before_save          :encrypt_password
  after_create_commit  :send_welcome_email
  after_destroy_commit :send_destruction_email

  # See hub_sso_lib.rb extensions for String.
  #
  def roles_array
    self.roles.to_authenticated_roles.to_a
  end

  def roles_array=(array)
    self.roles = array.join(',')
  end

  # Authenticates a user by e-mail address and unencrypted password.
  # Returns the user or nil.
  #
  def self.authenticate(email, password)
    # Ignore records that are not active.
    u = self.where(['LOWER(email) = ? and activated_at IS NOT NULL', email.downcase]).first
    u && u.authenticated?(password) ? u : nil
  end

  # Encrypts some data with the salt.
  #
  def self.encrypt(password, salt)
    Digest::SHA1.hexdigest("--#{salt}--#{password}--")
  end

  # Encrypts the password with the user salt.
  #
  def encrypt(password)
    self.class.encrypt(password, salt)
  end

  # Checks if the given password is correct, with built-in delays to thwart
  # timing and brute force attacks. Returns +true+ if the given password is
  # correct, else +false+.
  #
  def authenticated?(password)
    sleep(Random.new.rand(1.0)) # <= 1 second sleep - thwart timing attacks
    correct = self.crypted_password == encrypt(password)
    sleep(3) unless correct # Thwart brute force attacks
    return correct
  end

  # Activates the user in the database (harmless if they're already active).
  # Sends an 'account activated' e-mail if this record was indeed activated.
  #
  def activate
    was_awaiting_activation = self.activation_code.present?

    self.update_columns(
      activated_at:    Time.now,
      activation_code: nil
    )

    if was_awaiting_activation
      UserMailer.with(user: self).activation().deliver_later()
    end
  end

  # Set up the "forgotten password" reset code and expiry limit. Sends a
  # 'here is how to reset your password' e-mail.
  #
  def forgot_password
    self.update_columns(
      password_reset_code:            self.make_password_reset_code(),
      password_reset_code_expires_at: (Time.now.utc) + RESET_TIME_LIMIT
    )

    UserMailer.with(user: self).forgot_password().deliver_later()
  end

  # Pass a password and confirmation supplied by an end user, on assumption of
  # password reset flow *WITH RESET CODE VALIDATED BY THE CALLER*. Saves the
  # details, which may lead to validation issues for password length, mismatch
  # with the confirmation and so-on, or might succeed.
  #
  # * Upon success, clears the reset code data, sends a confirmation e-mail and
  #   returns +true+ with this record fully saved.
  #
  # * Upon failure, the confirmation code is left alone, no e-mail is sent and
  #   returns +false+ with this record in an unsaved, validation-failed state.
  #
  def attempt_password_reset(password, password_confirmation)
    success = false

    User.transaction do
      success = self.update(password: password, password_confirmation: password_confirmation)

      if success
        self.update_columns(
          password_reset_code: nil,
          password_reset_code_expires_at: nil
        )

        UserMailer.with(user: self).reset_password().deliver_later()
      end
    end

    return success
  end

  # Override of base class #destroy which sends an 'account has been deleted'
  # e-mail after calling "super" to perform the deletion.
  #
  def destroy
    UserMailer.with(user: self).destruction().deliver_later()
    super
  end

  # ============================================================================
  # PRIVATE INSTANCE METHODS
  # ============================================================================
  #
  private

    # Scramble a text representation of the current time and date into randomly
    # ordered characters, for use in other randomised tokens.
    #
    def scramble_time
      Time.now.to_s.split(//).sort_by { rand }.join()
    end

    # Set a user activation code for activation e-mail messages before-create.
    #
    def set_activation_code
      self.activation_code = Digest::SHA1.hexdigest(self.scramble_time())
    end

    # Set a unique salt for password encryption before-create. The record ought
    # to have a meaningful #email set prior.
    #
    def set_salt
      self.salt = Digest::SHA1.hexdigest("--#{Time.now.to_s}--#{email}--")
    end

    # Run before-save, this encrypts a password in #password, if present,
    # writing that into attribute #crypted_password.
    #
    def encrypt_password
      self.crypted_password = self.encrypt(password) if self.password.present?
    end

    # After a new record creation has been committed (after-create-commit) to
    # the database, send the 'welcome' e-mail.
    #
    def send_welcome_email
      UserMailer.with(user: self).signup_notification().deliver_later()
    end

    # When a record has just been deleted and only now remains in existence in
    # the form of this ephemeral instance in RAM, send a 'account deleted'
    # confirmation message to the user at this record's e-mail address.
    #
    def send_destruction_email
      UserMailer.with(user_email: self.email).destruction().deliver_later()
    end

    # Is password validation needed for this record?
    #
    def password_validation_required?
      self.crypted_password.blank? || self.password.present?
    end

    # Return a password reset code for users who've forgotten their password.
    #
    def make_password_reset_code
      return Digest::SHA1.hexdigest(self.scramble_time())
    end

end
