# Unless documented, all e-mail sending methods take a 'user' parameter which
# is set to the User record representing the e-mail's intended recipient.
#
class UserMailer < ApplicationMailer
  EMAIL_PLAIN_TEXT_LINE_WIDTH = 70

  # Word-wrap a given plain text message to EMAIL_PLAIN_TEXT_LINE_WIDTH width.
  # Returns the hard-wrapped String equivalent of the input +text+.
  #
  def self.hard_wrap(text)

    # The 'extend' stuff is a clean way of calling through to a helper.
    #
    Object.new.extend(ActionView::Helpers::TextHelper).word_wrap(
      text,
      line_width: EMAIL_PLAIN_TEXT_LINE_WIDTH
    )
  end

  def signup_notification
    @user = params[:user]
    @url  = url_for(controller: :account,
                    action:     :activate,
                    id:         @user.activation_code,
                    protocol:   'https')

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Please activate your new web site account"
    )
  end

  def activation
    @user = params[:user]
    @url  = root_url()

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Your web site account has been activated"
    )
  end

  def reactivation_notification
    @user = params[:user]
    @url  = url_for(controller: :account,
                    action:     :activate,
                    id:         @user.activation_code,
                    protocol:   'https')

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Please reactivate your account"
    )
  end

  def forgot_password
    @user = params[:user]
    @url  = url_for(controller: :account,
                    action:     :reset_password,
                    id:         @user.password_reset_code,
                    protocol:   'https')

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Request to change a web site account password"
    )
  end

  def reset_password
    @user = params[:user]
    @url  = EMAIL_ADMIN

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Your web site account password has been reset"
    )
  end

  # This one takes the user's e-mail address as a parameter, not any kind of
  # reference to a user. Under the hood, a 'find' would be attempted - but the
  # record has already been deleted by the time the message is being sent.
  #
  def destruction
    email = params[:user_email]
    @url  = EMAIL_ADMIN

    mail(
      to:      email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Your web site account has been deleted"
    )
  end
end
