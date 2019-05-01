class UserNotifier < ActionMailer::Base

  helper :application

  EMAIL_PLAIN_TEXT_LINE_WIDTH = 70

  # Return a string formatted according to e-mail text width resrtrictions.
  #
  def self.formatted( text )
    # The strange 'extend' stuff is a way of calling through to a helper.
    Object.new.extend( ActionView::Helpers::TextHelper ).word_wrap(
      text,
      :line_width => EMAIL_PLAIN_TEXT_LINE_WIDTH
    )
  end

  def signup_notification(user)
    setup_mail(
      user,
      "[#{INSTITUTION_NAME_SHORT}] Please activate your new web site account",
      url_for(:controller => :account,
              :action     => :activate,
              :id         => user.activation_code,
              :protocol   => 'https')
    )
  end

  def activation(user)
    setup_mail(
      user,
      "[#{INSTITUTION_NAME_SHORT}] Your web site account has been activated",
      root_url()
    )
  end

  def forgot_password(user)
    setup_mail(
      user,
      "[#{INSTITUTION_NAME_SHORT}] Request to change a web site account password",
      url_for(:controller => :account,
              :action     => :reset_password,
              :id         => user.password_reset_code,
              :protocol   => 'https')
    )
  end

  def reset_password(user)
    setup_mail(
      user,
      "[#{INSTITUTION_NAME_SHORT}] Your web site account password has been reset",
      EMAIL_ADMIN
    )
  end

  def destruction(user)
    setup_mail(
      user,
      "[#{INSTITUTION_NAME_SHORT}] Your web site account has been deleted",
      EMAIL_ADMIN
    )
  end

protected

  # Prepare for and render an e-mail message view. Pass the recipient User
  # object, subject text and an associated URL which will be shown in the body.
  #
  # Passes parameter 'url' through as local "@url" through to the view.
  #
  def setup_mail( user, subject, url )
    subject      subject
    from         EMAIL_ADMIN
    recipients   user.email
    sent_on      Time.now
    content_type 'text/plain'
    body         render(
                   :file => "user_notifier/#{ action_name }.txt.erb",
                   :body => { :url => url }
                 )
  end
end
