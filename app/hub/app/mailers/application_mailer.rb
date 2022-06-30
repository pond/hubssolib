class ApplicationMailer < ActionMailer::Base
  default from: EMAIL_ADMIN
  layout 'mailer'
end
