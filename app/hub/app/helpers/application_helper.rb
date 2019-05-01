# Methods added to this helper will be available to all templates in the application.

module ApplicationHelper

  # Make a link to the given controller and action, using an image based on the
  # action name of the given width and height. A <br /> tag separates the image
  # from some given text to add underneath, also a link. Since web spiders may
  # follow standard links, do not use this call for destructive actions such as
  # 'delete'; use make_protected_action_link instead. Remember that 'robots.txt'
  # files are not entirely sufficient as some local Desktop cacheing software
  # packages ignore them, and this sort of software is more likely to be running
  # under login credentials that let it get at otherwise protected pages.
  #
  # If you don't want the text link adding, pass 'nil' or an empty string.
  #
  # To override the default URI constructed from the given controller and
  # action, provide a sixth parameter with the required URI.
  #
  def make_action_link(controller, action, width, height, text, uri = nil)
    if (uri.nil?)

      html = link_to(image_tag(image_path("#{controller}/#{action}.png"), :size => "#{width}x#{height}", :border => 0),
                     {:controller => controller, :action => action}, :class => 'image')

      unless (text.nil? or text.empty?)
        html << '<br />'
        html << link_to(text, :controller => controller, :action => action)
      end

    else

      html = content_tag("a", image_tag(image_path("#{controller}/#{action}.png"), :size => "#{width}x#{height}", :border => 0),
                         { :href => uri, :class => 'image' })
      unless (text.nil? or text.empty?)
        html << '<br />'
        html << content_tag("a", text, { :href => uri })
      end

    end

    return html
  end

  # Make a protected link to the given controller and action with the given ID,
  # using an image based on the action name. The link is done as an image button
  # in a form to help stop accidental activation by web spiders (so use this call
  # for destructive actions such as 'delete'). Some given text is put underneath
  # the form but not included as part of the link. The final parameter is
  # optional; if you want a JavaScript "onclick" confirmation before the form can
  # be submitted, pass the message to use in the dialogue box here.
  #
  # If you don't want the text link adding, pass 'nil' or an empty string.
  #
  def make_protected_action_link(controller, action, id, text, onclick = nil)
    opts = {:type => 'image',
            :name => 'submit',
            :alt  => action.humanize,
            :src  => image_path("#{controller}/#{action}.png")}

    unless (onclick.nil? or onclick.empty?)
      opts[:onclick] = "return confirm('#{onclick}');"
    end

    html = form_tag({:controller => controller, :action => action, :id => id})
    html << tag('input', opts)
    html << '</form>'

    unless (text.nil? or text.empty?)
      html << text
    end

    return html
  end
end
