# https://coderwall.com/p/mzeenq/showing-errors-messages-in-rails-4
#
module ErrorMessagesHelper
  # Render error messages for the given objects. The :message and :header_message options are allowed.
  def error_messages_for(*objects)
    options = objects.extract_options!
    options[:header_message] ||= t(:"errors.template.header", model: t(:"activerecord.models.#{objects.compact.first.class.name.downcase}"), count: objects.compact.first.errors.messages.size)
    options[:message] ||= t(:"errors.template.body")
    messages = objects.compact.map { |o| o.errors.full_messages }.flatten
    unless messages.empty?
      content_tag(:div, id: "error_explanation") do
        list_items = messages.map { |msg| content_tag(:li, msg) }
        content_tag(:h2, options[:header_message]) + content_tag(:p, options[:message]) + content_tag(:ul, list_items.join.html_safe)
      end
    end
  end

  module FormBuilderAdditions
    def error_messages(options = {})
      @template.error_messages_for(@object, options)
    end
  end
end

ActionView::Helpers::FormBuilder.send(:include, ErrorMessagesHelper::FormBuilderAdditions)
