########################################################################
# File::    99_sanity_checker.rb
# (C)::     Hipposoft 2010
#
# Purpose:: Make sure essential constants are defined.
# ----------------------------------------------------------------------
#           05-Apr-2010 (ADH): Created.
#           31-Jan-2011 (ADH): Imported from Artisan.
########################################################################

raise "Please make sure that the various options in " +
      "'config/environments/#{ RAILS_ENV }.rb' "      +
      "and "                                          +
      "'config/initializers/40_general_settings.rb' " +
      "have been configured." if
(
   defined?( INSTITUTION_NAME_LONG ).nil? ||
             INSTITUTION_NAME_LONG.nil?   ||
   defined?( EMAIL_ADMIN ).nil?           ||
             EMAIL_ADMIN.nil?
)
