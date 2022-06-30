########################################################################
# File::    00_always_run_first.rb
# (C)::     http://thewebfellas.com/blog/2010/7/15/rails-2-3-8-rack-1-1-and-the-curious-case-of-the-missing-quotes
#
# Purpose:: Set up a patching system in "lib/patches".
# ----------------------------------------------------------------------
#           27-Jan-2011 (ADH): Created.
#           31-Jan-2011 (ADH): Imported from Artisan.
########################################################################

Dir[ File.join( Rails.root, "lib", "patches", "**", "*.rb" ) ].sort.each {
  | patch | require( patch )
}
