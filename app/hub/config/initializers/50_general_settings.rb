########################################################################
# File::    50_general_settings.rb
# (C)::     Hipposoft 2011
#
# Purpose:: Static Hub configuration which is invariant across different
#           environments (see also "config/environments/*.rb" and
#           "config/environment.rb").
# ----------------------------------------------------------------------
#           09-Mar-2009 (ADH): Created.
#           31-Jan-2011 (ADH): Imported from Artisan.
########################################################################

# Hub is a single-sign on solution for multiple Rails applications within a
# single domain. It's assumed that this domain is presenting an assemblage of
# Rails applications as a coherent name, to represent some company, or
# individual, or "institution". That instutition has a name - your personal
# name, company name, society name or similar - which is used in e-mail
# addresses for sign-up and so-on.
#
# Below, configure the institution's full and abbreviated names. These can be
# the same if you like, but as an example, for RISC OS Open we use "RISC OS
# Open" and "ROOL" for the full and abbreviated names respectively.
#
INSTITUTION_NAME_LONG  = "RISC OS Open"
INSTITUTION_NAME_SHORT = "ROOL"
INSTITUTION_NAME_EMAIL = "info@riscosopen.org"

# Maximum number of items to show per page in sortable list views.

MAXIMUM_LIST_ITEMS_PER_PAGE = 25
