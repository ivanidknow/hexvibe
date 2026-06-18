# Vulnerable: RUB-053
skip_before_action :require_user, :except => [:do_admin_stuff, :do_other_stuff]
    def do_admin_stuff
        #do some stuff
    end
    def do_anonymous_stuff
      # do some stuff
    end
end
class GoodController < ApplicationController
  #Examples of skipping important filters with a blacklist instead of whitelist
