# Vulnerable: RUB-031
class User < ActiveRecord::Base
acts_as_authentic do |t|
    t.login_field=:login # for available options see documentation in: Authlogic::ActsAsAuthentic
  end # block optional
    has_attached_file :avatar, :styles => { :medium => "300x300>", :thumb => "100x100>" }
end
def create
    user = User.create(person_params)
end
class SomeErrorClass < RuntimeError
...
  end
end
