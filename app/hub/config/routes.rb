Rails.application.routes.draw do

  root 'tasks#index'

  resource :account, only: :create, controller: :account do
    resource :login, only: [:show, :create], to: 'account#login'
  end

  get  ':controller(/:action(/:id))(.:format)'
  post ':controller(/:action(/:id))(.:format)'

end
