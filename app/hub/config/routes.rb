Rails.application.routes.draw do

  root 'tasks#index'

  resource :account, only: :create, controller: :account

  get  ':controller(/:action(/:id))(.:format)'
  post ':controller(/:action(/:id))(.:format)'

end
