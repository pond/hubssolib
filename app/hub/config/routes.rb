Rails.application.routes.draw do

  root 'tasks#index'

  get  ':controller(/:action(/:id))(.:format)'
  post ':controller(/:action(/:id))(.:format)'

end