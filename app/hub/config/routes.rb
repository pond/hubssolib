Rails.application.routes.draw do

  root 'tasks#index'
  get  '/:controller/:action/:id'

end
