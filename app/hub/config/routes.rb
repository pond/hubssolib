Rails.application.routes.draw do
  root 'tasks#index'
  get  'tasks/service/:id', to: 'tasks#service', as: 'tasks_service'

  # Mother of all routing hacks - have the 'create' action routed, but give us
  # an easy namespace for the plethora of old-fashioned and very non-RESTful
  # routes also present within the controller. Note that the 'new' view is
  # routed under the path 'signup'.
  #
  resource :account, only: :create, controller: :account do
    get 'signup',               to: 'account#new' # (sic.)
    get '',                     to: 'account#new' # (invisible Captcha uses this)
    get 'activate',             to: 'account#activate'
    get 'login_conditional',    to: 'account#login_conditional'
    get 'login_indication',     to: 'account#login_indication'

    # GET or POST routes to the same action (VERY old-fashioned Rails code).
    #
    match :login,               to: 'account#login',           via: [:get, :post]
    match :change_details,      to: 'account#change_details',  via: [:get, :post]
    match :change_password,     to: 'account#change_password', via: [:get, :post]
    match :forgot_password,     to: 'account#forgot_password', via: [:get, :post]

    match 'reset_password/:id', to: 'account#reset_password',  via: [:get, :post]
    post  'delete',             to: 'account#delete'
    post  'delete_confirm',     to: 'account#delete_confirm'
    get   'logout',             to: 'account#logout'

    # Administrator actions - listing known users, enumerating active users,
    # showing details of specific accounts and editing them, or deleting
    # specific accounts.
    #
    # * The 'edit_roles' form fetches via POST to protect against very crude
    #   web crawlers hitting it, but submits via PATCH.
    #
    get   'list',               to: 'account#list'
    get   'enumerate',          to: 'account#enumerate'
    get   'show/:id',           to: 'account#show'
    match 'edit_roles/:id',     to: 'account#edit_roles', via: [:post, :patch], as: 'edit_roles'
    post  'destroy/:id',        to: 'account#destroy'
  end
end
