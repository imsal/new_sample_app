Rails.application.routes.draw do
  root 'static_pages#home'
  get '/contact', to: 'static_pages#contact'
  get '/about', to: 'static_pages#about'
  get '/help', to: 'static_pages#help'
  get '/signup', to: 'users#new'#, as: 'signup'
  post '/signup', to: 'users#create'
  get    '/login',   to: 'sessions#new'
  post   '/login',   to: 'sessions#create'
  delete '/logout',  to: 'sessions#destroy'
  resources :users # Creates the REST routes needed in controllers
  resources :account_activations, only: [:edit] # sets up just the edit action for this route
  resources :password_resets, only: [:edit, :update, :new, :create] # for creating forms with password resets
end
