# Welcome to Hub

Hub is a single sign-on solution for multiple Ruby On Rails applications which
are running under the same domain but different paths within that domain. When
a user signs into Hub, they don't have to individually sign in to other
applications on the domain provided that those applications are integrated
with the Hub mechanism. This requires software development effort on behalf of
the application installer or application developer.

Hub provides a solution to a different problem from that addressed by cross
domain single sign-on solutions such as OpenID, wherein a user will typically
have to sign in to domain individually, but is at least able to do so using a
single set of identifying credentials.

## Installation

Use `bundler` to install gem dependencies:

```
bundle install
```

## Database setup

Use the migrations rather than schema:

```
bundle exec rake db:create
bundle exec rake db:migrate
```

## Further reading

For more information about Hub, please see:

* http://hub.pond.org.uk/

For more information about Ruby On Rails, please see:

* http://www.rubyonrails.org/

For more software from Hipposoft, please visit:

* http://hipposoft.pond.org.uk/
