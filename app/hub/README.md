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

If your host is unusual and you get issues with e.g. Nokogiri failing to
`require 'nokogiri/nokogiri'` or e.g. SASS complaining about range characters,
there's a good chance that you need to compile gems manually rather than using
pre-built binaries as those aren't working on your host. In that case:

```
bundle config force_ruby_platform true
```

...and consider e.g. `rm Gemfile.lock; bundle update` to force a rebuild. You
may need to manually remove any prebuilt gem versions with `gem uninstall` -
it will list all gem versions if there is more than one choice and the variant
built for a specific architecture is easy to see as the architecture's name is
listed with the gem.

## Database setup

Use the migrations rather than schema:

```
bundle exec rake db:create
bundle exec rake db:migrate
```

## Running

It's often best to put the Hub SSL application on a different port from the
usual one used for Rails applications, so you can leave it running in the
background on some less conventional URL while developing the code in your
application with integrates with Hub on the usual port number.


```
bundle exec rails s --port 3001
```


## Further reading

For more information about Hub, please see:

* http://hub.pond.org.uk/

For more information about Ruby On Rails, please see:

* http://www.rubyonrails.org/

For more software from Hipposoft, please visit:

* http://hipposoft.pond.org.uk/
