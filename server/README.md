# Hub DRb server

This needs to be running in the background on the same server as any Hub-enabled Rails applications (including the Hub application itself). For security reasons, it is unwise to have distributed Ruby processes exposed to the internet, thus the use of Unix domain ports via the `drbunix` URL scheme is enforced. If you need an SSO solution spanning multiple publically exposed hosts, Hub isn't right for you; you will need a more heavyweight and appropriately secured solution.

## Installation

```
bundle install
```

## Startup

```
bundle exec ruby hub_sso_server.rb &
```
