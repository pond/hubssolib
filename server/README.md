# Hub DRb server

This needs to be running in the background on the same server as any Hub-enabled Rails applications (including the Hub application itself). For security reasons, it is unwise to have distributed Ruby processes exposed to the internet, thus the use of Unix domain ports via the `drbunix` URL scheme is enforced. If you need an SSO solution spanning multiple publically exposed hosts, Hub isn't right for you; you will need a more heavyweight and appropriately secured solution.

## Installation

```
bundle install
```

## Startup

Some basic information about sessions is printed to `$stdout` by default:

```
bundle exec ruby hub_sso_server.rb &
```

Turn off the output entirely by setting environment variable `HUB_QUIET_SERVER` to `yes`, e.g. with:

```
HUB_QUIET_SERVER=yes bundle exec ruby hub_sso_server.rb &
```
