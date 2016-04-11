# l7proxyify

l7proxyify is designed to transparently proxy TLS traffic traversing a NAT host. It uses the Server Name Indicator attribute (SNI) in the ClientHello msg of TLS request to proxy a connection to it's destination.

Further reading on this idea is [squid-cache SSL Peek and Splice](http://wiki.squid-cache.org/Features/SslPeekAndSplice).

# Background

Check out my presentation [Build a proxy with Go](https://speakerdeck.com/wolfeidau/building-a-proxy-in-go) which I presented at the golang meetup in Melbourne, AU.

# Usage

```
L7 Proxy server

Usage:
  l7proxify [flags]

Flags:
      --debug              Log debug information.
      --localAddr string   Local listen address. (default "localhost:13131")
```

# Configuration

```toml
# globals
debug = true

[logging]
json = false

[rules]

[rules.001]
match = "amazonaws.com$"
action = "allow"

[rules.002]
match = "^github.com$"
action = "allow"

[rules.003]
match = ".*"
action = "deny"
```

# TODO

* Implement Server Hello parsing
* Enhance the rules with more options around which attributes to look at
* Add tracing for auditing
* Add metrics and health check endpoint

# References

* [Traffic Analysis of an SSL/TLS Session](http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session)

# Disclaimer

This is a **work in progress**, I released the code to demonstrate how it works and will continue development on it to add a lot more features over the coming months.

# License

This code is released under the MIT license see the LICENSE.md file for more details.
