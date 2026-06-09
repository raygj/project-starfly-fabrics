# Dev-mode allow-all exchange policy.
# NOT for production — allows any token exchange without restriction.

package starfly.exchange

default allow := true

reason := "dev mode: all exchanges allowed"
