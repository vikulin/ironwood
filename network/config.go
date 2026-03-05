package network

import (
	"time"

	"github.com/Arceliar/ironwood/types"
)

type config struct {
	routerRefresh      time.Duration
	routerTimeout      time.Duration
	peerKeepAliveDelay time.Duration
	peerTimeout        time.Duration
	peerMaxMessageSize uint64
	bloomTransform     func(types.Domain) types.Domain
	pathNotify         func(types.Domain)
	pathTimeout        time.Duration
	pathThrottle       time.Duration
}

type Option func(*config)

func configDefaults() Option {
	return func(c *config) {
		c.routerRefresh = 4 * time.Minute
		c.routerTimeout = 5 * time.Minute
		c.peerKeepAliveDelay = time.Second
		c.peerTimeout = 3 * time.Second
		c.peerMaxMessageSize = 1048576 // 1 megabyte
		c.bloomTransform = func(key types.Domain) types.Domain { return key }
		c.pathNotify = func(key types.Domain) {}
		c.pathTimeout = time.Minute
		c.pathThrottle = time.Second
	}
}

func WithRouterRefresh(duration time.Duration) Option {
	return func(c *config) {
		c.routerRefresh = duration
	}
}

func WithRouterTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.routerTimeout = duration
	}
}

func WithPeerKeepAliveDelay(duration time.Duration) Option {
	return func(c *config) {
		c.peerKeepAliveDelay = duration
	}
}

func WithPeerTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.peerTimeout = duration
	}
}

func WithPeerMaxMessageSize(size uint64) Option {
	return func(c *config) {
		c.peerMaxMessageSize = size
	}
}

func WithBloomTransform(xform func(key types.Domain) types.Domain) Option {
	return func(c *config) {
		c.bloomTransform = xform
	}
}

func WithPathNotify(notify func(key types.Domain)) Option {
	return func(c *config) {
		c.pathNotify = notify
	}
}

func WithPathTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.pathTimeout = duration
	}
}

func WithPathThrottle(duration time.Duration) Option {
	return func(c *config) {
		c.pathThrottle = duration
	}
}
