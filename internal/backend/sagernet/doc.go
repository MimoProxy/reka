// Package sagernet is the only package in Reka that imports sing-box and
// sing-tun. Everything else depends on the types defined here.
//
// The backend never builds a sing-box Box. It registers a handful of Reka
// implementations of the upstream context services (router, network manager,
// DNS) and constructs protocol instances directly, each with its own
// lifecycle scope, so that one instance can be replaced or closed without
// restarting the rest.
package sagernet
