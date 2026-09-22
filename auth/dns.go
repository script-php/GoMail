package auth

import "net"

// DNS functions are variables so standards behavior can be tested without
// depending on public DNS. Tests restore them after use.
var lookupTXT = net.LookupTXT
