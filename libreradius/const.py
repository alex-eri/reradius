AccessDrop = 0



# types
AccessRequest = 1
AccessAccept = 2
AccessReject = 3
AccountingRequest = 4
AccountingResponse = 5
AccessChallenge = 11
StatusServer = 12
StatusClient = 13
DisconnectRequest = 40
DisconnectACK = 41
DisconnectNAK = 42
CoARequest = 43
CoAACK = 44
CoANAK = 45

# Common Attrs
EAPMessage           = 79
MessageAuthenticator = 80

# Accounting
AccountingStart  = 1
AccountingStop   = 2
AccountingUpdate = 3
AccountingOn     = 7
AccountingOff    = 8


# Acct-Terminate-Cause
TCUserRequest        =  1
TCLostCarrier        =  2
TCLostService        =  3
TCIdleTimeout        =  4
TCSessionTimeout     =  5
TCAdminReset         =  6
TCAdminReboot        =  7
TCPortError          =  8
TCNASError           =  9
TCNASRequest         = 10
TCNASReboot          = 11
TCPortUnneeded       = 12
TCPortPreempted      = 13
TCPortSuspended      = 14
TCServiceUnavailable = 15
TCCallback           = 16
TCUserError          = 17
TCHostRequest        = 18