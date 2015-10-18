# Limit Login Sessions
WordPress plugin for limiting maximum amount of active login session for a user account.

# Features

It doesn't provide a settings page yet, so all options are currently hard coded. The plugin implements the following:

1. A user can have a maximum of 5 login sessions across various browsers and devices.
2. If more then 5 sessions are attempted it will show an error, unless the oldest activity session is more then 4 hours old.
3. If the oldest activity session is more then 4 hours old, that session will be closed and current attempt of the login is allowed.
