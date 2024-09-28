# ss14-auth-server.py
Local fake auth server for the game Space Station 14.

Requires the server to be running auth mode 0 or 2. And the client to set the `SS14_LAUNCHER_OVERRIDE_AUTH` environment variable to point to the fake auth server.

User credentials are saved in a single file, passwords are encrypted with the highest standard (base16).
