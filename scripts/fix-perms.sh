#!/bin/bash

umask 077;
set -e;
# set -x;

AUTH_DATA_ROOT="/opt/auth";
cd "${AUTH_DATA_ROOT}";
mkdir -p keys logs

find "${AUTH_DATA_ROOT}" -type d -print0 | xargs -n60 -P 5 -0 chmod 0700
find "${AUTH_DATA_ROOT}" -type f -print0 | xargs -n60 -P 5 -0 chmod 0600

chmod 0750 "${AUTH_DATA_ROOT}";
chmod 0700 "${AUTH_DATA_ROOT}/wrappers/ssh.py";

# Runtime processes run as the auth user and must be able to read configs.
# Configs may contain secrets, so keep them readable only by auth/auth group.
chown -R auth:auth "${AUTH_DATA_ROOT}/configs"
chmod 0750 "${AUTH_DATA_ROOT}/configs"
find "${AUTH_DATA_ROOT}/configs" -type f -print0 | xargs -r -n60 -P 5 -0 chmod 0640

# Logs are written by interactive users in the auth group. Keep the rest of
# /opt/auth strict, but preserve group-write and setgid for session logs.
chown auth:auth "${AUTH_DATA_ROOT}/logs"
chmod 2770 "${AUTH_DATA_ROOT}/logs"
find "${AUTH_DATA_ROOT}/logs" -mindepth 1 -type d -print0 | xargs -r -n60 -P 5 -0 chgrp auth
find "${AUTH_DATA_ROOT}/logs" -mindepth 1 -type d -print0 | xargs -r -n60 -P 5 -0 chmod 2770
find "${AUTH_DATA_ROOT}/logs" -type f -print0 | xargs -r -n60 -P 5 -0 chgrp auth
find "${AUTH_DATA_ROOT}/logs" -type f -print0 | xargs -r -n60 -P 5 -0 chmod 0660

find "${AUTH_DATA_ROOT}/shared" -type d -print0 | xargs -n60 -P 5 -0 chmod 0750
find "${AUTH_DATA_ROOT}/shared" -type f -print0 | xargs -n60 -P 5 -0 chmod 0640
chmod 0750 "${AUTH_DATA_ROOT}/shared/helper.py";
chmod 0700 "${AUTH_DATA_ROOT}/shared/auth-manager.py";
chmod 0700 "${AUTH_DATA_ROOT}/shared/isolate.py";
touch "${AUTH_DATA_ROOT}/known_hosts";
chmod 0600 "${AUTH_DATA_ROOT}/known_hosts";

# python fixes
#find /usr/lib/python2.7/site-packages/ -type d -print0 | xargs -n60 -P 5 -0 chmod 0755
#find /usr/lib/python2.7/site-packages/ -type f -print0 | xargs -n60 -P 5 -0 chmod 0644
#find /usr/lib64/python2.7/site-packages/ -type d -print0 | xargs -n60 -P 5 -0 chmod 0755
#find /usr/lib64/python2.7/site-packages/ -type f -print0 | xargs -n60 -P 5 -0 chmod 0644

# oath hash storage
#chmod 0700 /etc/oath/
#chmod 0600 /etc/oath/users.oath
#chown -R root:root /etc/oath/
