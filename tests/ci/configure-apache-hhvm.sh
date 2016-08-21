#!/bin/sh

# Configure apache virtual hosts
sudo cp -f tests/ci/travis-ci-apache-hhvm /etc/apache2/sites-available/default
sudo sed -e "s?%TRAVIS_BUILD_DIR%?$(pwd)?g" --in-place /etc/apache2/sites-available/default
sudo service apache2 restart

echo "starting HHVM"

# Run HHVM
echo "PIDFILE=\"/tmp/hhvm.pid\"" >> /etc/default/hhvm
hhvm -m daemon -vServer.Type=fastcgi -vServer.Port=9090 -vServer.FixPathInfo=true -vLog.Level=verbose -vLog.UseLogFile=true -vLog.File=/tmp/hhvm.log -vLog.AlwaysLogUnhandledExceptions=true
