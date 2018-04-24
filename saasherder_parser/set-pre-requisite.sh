#!/bin/bash
git clone https://github.com/openshiftio/saasherder
cd saasherder && python setup.py install && cd ../
git clone https://github.com/openshiftio/saas-openshiftio
git clone https://github.com/openshiftio/saas-analytics
git clone https://github.com/openshiftio/saas-launchpad
git clone https://github.com/openshiftio/saas-chat
