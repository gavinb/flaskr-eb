Flaskr-eb README
================

This sample code takes Flaskr, the simple example in the Flask
documentation, and turns it into an app that runs on Amazon's
Elastic Beanstalk.  This represents just about the most basic
starter app you need to run on the scalable EC2 infrastructure.

Changes
-------

The original database was Sqlite3.  This was removed and modified
to use DynamoDB.  The first-time setup should be done by opening
the /initdb URL.

Additions
---------

The `.ebextensions` folder contains Python-specific settings,
including the WSGI configuration and the environment variables
which are used to supply the AWS Identity Key and Secret Key
needed to use the APIs.  Make sure you update these values
before deploying the system.

Requirements
------------

To run this package, you will need the 'eb' tool from the
AWS-ElasticBeanstalk-CLI package.

Credits
-------

Original Flaskr code written by Armin Roacher
Copyright (c) 2010, BSD-licensed.


  -- Gavin Baker
     gavinb@antonym.org
