Bind9 DNSSEC keys management
############################

|licence| |codacy|

Since version 9.7, BIND9 added support for auto-dnssec. After initial configuration,
servers using auto-dnssec will automatically sign and re-sign zones at the appropriate time as
determined by key metadata. However, keys generation and rotation planning is left to the
DNS operator.

Since BIND9 9.9, BIND9 support inline signing. This means that the signature process in completely
transparent with regard to the DNS zone file.

This program purpose is to ease this initial configuration and automate key generation and rotation
planning while letting BIND9 signs zone and effectively rotate keys.

Once setup, it will automatically generate new ZSK and KSK as defined in its configuration and
sets keys metadata to allow BIND9 to do the rotation.

ZSK are rotate automatically. Then a KSK needs to be rotate, this program will wait for you to
publish the new KSK DS in the parent zone before planing the old KSK retirement.


.. contents:: Table of Contents


Dependencies
============

This program depends of the following programs

* python 3
* dnspython3
* Bind utils: dnssec-settime, dnssec-dsfromkey, dnssec-keygen and rndc

Here there is a table with the name of packages providing these dependencies on Debian 9
Centos 7.

+-------------------+----------+
| Debian 9          | Centos 7 |
+===================+==========+
| python3           | python34 |
+-------------------+----------+
| python3-dnspython | N/A      |
+-------------------+----------+
| bind9             | bind     |
+-------------------+----------+
| bind9utils        | N/A      |
+-------------------+----------+

The binaries provided by ``bind9utils`` on Debian 9 are included in ``bind`` on Centos 7.
``dnspython`` for python 3 is not packaged for Centos 7. You can either retrieve it from
https://pypi.org/project/dnspython3/ or install ip with ``pip3`` or let it uninstalled.
``dnssec_keys_management.py`` will still works without it, but some handy but optional
functionalities will be unavailable.


Installation
============

Just download and copy ``dnssec_keys_management.py`` on the same server as your BIND9 master.

Copy ``dnssec_keys_management.ini.sample`` into ``dnssec_keys_management.ini`` and place it in one
of the following locations:

* In the same directory as ``dnssec_keys_management.py``
* ``/etc/dnssec_keys_management.ini``
* In ``~/.config/dnssec_keys_management.ini`` where ``~`` is the home of the user what will launch
  ``dnssec_keys_management.py``.

Edit ``dnssec_keys_management.ini`` and edit the ``base_directory`` settings.
``dnssec_keys_management.py`` will store dnssec keys in that directory. Bind9 must be able to
access that directory.
You can let the other parameters as is or change it. Be sur you understand the implication before
changing ``interval``.

Finally, setup a cron task to run ``dnssec_keys_management.py --cron`` at least once a day:

.. code-block::

    0 0 * * * root /usr/local/bind-dnssec/dnssec_keys_management.py -c

The cron will handle new key generation and rotation planing. It will output to stderr messages
when you need to take actions, this will be sent by mail by cron.
Be sur cron is configured so you can receive mail from it.

Usages
======

Signing a new zone
------------------

#. We suppose here you already have an unsigned DNS zone setup in BIND9. We also suppose you let
   the ``base_directory`` settings to its default value ``/etc/bind/keys`` and the zone SOA expire
   time is one week.

   .. code-block::

       zone "example.com" in {
            type master;
            notify yes;
            file "/var/lib/bind/zones/db.example.com";
            allow-query { any; };
       };

#. First, lets create the initials keys for the zone:

   .. code-block::

       # ./dnssec_keys_management.py --make example.com

#. Then edit BIND config to enable zone signature:

   .. code-block::

       zone "example.com" in {
            type master;
            notify yes;
            file "/var/lib/bind/zones/db.example.com";
            allow-query { any; };
            key-directory "/etc/bind/keys/example.com";
            inline-signing yes;
            auto-dnssec maintain;
            // resign once a day, signatures are valid 4 weeks (4*SOA expire time)
            sig-validity-interval 28 27;
       };

   ``sig-validity-interval`` define how long signatures will be valid in days (first parameters).
   You should put 4*SOA expire time in here. The second define how long before the signatures
   expire the zone should be resign.
   I personally like my zones to have a new signatures every days, so I have time if something breaks
   to fix it. 28 - 1 equals 27, so I set the second parameters to 27.
   It is very important that the signature interval (1 day here) is lower than the ``interval``
   parameter in ``dnssec_keys_management.ini``.

#. After that, you must publish the zone KSK DS into the parent zone. Depending of your registrar, it
   will ask you for a DS record or the KSK public key.

   To generate DS records just use the command:

   .. code-block::

       # ./dnssec_keys_management.py --ds all example.com
       example.com. IN DS 58525 8 1 32B5BA350B9AB7CF1B2B2E66379A7BF337C6AB09
       example.com. IN DS 58525 8 2 BAFECE6ABD12DC33F8001770EA6507DCC9476E6B504FF8E3FC2FD7DD28950666
       dnssec-dsfromkey: fatal: unknown algorithm GOST
       example.com. IN DS 58525 8 4 8BB9438C58CD3287A4B76FD28C766EE06566EE63BD5D5E17F4492224923A2F99A1C73F069A7E65B2D00B0442A43BDE

   The GOST algorithm is not available on my server leading to the error here. It can just be ignored,
   publish the successfully generated DS in the parent zone.

   To fetch the KSK public key, use the command:

   .. code-block::

       # ./dnssec_keys_management.py --key ksk example.com
       ; This is a key-signing key, keyid 58525, for example.com.
       ; Created: 20180506123910 (Sun May  6 14:39:10 2018)
       ; Publish: 20180506123910 (Sun May  6 14:39:10 2018)
       ; Activate: 20180506123910 (Sun May  6 14:39:10 2018)
       example.com. IN DNSKEY 257 3 8 AwEAAaMDcXZfm5S0MS4fhUcUfZCu1v2pRGi7bGZD1jHF36X2/eaARgxf xFFySSon3gM9wZdTBlYwZUpATLQTVCAj8REwvn7cJyNptxt67IgHluUW 4j7+kjB2m686+o2KIrupapVnOvDdet2oMqCVOsQv+g/Tt2N2ycxfEPm9 edySl67HtsNCIA6NnxTywL8ihwcDEqqNW2SVhMK8O49ti1XcIYPsE4ep jRwCNOFqOcbygAeMxER5pxTgVxndzpteXkM/jTMJB2SzsOcGg4yo3s43 bf8WjqFKND6tpXZQRRbkSD0/GGJBdUSmvrippF1RpBmWrvIUKHOoMytc GBIp2n8=

#. Finally, enable nsec3 so your zone cannot be crawled:

   .. code-block::

       # ./dnssec_keys_management.py --nsec3 example.com
       Enabling nsec3 for zone example.com:
       request queued



KSK rollover
------------

By default, ``dnssec_keys_management.py`` will generate a new KSK once a year and publish it into
the DNS zone. In order to activate it and plan the old KSK removal, you need to take actions:
the new KSK DS must be publish into the parent zone.
``dnssec_keys_management.py --cron`` will output
``New KSK needs DS seen and/or old KSK needs inactivate/remove for zone example.com`` every day
until you inform it you have publish DS in the parent zone.

You can display the keys actualy present with the following commands:

.. code-block::

    # ./dnssec_keys_management.py --key-table default example.com
    +-----------+-+-----+-------------------+-------------------+-------------------+-------------------+
    | Zone name |T|KeyId|      Publish      |     Activate      |     Inactive      |      Delete       |
    +-----------+-+-----+-------------------+-------------------+-------------------+-------------------+
    |example.com|K|58525|2017-05-06 12:39:10|2017-05-06 12:39:10|        N/A        |        N/A        |
    |example.com|K|48010|2018-04-04 12:54:24|        N/A        |        N/A        |        N/A        |
    |example.com|Z|38943|2018-05-06 12:39:10|2018-05-06 12:39:10|2018-06-05 12:39:10|2018-06-28 12:39:10|
    |example.com|Z| 8409|2018-05-13 12:39:10|2018-06-05 12:39:10|        N/A        |        N/A        |
    +-----------+-+-----+-------------------+-------------------+-------------------+-------------------+

You can see that the KSK 48010 needs to be activated. To do so, publish its DS into the parent zone.
Do not remove previous DS yet.

.. code-block::

    # ./dnssec_keys_management.py --ds all  example.com 2>/dev/null
    example.com. IN DS 58525 8 1 32B5BA350B9AB7CF1B2B2E66379A7BF337C6AB09
    example.com. IN DS 58525 8 2 BAFECE6ABD12DC33F8001770EA6507DCC9476E6B504FF8E3FC2FD7DD28950666
    example.com. IN DS 58525 8 4 8BB9438C58CD3287A4B76FD28C766EE06566EE63BD5D5E17F4492224923A2F99A1C73F069A7E65B2D00B0442A43BDE37
    example.com. IN DS 48010 8 1 15E9FBDDEF7D91D6AEE353AE3E0209187C21BEF8
    example.com. IN DS 48010 8 2 C5E23F94FF50A0D09CE76622CB150ED3209F22C6699626492DAFB72515B434D9
    example.com. IN DS 48010 8 4 D9B3F0D8019AFC4BFDB7338F92C3D03EF08CDB6DA596887D8987E3739F9AA90E45CAB22AFB436B419880E7802CD0CE87

    # ./dnssec_keys_management.py --key ksk  example.com
    ; This is a key-signing key, keyid 58525, for example.com.
    ; Created: 20180506123910 (Sun May  6 14:39:10 2018)
    ; Publish: 20180506123910 (Sun May  6 14:39:10 2018)
    ; Activate: 20180506123910 (Sun May  6 14:39:10 2018)
    example.com. IN DNSKEY 257 3 8 AwEAAaMDcXZfm5S0MS4fhUcUfZCu1v2pRGi7bGZD1jHF36X2/eaARgxf xFFySSon3gM9wZdTBlYwZUpATLQTVCAj8REwvn7cJyNptxt67IgHluUW 4j7+kjB2m686+o2KIrupapVnOvDdet2oMqCVOsQv+g/Tt2N2ycxfEPm9 edySl67HtsNCIA6NnxTywL8ihwcDEqqNW2SVhMK8O49ti1XcIYPsE4ep jRwCNOFqOcbygAeMxER5pxTgVxndzpteXkM/jTMJB2SzsOcGg4yo3s43 bf8WjqFKND6tpXZQRRbkSD0/GGJBdUSmvrippF1RpBmWrvIUKHOoMytc GBIp2n8=

    ; This is a key-signing key, keyid 48010, for example.com.
    ; Created: 20180506125424 (Sun May  6 14:54:24 2018)
    ; Publish: 20180506125424 (Sun May  6 14:54:24 2018)
    example.com. IN DNSKEY 257 3 8 AwEAAe+YUTscIDDZHdJ36lE/3rGXcDwfs3DqqIoLNfhpA5Hjne9Os7sR B2ekTf4ZfSVTDLApBcZvXeV1/w29VnssJCWztG7BraJ0khcF23vmHzNk 2TGKYePD3rKsJlGCOz/whJckbaDt2dKx5BAvSeBucWm0JhFTCy7UwFyO V1LamXm8l9m3a9Eo3KQzuOpGkHed7WikA60EYSi1lYNXkLOLseMHP7FS NBfkPrX0kWTm0V1R6txIfeSBPBoEn5rK2S756zV3TyzVWqbOgfKXdB+X 2EAiRow7Rym6B+8xrgk3uyfFzxsaQnRd8t+I9GqQi/u+N5YUbD+Zfj0p 9dm5EQc=

Keys are always sorted from the oldest to the newest, indeed, the key 48010 is last.

Once you have publish DS into the parent zone, you can check that the DS is available with the
command ``./dnssec_keys_management.py --ds-check 48010 example.com``.

In case of errors, you will have this kind of output:

.. code-block::

    # ./dnssec_keys_management.py --ds-check 48010 example.com
    DS not found on the following parent servers:
     * d.gtld-servers.net. (192.31.80.30)
     * k.gtld-servers.net. (192.52.178.30)
     * b.gtld-servers.net. (192.33.14.30)
     * a.gtld-servers.net. (192.5.6.30)
     * l.gtld-servers.net. (192.41.162.30)
     * c.gtld-servers.net. (192.26.92.30)
     * m.gtld-servers.net. (192.55.83.30)
     * g.gtld-servers.net. (192.42.93.30)
     * j.gtld-servers.net. (192.48.79.30)
     * h.gtld-servers.net. (192.54.112.30)
     * i.gtld-servers.net. (192.43.172.30)
     * f.gtld-servers.net. (192.35.51.30)
     * e.gtld-servers.net. (192.12.94.30)
    Found keys are 31406, 31589, 43547

If every things is ok, the command will output:

.. code-block::

    # ./dnssec_keys_management.py --ds-check 48010 example.com
    DS for key 48010 found on all parent servers

Only then, you can inform ``dnssec_keys_management.py`` the DS are successfully published and
the key rotation can be perform with to command:
``./dnssec_keys_management.py --ds-seen 48010 example.com``.

.. code-block::

    # ./dnssec_keys_management.py --ds-seen 48010 example.com
    DS for key 48010 found on all parent servers

This will schedule the new KSK to be activated in ``interval`` and the old one to be removed from
the zone in ``2 * interval``. Wait for the old KSK removal form the zone to remove corresponding DS
from the parent zone.

You can use the excellent web site http://dnsviz.net to analyse dnssec for your zone. For instance
http://dnsviz.net/d/example.com/dnssec/.

Errors
======

Python dnspython module not available
-------------------------------------

The two commands ``dnssec_keys_management.py --ds-seen`` and
``dnssec_keys_management.py --ds-check`` check the DNS parent server for the zone DS. In order
to do so, the python library ``pythondns3`` is needed. Without it you will get the error:
``Python dnspython module not available, check failed``.

Without ``pythondns3`` you cannot use ``dnssec_keys_management.py --ds-check``.
``dnssec_keys_management.py --ds-seen`` perform the same checks as ``--ds-check`` before
scheduling KSK rotation, but you can skip the tests with the ``--no-check`` options.

Beware that with the ``--no-check`` keys will be rotate whether the DS are published in the
parent zone or not. Use it very carefully.



.. |licence| image:: https://badges.genua.fr/github/license/nitmir/bind-dnssec.svg
    :target: https://www.gnu.org/licenses/gpl-3.0.html

.. |codacy| image:: https://badges.genua.fr/codacy/grade/a262f8980c514d85951f89f4e7b47916/master.svg
    :target: https://app.codacy.com/app/valentin-samir/bind-dnssec