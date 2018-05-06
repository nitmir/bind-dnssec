#!/usr/bin/env python3
# -*- coding: utf8 -*-
# pylint: disable=locally-disabled,invalid-name
"""The script allow to manage bind dnssec keys (generate new keys and handle key rollover)."""
import os
import sys
import binascii
import datetime
import subprocess
import argparse
import pwd
import collections
import configparser
from functools import total_ordering
try:
    import dns.resolver
except ImportError:
    dns = None


class Config(object):  # pylint: disable=locally-disabled,too-many-instance-attributes
    """Holds configuration for dnssec keys management."""

    # Directory where dnssec keys will be stored
    BASE = "/etc/bind/keys"

    # Interval between 2 operations on the dns keys.
    # For example if you have KEY1 enabled, KEY2 is published INTERVAL before disabling KEY1. KEY1
    # is disabled when KEY2 is activated, KEY1 is deleted INTERVAL after being disabled.
    # INTERVAL MUST be greater than the longest TTL DS records can have.
    # INTERVAL MUST also be higher than the bind signature interval (default 22.5 days)
    # This partially depends of the parent zone configuration and you do not necessarily have
    # control over it.
    INTERVAL = datetime.timedelta(days=23)

    # Time after which a ZSK is replaced by a new ZSK.
    # Generation of ZSK and activation / deactivation / deletion is managed automatically as long as
    # dnssec_keys_management.py -c is called at least once a day.
    ZSK_VALIDITY = datetime.timedelta(days=30)  # ~1 month

    # Time after which a new KSK is generated and published for the zone (and activated after
    # INTERVAL). The old key is removed only INTERVAL after the new key was
    # dnssec_keys_management.py --ds-seen.
    # This usually requires a manual operation with the registrar (publish DS of the new key
    # in the parent zone). dnssec_keys_management.py -c displays a message as long as --ds-seen
    # needs to be called and has not yet be called
    KSK_VALIDITY = datetime.timedelta(days=366)  # ~1 year

    # Algorithm used to generate new keys. Only the first created KSK and ZSK of a zone will use
    # this algorithm. Any renewing key will use the exact same parameters (name, algorithm, size,
    # and type) as the renewed key.
    ALGORITHM = "RSASHA256"

    SUPPORTED_ALGORITHMS = {
        8: "RSASHA256",
        10: "RSASHA512",
        12: "ECCGOST",
        13: "ECDSAP256SHA256",
        14: "ECDSAP384SHA384",
    }

    DS_ALGORITHMS = {
        1: 'SHA-1',
        2: 'SHA-256',
        3: 'GOST',
        4: 'SHA-384',
    }

    # Size of the created KSK. Only the first created KSK of a zone will use this size.
    # Any renewing key will use the exact same parameters (name, algorithm, size, and type)
    # as the renewed key
    KSK_SIZE = "2048"

    # Size of the created ZSK. Only the first created ZSK of a zone will use this size.
    # Any renewing key will use the exact same parameters (name, algorithm, size, and type)
    # as the renewed key.
    ZSK_SIZE = "1024"

    # path to the dnssec-settime binary
    DNSSEC_SETTIME = "/usr/sbin/dnssec-settime"
    # path to the dnssec-dsfromkey binary
    DNSSEC_DSFROMKEY = "/usr/sbin/dnssec-dsfromkey"
    # path to the dnssec-keygen binary
    DNSSEC_KEYGEN = "/usr/sbin/dnssec-keygen"
    # path to the rndc binary
    RNDC = "/usr/sbin/rndc"

    # Possible config paths. The first path whose exists will be used as configuration
    config_paths = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "config.ini")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "dnssec_keys_management.ini")),
        os.path.abspath(os.path.expanduser("~/.config/dnssec_keys_management.ini")),
        "/etc/dnssec_keys_management.ini",
    ]

    def show(self):
        """Display config."""
        print("Key base path: %s" % self.BASE)
        print("Interval between two operation: %s" % self.INTERVAL)
        print("ZSK validity duration: %s" % self.ZSK_VALIDITY)
        print("KSK validity duration: %s" % self.KSK_VALIDITY)
        print("DNSKEY algorithm: %s" % self.ALGORITHM)
        print("KSK size: %s" % self.KSK_SIZE)
        print("ZSK size: %s" % self.ZSK_SIZE)
        print("")
        print("Path to dnssec-settime: %s" % self.DNSSEC_SETTIME)
        print("Path to dnssec-dsfromkey: %s" % self.DNSSEC_DSFROMKEY)
        print("Path to dnssec-keygen: %s" % self.DNSSEC_KEYGEN)
        print("Path to rndc: %s" % self. RNDC)

    def __init__(self, path=None):
        """Parse the config file and update attributes accordingly."""
        if path is None:
            for path in self.config_paths:
                if os.path.isfile(path):
                    self._parse(path)
                    break
        else:
            self._parse(path)
        self.check_paths()

    def _parse(self, config_file):
        config_parser = configparser.ConfigParser()
        config_parser.read(config_file)
        self._parse_dnssec_section(config_parser)
        self._parse_path_section(config_parser)

    def _parse_dnssec_section(self, config_parser):
        if config_parser.has_section("dnssec"):
            if config_parser.has_option("dnssec", "base_directory"):
                self.BASE = config_parser.get("dnssec", "base_directory")
            if config_parser.has_option("dnssec", "interval"):
                try:
                    self.INTERVAL = datetime.timedelta(
                        days=config_parser.getfloat("dnssec", "interval")
                    )
                except ValueError:
                    print(
                        "Unable to convert the config parameter 'interval' to a float",
                        file=sys.stderr
                    )
            if config_parser.has_option("dnssec", "zsk_validity"):
                try:
                    self.ZSK_VALIDITY = datetime.timedelta(
                        days=config_parser.getfloat("dnssec", "zsk_validity")
                    )
                except ValueError:
                    print(
                        "Unable to convert the config parameter 'zsk_validity' to a float",
                        file=sys.stderr
                    )
            if config_parser.has_option("dnssec", "ksk_validity"):
                try:
                    self.KSK_VALIDITY = datetime.timedelta(
                        days=config_parser.getfloat("dnssec", "ksk_validity")
                    )
                except ValueError:
                    print(
                        "Unable to convert the config parameter 'ksk_validity' to a float",
                        file=sys.stderr
                    )
            if config_parser.has_option("dnssec", "algorithm"):
                self.ALGORITHM = config_parser.get("dnssec", "algorithm")
                if self.ALGORITHM not in self.SUPPORTED_ALGORITHMS.values():
                    raise ValueError(
                        "Invalid algorithm %s."
                        "Supported algorithms are %s" % (
                            self.ALGORITHM, ", ".join(self.SUPPORTED_ALGORITHMS.values())
                        )
                    )
            if config_parser.has_option("dnssec", "zsk_size"):
                self.ZSK_SIZE = config_parser.get("dnssec", "zsk_size")

            if config_parser.has_option("dnssec", "ksk_size"):
                self.KSK_SIZE = config_parser.get("dnssec", "ksk_size")

    def _parse_path_section(self, config_parser):
        if config_parser.has_section("path"):
            if config_parser.has_option("path", "dnssec_settime"):
                self.DNSSEC_SETTIME = config_parser.get("path", "dnssec_settime")
            if config_parser.has_option("path", "dnssec_dsfromkey"):
                self.DNSSEC_DSFROMKEY = config_parser.get("path", "dnssec_dsfromkey")
            if config_parser.has_option("path", "dnssec_keygen"):
                self.DNSSEC_KEYGEN = config_parser.get("path", "dnssec_keygen")
            if config_parser.has_option("path", "rndc"):
                self.RNDC = config_parser.get("path", "rndc")

    def check_paths(self):
        """Check config path to needed binaries."""
        for path in [self.DNSSEC_SETTIME, self.DNSSEC_DSFROMKEY, self.DNSSEC_KEYGEN, self.RNDC]:
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                raise ValueError(
                    "%s not found or not executable. Is bind9utils installed ?\n" % path
                )


def get_zones(zone_names=None, config=None):
    """
    Return a list of :class:`Zone` instances.

    :param Config config: A :class:`Config` instance
    :param list zone_names: If provider return :class:`Zone` instance for the zone provided.
        Otherwise, return :class:`Zone` instance for all founded zones
    """
    if config is None:
        config = Config()
    zones = []
    if zone_names is None:
        for f in os.listdir(config.BASE):
            if os.path.isdir(os.path.join(config.BASE, f)) and not f.startswith('.'):
                zones.append(Zone(f, config=config))
    else:
        for name in zone_names:
            zones.append(Zone(name, config=config))
    return zones


def bind_chown(path):
    """Give the files to the bind user and sets the modes in a relevant way."""
    try:
        bind_uid = pwd.getpwnam('bind').pw_uid
        os.chown(path, bind_uid, -1)
        for root, dirs, files in os.walk(path):
            for dir_ in dirs:
                os.chown(os.path.join(root, dir_), bind_uid, -1)
            for file_ in files:
                os.chown(os.path.join(root, file_), bind_uid, -1)
    except KeyError:
        print("User bind not found, failing to give keys ownership to bind", file=sys.stderr)


def bind_reload(config=None):
    """Reload bind config."""
    if config is None:
        config = Config()
    cmd = [config.RNDC, "reload"]
    p = subprocess.Popen(cmd)
    p.wait()


class Zone(object):
    """Allow to manage dnssec keys for a dns zone."""

    ZSK = None
    KSK = None
    name = None
    _path = None
    _cfg = None

    def __str__(self):
        """Zone name."""
        return self.name

    def __repr__(self):
        """Zone representation."""
        return "Zone %s" % self.name

    @classmethod
    def create(cls, name, config=None):
        """Create the zone keys storage directory and return a :class:`Zone` instance."""
        if config is None:
            config = Config()
        path = os.path.join(config.BASE, name)
        if os.path.isdir(path):
            raise ValueError("%s exists" % path)
        os.mkdir(path)
        bind_chown(path)
        return cls(name, config=config)

    def nsec3(self, salt=None):
        """Enable NSEC3 for the zone ``zone``."""
        if salt is None:
            salt = binascii.hexlify(os.urandom(24)).decode()
        cmd = [self._cfg.RNDC, "signing", "-nsec3param", "1", "0", "10", salt, self.name]
        print("Enabling nsec3 for zone %s: " % self.name, file=sys.stdout)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        out = p.communicate()[0].decode()
        print(out, file=sys.stdout)
        p.wait()

    def do_zsk(self):
        """Perform daily routine on ZSK keys (generate new keys, delete old ones...)."""
        last_activate_zsk = None
        for zsk in self.ZSK:
            if zsk.is_activate and not zsk.is_inactive:
                zsk.inactive = zsk.activate + self._cfg.ZSK_VALIDITY
                zsk.delete = zsk.inactive + self._cfg.INTERVAL
                last_activate_zsk = zsk
        now = datetime.datetime.utcnow()
        zsk = self.ZSK[-1]
        if zsk.is_activate:
            zsk.inactive = max(zsk.inactive, now + self._cfg.INTERVAL)
            zsk.delete = zsk.inactive + self._cfg.INTERVAL
            zsk.gen_successor()
            bind_reload(self._cfg)
        elif last_activate_zsk is not None:
            zsk.activate = last_activate_zsk.inactive
        else:
            raise RuntimeError("No ZSK is activated, this should never happen")

    def do_ksk(self):
        """Perform daily routine on KSK keys (generate new keys...)."""
        ksk = self.KSK[-1]
        if ksk.need_renew:
            now = datetime.datetime.utcnow()
            new_ksk = Key.create("KSK", self.name, config=self._cfg)
            # do not activate the new key until ds-seen
            new_ksk.activate = None
            new_ksk.publish = now
            bind_reload(self._cfg)
        active_ksk = [key for key in self.KSK if key.is_publish and key.delete is None]
        if len(active_ksk) >= 2:
            print(
                (
                    "New KSK needs DS seen and/or old KSK needs "
                    "inactivate/remove for zone %s"
                ) % self.name,
                file=sys.stderr
            )

    def _get_ds_from_parents(self):
        parent = '.'.join(self.name.split('.')[1:])
        if not parent:
            parent = '.'
        nameservers = {
            ns.to_text(): [ip.to_text() for ip in dns.resolver.query(ns.to_text())]
            for ns in dns.resolver.query(parent, 'NS')
        }

        ds = {}
        for ns, ns_ips in nameservers.items():
            for ns_ip in ns_ips:
                r = dns.resolver.Resolver()
                r.nameservers = [ns_ip]
                ds[(ns, ns_ip)] = list(r.query(self.name, 'DS'))
        return ds

    def ds_check(self, keyid, key=None):
        """
        Check if a DS with ``keyid`` is present in the parent zone.

        :param int keyid: A key id
        :param Key key: A :class:`Key` instance
        """
        if dns is None:
            print("Python dnspython module not available, check failed", file=sys.stderr)
            return False
        if key is None:
            key = self._get_key_by_id(keyid)[0]
        if key is not None:
            ds_records = self._get_ds_from_parents()
            missing = collections.defaultdict(list)
            bad_digest = collections.defaultdict(list)
            founds = {}
            for (ns, ns_ip), ds in ds_records.items():
                keyids = set()
                for d in ds:
                    if d.key_tag == keyid:
                        if key is None:
                            break
                        algorithm = self._cfg.DS_ALGORITHMS[d.digest_type]
                        if d.digest == key.ds_digest(algorithm):
                            break
                        else:
                            bad_digest[ns].append(ns_ip)
                            break
                    keyids.add(d.key_tag)
                else:
                    missing[ns].append(ns_ip)
                    founds[(ns, ns_ip)] = keyids
            if missing or bad_digest:
                if missing:
                    print("DS not found on the following parent servers:", file=sys.stderr)
                    keyids = None
                    for ns, ns_ips in missing.items():
                        print(" * %s (%s)" % (ns, ', '.join(ns_ips)), file=sys.stderr)
                        for ip in ns_ips:
                            if keyids is None:
                                keyids = founds[(ns, ip)]
                            else:
                                keyids &= founds[(ns, ip)]
                    keyids_list = list(keyids)
                    keyids_list.sort()
                    print(
                        "Found keys are %s" % ', '.join(str(id_) for id_ in keyids_list),
                        file=sys.stderr
                    )
                if bad_digest:
                    print(
                        "DS found but digest do not match on the following parent servers:",
                        file=sys.stderr
                    )
                    for ns, ns_ips in bad_digest.items():
                        print(" * %s (%s)" % (ns, ', '.join(ns_ips)), file=sys.stderr)
                return False
            else:
                print("DS for key %s found on all parent servers" % keyid)
                return True
        else:
            print("Key not found", file=sys.stderr)
            return False

    def _get_key_by_id(self, keyid):
        old_ksks = []
        for ksk in self.KSK:
            if ksk.keyid == keyid:
                seen_ksk = ksk
                break
            old_ksks.append(ksk)
        else:

            return None, []
        return seen_ksk, old_ksks

    def ds_seen(self, keyid, check=True):
        """Tell that the DS for the KSK ``keyid`` has been seen, programming KSK rotation."""
        seen_ksk, old_ksks = self._get_key_by_id(keyid)
        if seen_ksk is not None:
            if check:
                if not self.ds_check(keyid, key=seen_ksk):
                    print(
                        "You may use --no-check to bypass this check and force --ds-seen",
                        file=sys.stderr
                    )
                    return
            now = datetime.datetime.utcnow()
            if seen_ksk.activate is None:
                seen_ksk.activate = (now + self._cfg.INTERVAL)
            for ksk in old_ksks:
                print(" * program key %s removal" % ksk.keyid)
                # set inactive in at least INTERVAL
                ksk.inactive = seen_ksk.activate
                # delete INTERVAL after being inactive
                ksk.delete = ksk.inactive + self._cfg.INTERVAL
            bind_reload(self._cfg)
        else:
            print("Key not found", file=sys.stderr)

    def remove_deleted(self):
        """Move deleted keys to the deleted folder."""
        deleted_path = os.path.join(self._path, "deleted")
        try:
            os.mkdir(deleted_path)
        except OSError as error:
            if error.errno != 17:  # File exists
                raise
        now = datetime.datetime.utcnow()
        for key in self.ZSK + self.KSK:
            key.remove_deleted(deleted_path, now=now)

    def ds(self, algorithm=None):
        """Display the DS of the KSK of the zone."""
        for ksk in self.KSK:
            if algorithm == 'all':
                for algo in self._cfg.DS_ALGORITHMS.values():
                    sys.stdout.write(ksk.ds(algorithm=algo))
            else:
                sys.stdout.write(ksk.ds(algorithm=algorithm))

    def key(self, show_ksk=False, show_zsk=False):
        """Display the public keys of the KSK and/or ZSK."""
        if show_ksk:
            for ksk in self.KSK:
                print(ksk)
        if show_zsk:
            for zsk in self.ZSK:
                print(zsk)

    @staticmethod
    def _key_table_format(znl, show_all=False):
        format_string = "|{!s:^%d}|{}|{!s:>5}|" % znl
        if show_all:
            format_string += "{algorithm!s:^19}|"
            format_string += "{created!s:^19}|"
        format_string += "{!s:^19}|{!s:^19}|{!s:^19}|{!s:^19}|"
        separator = ("+" + "-" * znl + "+-+-----+" + ("-" * 19 + "+") * (6 if show_all else 4))
        return format_string, separator

    @classmethod
    def _key_table_header(cls, znl, show_all=False):
        (format_string, separator) = cls._key_table_format(znl, show_all)
        print(separator)
        print(format_string.format(
            "Zone name", "T", "KeyId", "Publish", "Activate",
            "Inactive", "Delete", created="Created", algorithm="Algorithm"
        ))
        print(separator)

    def _key_table_body(self, znl, show_all=False):
        format_string = self._key_table_format(znl, show_all)[0]
        for ksk in self.KSK:
            print(format_string.format(
                ksk.zone_name,
                "K",
                ksk.keyid,
                ksk.publish or "N/A",
                ksk.activate or "N/A",
                ksk.inactive or "N/A",
                ksk.delete or "N/A",
                created=ksk.created or "N/A",
                algorithm=ksk.algorithm or "N/A",
            ))
        for zsk in self.ZSK:
            print(format_string.format(
                zsk.zone_name,
                "Z",
                zsk.keyid,
                zsk.publish or "N/A",
                zsk.activate or "N/A",
                zsk.inactive or "N/A",
                zsk.delete or "N/A",
                created=zsk.created or "N/A",
                algorithm=zsk.algorithm or "N/A",
            ))

    @classmethod
    def _key_table_footer(cls, znl, show_all=False):
        separator = cls._key_table_format(znl, show_all)[1]
        print(separator)

    @classmethod
    def key_table(cls, zones, show_all=False):
        """Show meta data for the zone keys in a table."""
        znl = max(9, *[len(zone.name) for zone in zones])
        cls._key_table_header(znl, show_all)
        for zone in zones:
            # noinspection PyProtectedMember
            zone._key_table_body(znl, show_all)  # pylint: disable=locally-disabled,protected-access
        cls._key_table_footer(znl, show_all)

    def __init__(self, name, config=None):
        """Read every keys attached to the zone. If not keys is found, generate new ones."""
        if config is None:
            self._cfg = Config()
        else:
            self._cfg = config
        path = os.path.join(self._cfg.BASE, name)
        if not os.path.isdir(path):
            raise ValueError("%s is not a directory" % path)
        self.name = name
        self._path = path
        self.ZSK = []
        self.KSK = []
        for file_ in os.listdir(path):
            file_path = os.path.join(path, file_)
            if os.path.isfile(file_path) and file_path.endswith(".private"):
                try:
                    key = Key(file_path, config=self._cfg)
                    if key.type == "ZSK":
                        self.ZSK.append(key)
                    elif key.type == "KSK":
                        self.KSK.append(key)
                    else:
                        raise RuntimeError("impossible")
                except ValueError as error:
                    print("%s" % error, file=sys.stderr)
        self.ZSK.sort()
        self.KSK.sort()
        if not self.ZSK:
            self.ZSK.append(Key.create("ZSK", name, config=self._cfg))
            self.do_zsk()
        if not self.KSK:
            self.KSK.append(Key.create("KSK", name, config=self._cfg))
            self.do_ksk()


@total_ordering
class Key(object):
    """Allow to manage a specific dnssec key."""

    # pylint: disable=locally-disabled,too-many-instance-attributes
    _created = None
    _publish = None
    _activate = None
    _inactive = None
    _delete = None
    _data = None
    _path = None
    _cfg = None
    type = None
    keyid = None
    flag = None
    zone_name = None
    algorithm = None

    def __str__(self):
        """Verbatim content of the key file."""
        return self._data

    def __repr__(self):
        """Path to the key file."""
        r = os.path.basename(self._path)
        return r

    @staticmethod
    def _date_from_key(date):
        if date is not None:
            return datetime.datetime.strptime(date, "%Y%m%d%H%M%S")

    @staticmethod
    def _date_to_key(date):
        if date is None:
            return 'none'
        else:
            return datetime.datetime.strftime(date, "%Y%m%d%H%M%S")

    def _date_check(self, value, needed_date, value_name, needed_date_name):
        if value is not None:
            if needed_date is None or value < needed_date:
                raise RuntimeError(
                    "Cannot set %s date before %s date on key %s on zone %s" % (
                        value_name,
                        needed_date_name,
                        self.keyid,
                        self.zone_name
                    )
                )

    def _date_check2(self, value, needed_date, value_name, needed_date_name):
        msg = "Cannot set %s date after %s date on key %s on zone %s" % (
            value_name,
            needed_date_name,
            self.keyid,
            self.zone_name
        )
        if value is None and needed_date is not None:
            raise RuntimeError(msg)
        elif value is not None and needed_date is not None:
            if value > needed_date:
                raise RuntimeError(msg)

    @classmethod
    def create(cls, typ, name, options=None, config=None):
        """
        Create a new dnssec key.

        :param str typ: The type of the key to create. Most be 'KSK' or 'ZSK'.
        :param str name: The zone name for which we are creating the key.
        :param list options: An optional list of extra parameters to pass to DNSSEC_KEYGEN binary.
        :param Config config: A :class:`Config` object
        """
        if config is None:
            config = Config()
        if options is None:
            options = []
        path = os.path.join(config.BASE, name)
        cmd = [config.DNSSEC_KEYGEN, "-a", config.ALGORITHM]
        if typ == "KSK":
            cmd.extend(["-b", config.KSK_SIZE, "-f", "KSK"])
        elif typ == "ZSK":
            cmd.extend(["-b", config.ZSK_SIZE])
        else:
            raise ValueError("typ must be KSK or ZSK")
        cmd.extend(options)
        cmd.extend(["-K", path, name])
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        p.wait()
        if p.returncode != 0:
            raise ValueError("The key creation has failed")
        keyname = p.communicate()[0].strip().decode()
        bind_chown(path)
        return cls(os.path.join(path, "%s.private" % keyname), config=config)

    def gen_successor(self):
        """
        Create a new key which is an explicit successor to the current key.

        The name, algorithm, size, and type of the key will be set to match the existing key.
        The activation date of the new key will be set to the inactivation date of the existing one.
        The publication date will be set to the activation date minus the pre-publication interval.
        """
        cmd = [
            self._cfg.DNSSEC_KEYGEN, "-i", str(int(self._cfg.INTERVAL.total_seconds())),
            "-S", self._path, "-K", os.path.dirname(self._path)
        ]
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        err = p.communicate()[1].decode()
        if p.returncode != 0:
            raise ValueError("err %s: %s" % (p.returncode, err))
        if err:
            print(err, file=sys.stderr)
        bind_chown(os.path.dirname(self._path))

    def settime(self, flag, date):
        """Set the time of the flag ``flag`` for the key to ``date``."""
        cmd = [
            self._cfg.DNSSEC_SETTIME,
            "-i", str(int(self._cfg.INTERVAL.total_seconds())),
            "-%s" % flag, date, self._path
        ]
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        err = p.communicate()[1].decode()
        if p.returncode != 0:
            raise ValueError("err %s: %s" % (p.returncode, err))
        if err:
            print("%s" % err, file=sys.stderr)

    @property
    def created(self):
        """Date of creation of the key."""
        if self._created is not None:
            return self._date_from_key(self._created)

    @property
    def publish(self):
        """Date of publication of the key."""
        if self._publish is not None:
            return self._date_from_key(self._publish)

    @publish.setter
    def publish(self, value):
        self._date_check(value, self.created, "publish", "created")
        self._date_check2(value, self.activate, "publish", "activate")
        date = self._date_to_key(value)
        if date != self._publish:
            self.settime('P', date)
            self._publish = date
            with open(self._path, 'r') as f:
                self._data = f.read()

    @property
    def activate(self):
        """Date of activation of the key."""
        if self._activate is not None:
            return self._date_from_key(self._activate)

    @activate.setter
    def activate(self, value):
        self._date_check(value, self.publish, "active", "publish")
        self._date_check2(value, self.inactive, "activate", "inactive")
        date = self._date_to_key(value)
        if date != self._activate:
            self.settime('A', date)
            self._activate = date
            with open(self._path, 'r') as f:
                self._data = f.read()

    @property
    def inactive(self):
        """Date of inactivation of the key."""
        if self._inactive is not None:
            return self._date_from_key(self._inactive)

    @inactive.setter
    def inactive(self, value):
        self._date_check(value, self.activate, "inactive", "activate")
        self._date_check2(value, self.delete, "inactive", "delete")
        date = self._date_to_key(value)
        if date != self._inactive:
            self.settime('I', date)
            self._inactive = date
            with open(self._path, 'r') as f:
                self._data = f.read()

    @property
    def delete(self):
        """Date of deletion of the key."""
        if self._delete:
            return self._date_from_key(self._delete)

    @delete.setter
    def delete(self, value):
        self._date_check(value, self.inactive, "delete", "inactive")
        date = self._date_to_key(value)
        if date != self._delete:
            self.settime('D', date)
            self._delete = date
            with open(self._path, 'r') as f:
                self._data = f.read()

    @property
    def is_publish(self):
        """``True``if the key is published."""
        return self.publish is not None and self.publish <= datetime.datetime.utcnow()

    @property
    def is_activate(self):
        """``True``if the key is activated."""
        return self.activate is not None and self.activate <= datetime.datetime.utcnow()

    @property
    def is_inactive(self):
        """``True``if the key is inactivated."""
        return self.inactive is not None and self.inactive <= datetime.datetime.utcnow()

    @property
    def is_delete(self):
        """``True``if the key is deleted."""
        return self.delete is not None and self.delete <= datetime.datetime.utcnow()

    @property
    def need_renew(self):
        """``True`` is the current key needs to be renewed."""
        if self.type == "KSK":
            return (
                self.activate is not None and
                (
                    (self.activate + self._cfg.KSK_VALIDITY) <=
                    (datetime.datetime.utcnow() + self._cfg.INTERVAL)
                )
            )
        elif self.type == "ZSK":
            return (
                self.activate is not None and
                (
                    (self.activate + self._cfg.ZSK_VALIDITY) <=
                    (datetime.datetime.utcnow() + self._cfg.INTERVAL)
                )
            )
        else:
            raise RuntimeError("impossible")

    def ds(self, algorithm=None):
        """Display the DS of the key."""
        cmd = [self._cfg.DNSSEC_DSFROMKEY]
        if algorithm is not None:
            cmd.extend(['-a', algorithm])
        cmd.append(self._path)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        p.wait()
        if err:
            print(err.decode('utf-8').strip(), file=sys.stderr)
        return out.decode('utf-8')

    def ds_digest(self, algorithm):
        """Return raw DS digest of the key computed with ``algorithm``."""
        ds = self.ds(algorithm)
        return binascii.a2b_hex(ds.split()[-1])

    def remove_deleted(self, deleted_path, now=None):
        """Move deleted keys to the deleted folder."""
        if now is None:
            now = datetime.datetime.utcnow()
        if self.delete and (self.delete + self._cfg.INTERVAL) <= now:
            for path in [self._path, self._path_private]:
                basename = os.path.basename(path)
                new_path = os.path.join(deleted_path, basename)
                os.rename(path, new_path)

    def __init__(self, path, config=None):
        """Parse the dnssec key file ``path``."""
        if config is None:
            self._cfg = Config()
        else:
            self._cfg = config
        if not path.endswith(".private"):
            raise ValueError("%s is not a valid private key (should ends with .private)" % path)
        if not os.path.isfile(path):
            raise ValueError("%s do not exists" % path)
        self._path = "%s.key" % path[:-8]
        if not os.path.isfile(self._path):
            raise ValueError("The public key (%s) of %s does not exist" % (self._path, path))
        self._path_private = path
        self._parse_public_key()
        self._parse_private_key()

        if self.flag == 256:
            self.type = "ZSK"
        elif self.flag == 257:
            self.type = "KSK"
        else:
            raise ValueError(
                "%s is not a valid key: flag %s unknown (known ones are 256 and 257)" % (
                    self._path,
                    self.flag
                )
            )

    def _parse_public_key(self):
        with open(self._path, 'r') as f:
            self._data = f.read()
        for line in self._data.split("\n"):
            if line.startswith(";") or not line:
                continue
            line = line.split(";", 1)[0].strip()
            line = line.split()
            if len(line) < 7:
                raise ValueError(
                    "The public key %s should have at least 7 fields: %r" % (self._path, line)
                )
            if not line[0].endswith('.'):
                raise ValueError(
                    (
                        "The public key %s should begin with the zone fqdn (ending with a .)"
                    ) % self._path
                )
            self.zone_name = line[0][:-1]
            try:
                self.flag = int(line[3])
            except ValueError:
                raise ValueError(
                    "The flag %s of the public key %s should be an integer" % (line[3], self._path)
                )

    def _parse_private_key(self):
        keyid = self._path_private.split('.')[-2].split('+')[-1]
        try:
            self.keyid = int(keyid)
        except ValueError:
            raise ValueError(
                "The keyid %s of the key %s should be an integer" % (keyid, self._path_private)
            )
        with open(self._path_private, 'r') as f:
            private_data = f.read()
        for line in private_data.split("\n"):
            if line.startswith("Created:"):
                self._created = line[8:].strip()
                self._date_from_key(self._created)
            elif line.startswith("Publish:"):
                self._publish = line[8:].strip()
                self._date_from_key(self._publish)
            elif line.startswith("Activate:"):
                self._activate = line[9:].strip()
                self._date_from_key(self._activate)
            elif line.startswith("Inactive:"):
                self._inactive = line[9:].strip()
                self._date_from_key(self._inactive)
            elif line.startswith("Delete:"):
                self._delete = line[7:].strip()
                self._date_from_key(self._delete)
            elif line.startswith("Algorithm:"):
                algorithm = int(line[11:13].strip())
                self.algorithm = self._cfg.SUPPORTED_ALGORITHMS.get(
                    algorithm,
                    "Unknown (%d)" % algorithm
                )
        if self.created is None:
            raise ValueError(
                "The key %s must have as list its Created field defined" % self._path_private
            )

    def __lt__(self, y):
        """
        Allow to compare two keys.

        Comparison is done on the keys activation date is possible, if not on the publication
        date, and finally, if not possible, on the creation date.
        Keys always have a creation date.
        """
        if not isinstance(y, Key):
            raise ValueError("can only compare two Keys")
        if self.activate is not None and y.activate is not None:
            return self.activate < y.activate
        elif self.publish is not None and y.publish is not None:
            return self.publish < y.publish
        else:
            return self.created < y.created

    def __eq__(self, y):
        """
        Allow to check if two key instances are equals.

        Two key instances are equals if they point to the same key file.
        """
        # pylint: disable=locally-disabled,protected-access
        # noinspection PyProtectedMember
        return isinstance(y, Key) and y._path == self._path


def parse_arguments(config):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('zone', nargs='*', help='A dns zone name.')
    parser.add_argument(
        '--config',
        help=(
            "Path to a config file. If not specified, the first file found "
            "among %s will be used." % ", ".join(Config.config_paths)
        )
    )
    parser.add_argument(
        '--make', '-m',
        action='store_true',
        help='Create initials keys for each supplied zone'
    )
    parser.add_argument(
        '--cron', '-c',
        action='store_true',
        help='Perform maintenance for each supplied zone or for all zones if no zone supplied'
    )
    parser.add_argument(
        '--ds',
        choices=list(config.DS_ALGORITHMS.values()) + ['all'],
        help='Show KSK DS for each supplied zone or for all zones if no zone supplied'
    )
    parser.add_argument(
        '--key',
        nargs='?', const="all", type=str, choices=["all", "ksk", "zsk"],
        help='Show DNSKEY for each zone supplied zone or for all zones if no zone supplied'
    )
    parser.add_argument(
        '--key-table',
        nargs='?', const="default", type=str, choices=["default", "all_fields"],
        help='Show a table with all non deleted DNSKEY meaningful dates'
    )
    parser.add_argument(
        '--ds-seen',
        metavar='KEYID',
        type=int,
        help=(
            'To call with the ID of a new KSK published in the parent zone. '
            'Programs old KSK removal. '
            'If will check that the KSK DS appear on each servers of the parent '
            'zone, except if called with --no-check.'
        )
    )
    parser.add_argument(
        '--no-check',
        action='store_true',
        help='Allow to bypass DS check from parent zone in --ds-seen'
    )
    parser.add_argument(
        '--ds-check',
        metavar='KEYID',
        type=int,
        help=(
            'To call with the ID of a KSK published in the parent zone. '
            'Check that the KSK DS appear on each servers of the parent zone. '
        )
    )
    parser.add_argument(
        '--nsec3',
        action='store_true',
        help='Enable NSEC3 for the zones, using a random salt'
    )
    parser.add_argument(
        '--show-config',
        action='store_true',
        help='Show the current configuration'
    )
    return parser


def main():  # pylint: disable=locally-disabled,too-many-branches
    """Run functions based on command line arguments."""
    config = Config()
    parser = parse_arguments(config)
    args = parser.parse_args()
    zones = args.zone
    if args.show_config:
        config.show()
    if args.make:
        for zone in zones:
            Zone.create(zone, config=config)
    zones = get_zones(zones if zones else None, config=config)
    if args.nsec3:
        for zone in zones:
            zone.nsec3()
    if args.ds_check:
        if len(zones) != 1:
            sys.exit("Please specify exactly ONE zone name\n")
        for zone in zones:
            zone.ds_check(args.ds_check)
    if args.ds_seen:
        if len(zones) != 1:
            sys.exit("Please specify exactly ONE zone name\n")
        for zone in zones:
            zone.ds_seen(args.ds_seen, check=not args.no_check)
    if args.cron:
        for zone in zones:
            zone.do_zsk()
            zone.do_ksk()
            zone.remove_deleted()
    if args.ds:
        for zone in zones:
            zone.ds(args.ds)
    if args.key:
        for zone in zones:
            zone.key(show_ksk=args.key in ["all", "ksk"],
                     show_zsk=args.key in ["all", "zsk"])
    if args.key_table:
        Zone.key_table(zones, args.key_table == "all_fields")
    if not any([
            args.make, args.cron, args.ds, args.key, args.ds_seen, args.nsec3,
            args.show_config, args.key_table, args.ds_check
    ]):
        parser.print_help()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, IOError) as main_error:
        sys.exit("%s" % main_error)
