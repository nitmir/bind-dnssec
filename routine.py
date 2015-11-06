#!/usr/bin/env python

import os
import sys
import datetime
import subprocess 

from functools import total_ordering

BASE = "/etc/bind/keys"
INTERVAL = "3d"
ZSK_VALIDITY = datetime.timedelta(days=30)

def get_zones(zone_names=None):
    l = []
    if zone_names is None:
        for f in os.listdir(BASE):
            if os.path.isdir(os.path.join(BASE, f)):
                l.append(Zone(f))
    else:
        for name in zone_names:
            l.append(Zone(name))
    return l

def settime(path, flag, date):
    cmd = ["/usr/sbin/dnssec-settime", "-i", INTERVAL, "-%s" % flag, date, path]
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE)
    err = p.communicate()[1]
    if p.returncode != 0:
        raise ValueError("err %s: %s" % (p.returncode, err))
    if err:
        print err

def bind_chown(path):
    os.chown(path, 104, -1)
    for root, dirs, files in os.walk(path):  
        for momo in dirs:  
            os.chown(os.path.join(root, momo), 104, -1)
        for momo in files:
            os.chown(os.path.join(root, momo), 104, -1)

def bind_reload():
    cmd = ["/usr/sbin/rndc", "reload"]
    p = subprocess.Popen(cmd)
    p.wait()

class Zone(object):
    ZSK = None
    KSK = None
    _path = None
    name = None

    def __str__(self):
        return self.name

    def __unicode__(self):
        return self.name.decode("utf-8")

    def __repr__(self):
        return "Zone %s" % self.name

    @classmethod
    def create(cls, name):
        path = os.path.join(BASE, name)
        if os.path.isdir(path):
            raise ValueError("%s existe" % path)
        os.mkdir(path)
        bind_chown(path)
        return cls(name)

    def do_zsk(self):
        for zsk in self.ZSK:
            if zsk.is_activate:
                inactive = zsk.activate + ZSK_VALIDITY
                zsk.delete = inactive + ZSK_VALIDITY
                zsk.inactive = inactive
        if zsk.is_activate:
            zsk.gen_successor()
            bind_reload()

    def ds(self):
        for ksk in self.KSK:
            cmd = ["/usr/sbin/dnssec-dsfromkey", ksk._path]
            p = subprocess.Popen(cmd)
            p.wait()
    def key(self):
        for ksk in self.KSK:
            print ksk

    def __init__(self, name):
        path = os.path.join(BASE, name)
        if not os.path.isdir(path):
            raise ValueError("%s n'est pas un dossier" % path)
        self.name = name
        self._path = path
        self.ZSK = []
        self.KSK = []
        for file in os.listdir(path):
            file_path = os.path.join(path, file)
            if os.path.isfile(file_path):
               try:
                   key = Key(file_path)
                   if key.type == "ZSK":
                       self.ZSK.append(key)
                   elif key.type == "KSK":
                       self.KSK.append(key)
                   else:
                       raise RuntimeError("impossible")
               except ValueError:
                   pass
        self.ZSK.sort()
        self.KSK.sort()
        if not self.ZSK:
            self.ZSK.append(Key.create("ZSK", name))
        if not self.KSK:
            self.KSK.append(Key.create("KSK", name))

@total_ordering
class Key(object):
    _created = None
    _publish = None
    _activate = None
    _inactive = None
    _delete = None
    _data = None
    _path = None
    type = None
    keyid = None

    def __str__(self):
        return self._data

    def __repr__(self):
        r = os.path.basename(self._path)
        return r
        
    def _date_from_key(self, date):
        if date is not None:
            return datetime.datetime.strptime(date, "%Y%m%d%H%M%S")
    def _date_to_key(self, date):
        return datetime.datetime.strftime(date, "%Y%m%d%H%M%S")

    @classmethod
    def create(cls, typ, name):
        path = os.path.join(BASE, name)
        if typ == "KSK":
            cmd = ["/usr/sbin/dnssec-keygen", "-a", "RSASHA256", "-b", "2048", "-f", "KSK", "-K", path,  name]
        elif typ == "ZSK":
            cmd = ["/usr/sbin/dnssec-keygen", "-a", "RSASHA256", "-b", "1024", "-K", path,  name]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        p.wait()
        if p.returncode != 0:
            raise ValueError("La creation de la clef a echoue")
        keyname = p.communicate()[0].strip()
        bind_chown(path)
        return cls(os.path.join(path, "%s.key" % keyname))
          
    def gen_successor(self):
        cmd = ["/usr/sbin/dnssec-keygen", "-i", INTERVAL,  "-S", self._path, "-K", os.path.dirname(self._path)]
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        err = p.communicate()[1]
        if p.returncode != 0:
            raise ValueError("err %s: %s" % (p.returncode, err))
        if err:
            print err
        bind_chown(os.path.dirname(self._path))

    @property
    def created(self):
        return self._date_from_key(self._created)

    @property
    def publish(self):
        return self._date_from_key(self._publish)
    @publish.setter
    def publish(self, value):
        date = self._date_to_key(value)
        if date != self._publish:
            settime(self._path, 'P', date)
            self._publish = date
            with open(self._path, 'r') as f:   
                self._data = f.read()

    @property
    def activate(self):
        return self._date_from_key(self._activate)
    @activate.setter
    def activate(self, value):
        date = self._date_to_key(value)
        if date != self._activate:
            settime(self._path, 'A', date)
            self._activate = date
            with open(self._path, 'r') as f:   
                self._data = f.read()

    @property
    def inactive(self):
        return self._date_from_key(self._inactive)
    @inactive.setter
    def inactive(self, value):
        date = self._date_to_key(value)
        if date != self._inactive:
            settime(self._path, 'I', date)
            self._inactive = date
            with open(self._path, 'r') as f:   
                self._data = f.read()

    @property
    def is_activate(self):
        return self.activate <= datetime.datetime.now()
    @property
    def is_inactive(self):
        return self.inactive <= datetime.datetime.now()

    @property
    def delete(self):
        return self._date_from_key(self._delete)
    @delete.setter
    def delete(self, value):
        date = self._date_to_key(value)
        if date != self._delete:
            settime(self._path, 'D', date)
            self._delete = date
            with open(self._path, 'r') as f:   
                self._data = f.read()

    def __init__(self, path):
        with open(path, 'r') as f:   
            self._data = f.read()
        if "This is a zone-signing key" in self._data:
            self.type = "ZSK"
        elif "This is a key-signing key" in self._data:
            self.type = "KSK"
        else:
            raise ValueError("%s n'est pas une clef valide" % path)
        self._path = path
        lines = self._data.split("\n")
        self. keyid = lines[0].split(',')[1].split()[-1]
        for line in lines:
            if line.startswith("; Created: "):
                self._created = line[11:11+14]
            elif line.startswith("; Publish: "):
                self._publish = line[11:11+14]
            elif line.startswith("; Activate: "):
                self._activate = line[12:12+14]
            elif line.startswith("; Inactive: "):
                self._inactive = line[12:12+14]
            elif line.startswith("; Delete: "):
                self._delete = line[10:10+14]

    def __lt__(self, y):
       if not isinstance(y, Key):
           raise ValueError("can only compare two Keys")
       return self.activate < y.activate

    def __eq__(self, y):
        return isinstance(y, Key) and y._path == self._path

if __name__ == '__main__':
    try:
        zones = []
        for arg in sys.argv[1:]:
            if not arg.startswith('-'):
                zones.append(arg)
        if '-m' in sys.argv and zones:
            for zone in zones:
                Zone.create(zone)
        zones = get_zones(zones if zones else None)
        if '-c' in sys.argv:
            for zone in zones:
                zone.do_zsk()
        if '-ds' in sys.argv:
            for zone in zones:
                zone.ds()
        if '-key' in sys.argv:
            for zone in zones:
                zone.key()
    except ValueError as error:
        sys.stderr.write("%s\n" % error)
        sys.exit(1)
