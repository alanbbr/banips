#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""
Apply one or more ipsets to the local system to block attacks from those IPs.

author: Alan Brenner
license: GPLv2
"""

import concurrent.futures
import datetime
import gzip
import json
import logging
import os
import re
import shutil
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from pprint import pformat
from subprocess import run
from urllib import request
try:
    import pygeoip
    GEOIP = True
except ImportError:
    GEOIP = False

logging.basicConfig(format='%(asctime)-15s %(levelname)s:%(name)s:'
                    '%(funcName)s:%(lineno)d:%(message)s')
logger = logging.getLogger('banips')


COMMANDS = ('download', 'start', 'stop', 'refresh', 'suspend', 'resume',
            'restore_backup', 'remove_backup', 'report', 'query', 'exporter')
# set initial defaults
DEFS = {'ver': '0.1.0',
        'action': 'start',
        'asns': '',
        'backupdir': '/var/local/banIP/Backup',
        'banlist': '/etc/banIP/banip.banlist',
        'chain': 'banIP',
        'countries': '',
        'devs': [],
        'exporter_host': '',
        'exporter_port': 9100,
        'extrasources': '',
        'geoip4': '/usr/share/GeoIP/GeoIP.dat',
        'geoip6': '/usr/share/GeoIP/GeoIPv6.dat',
        'global_settype': 'src+dst',
        'ip_cmd': shutil.which('ip'),
        'ipset_cmd': shutil.which('ipset'),
        'ipt4_cmd': shutil.which('iptables'),
        'ipt4_restorecmd': shutil.which('iptables-restore'),
        'ipt4_savecmd': shutil.which('iptables-save'),
        'ipt6_cmd': shutil.which('ip6tables'),
        'ipt6_restorecmd': shutil.which('ip6tables-restore'),
        'ipt6_savecmd': shutil.which('ip6tables-save'),
        'lan_forwardchains_4': 'FORWARD',
        'lan_forwardchains_6': 'FORWARD',
        'lan_inputchains_4': 'INPUT',
        'lan_inputchains_6': 'INPUT',
        'lan_outputchains_4': 'OUTPUT',
        'lan_outputchains_6': 'OUTPUT',
        'localsources': ["maclist", "oklist", "banlist"],
        'log_accept': 'banIP_ACCEPT',
        'log_accept_enabled': '0',
        'log_accept_opts': "-m limit --limit 2/sec",
        'log_accept_prefix': 'banIP_ACCEPT',
        'log_drop': 'banIP_DROP',
        'log_drop_enabled': '0',
        'log_drop_opts': "-m limit --limit 2/sec",
        'log_drop_prefix': 'banIP_DROP',
        'maclist': '/etc/banIP/banip.maclist',
        'mail_enabled': '0',
        'mailreceiver': '',
        'mailsender': '',
        'mailsubject': '',
        'oklist': '/etc/banIP/banip.oklist',
        'pidfile': '/var/run/banip.pid',
        'proto4_enabled': True,
        'proto6_enabled': True,
        'query_timeout': 30,
        'reportdir': '/var/local/banIP/Report',
        'settype_all': '',
        'settype_dst': '',
        'settype_src': '',
        'sources': '',
        'srcfile': '/etc/banIP/banip.sources',
        'target_dst': 'REJECT',
        'target_src': 'DROP',
        'tmpdir': '/var/local/banIP/tmp',
        'wait': "-w5",
        'wan_forwardchains_4': 'forwarding_wan_rule',
        'wan_forwardchains_6': 'forwarding_wan_rule',
        'wan_inputchains_4': 'input_wan_rule',
        'wan_inputchains_6': 'input_wan_rule',
        'wan_outputchains_4': 'output_wan_rule',
        'wan_outputchains_6': 'output_wan_rule',
        'oklist': '/etc/banIP/banip.oklist',
        'oklistonly': '0'}


def _get_banip(filename):
    """
    Parse a file that looks like:

    config banip 'global'
        option ban_mail_enabled '0'
        list ban_sources 'darklist'
        list ban_sources 'debl'
        list ban_sources 'talos'

    param filename: config file to parse
    return: dictionary of strings or lists of strings
    """
    rval = {}
    with open(filename, 'r', encoding='utf8') as banip:
        for line in banip:
            parts = line.strip().split(' ')
            logger.debug(parts)
            key = 'devs' if parts[1] == 'ban_ifaces' else parts[1][4:]
            if parts[0] == 'config' or len(parts) == 0:
                continue
            val = parts[2].strip("'")
            if parts[0] == 'option':
                rval[key] = val
            elif parts[0] == 'list':
                if key not in rval:
                    rval[key] = []
                rval[key].append(val)
            else:
                logger.warning("unexpected line: %s", line)
    logger.debug(pformat(rval))
    return rval


def _get_ini(filename):
    """
    Parse an ini style configuration file:

    [banips]
    mail_enabled = 0
    ban_sources = darklist,debl,talos

    param filename: config file to parse
    return: dictionary of strings or lists of strings
    """
    import configparser # pylint: disable=import-outside-toplevel
    config = configparser.ConfigParser()
    config.read(filename)
    rval = {}
    for key in config['banips']:
        if ',' in config['banips'][key]:
            rval[key] = config['banips'][key].split(',')
            continue
        if 'enabled' in key:
            rval[key] = config['banips'].getboolean(key)
        else:
            rval[key] = config['banips'][key]
    logger.debug(pformat(rval))
    return rval


def _filetest(filename):
    """Return true if the named file exists and is not empty."""
    return Path(filename).is_file() and Path(filename).stat().st_size > 0


class BanIPs:
    """
    Manage ipsets to block known bad actor addresses.
    """

    def __init__(self, cmdopts): # pylint: disable=R0912
        """
        Load configuration from file and command line.

        param cmdopts: dictionary of command line options
        """
        logger.debug(cmdopts)
        conf = _get_banip(cmdopts['config']) if cmdopts['banip'] else _get_ini(cmdopts['config'])
        self.conf = {**DEFS, **conf, **cmdopts}
        for key in self.conf:
            if 'enabled' in key or key in ('oklistonly', ):
                self.conf[key] = self.conf[key].lower() in ('1', 'true', 'yes')
        for ii in ('src', 'dst'):
            key = 'lc_' + ii
            if key not in self.conf:
                self.conf[key] = self.conf['chain'] + '_log_src'
            key = 'lt_' + ii
            if key not in self.conf:
                self.conf[key] = self.conf['target_' + ii]
        if isinstance(self.conf['extrasources'], str):
            self.conf['extrasources'] = [self.conf['extrasources'], ] if self.conf['extrasources'] else []
        for key in ('src', 'dst'):
            if f'target_{key}' not in self.conf:
                self.conf[f'target_{key}'] = self.conf[f'lc_{key}']
            if f'logprefix_{key}' not in self.conf:
                self.conf[f'logprefix_{key}'] = ['banips-' + self.conf['ver'], f'{key}/' + self.conf[f'target_{key}']]
        for key in ('backupdir', 'tmpdir'):
            band = Path(self.conf[key])
            if not band.is_dir():
                band.mkdir(parents=True)
        for key in ('geoip4', 'geoip6'):
            geof = Path(self.conf[key])
            if not geof.is_file():
                self.conf[key] = None
        logger.debug(pformat(self.conf))


    def _gettype(self, src_name, aslist=False):
        """
        Get the set type, one of src, dst, src+dst or the global_settype.

        @param src_name:
        @return: one of src, dst, src+dst
        """
        if src_name in self.conf['settype_src']:
            rval = "src"
        elif src_name in self.conf['settype_dst']:
            rval = "dst"
        elif src_name in self.conf['settype_all']:
            rval = "src+dst"
        else:
            rval = self.conf['global_settype']
        if aslist:
            return rval.split('+')
        return rval


    def _iptable_cmd(self, ver, command, chain, rule=None):
        """
        Run iptables.
        """
        cmd = [self.conf[f"ipt{ver}_cmd"], self.conf['wait'], command, chain]
        if rule is not None:
            cmd.extend(rule)
        logger.debug(cmd)
        logger.debug(' '.join(cmd))
        cpc = run(cmd, check=False, capture_output=True, text=True)
        logger.debug("rc: %d, stdout: %r, stderr: %r", cpc.returncode, cpc.stdout, cpc.stderr)
        return cpc


    def _iptables_find_entry(self, ver, src_name):
        """
        Return the position of an entry, or None if it doesn't exist;
        """
        logger.debug("%s, %s", ver, src_name)
        cpc = self._iptable_cmd(ver, '-L', self.conf['chain'], ['-v', '--line-numbers'])
        for line in cpc.stdout.split("\n"):
            parts = line.split(' ')
            if parts[0][0] not in ('1', '2', '3', '4', '5', '6', '7', '8', '9'):
                continue
            logger.debug(line.strip())
            # TODO: how to match src_name in the output so we can return parts[0]?
            if parts[3] == src_name:
                return parts[0]
        return None


    def _iptables_get_rule(self, src_name, dev):
        """
        Generate the rule used for matching a set.
        """
        set_type = self._gettype(src_name)
        io = '-i' if set_type != "dst" else '-o'
        opt = 'src' if set_type != "dst" else 'dst'
        tgt = self.conf['log_accept'] if 'oklist' in src_name else self.conf['log_drop']
        return [io, dev, '-m', 'set', '--match-set', src_name, opt, '-j', tgt]


    def iptables_insert(self, src_name):
        """
        Add entries to the chain that links to the ipsets.

        """
        logger.debug(src_name)
        ver = '6' if '6' in src_name else '4'
        if src_name == 'maclist':
            pos = 1
        elif 'banlist' in src_name:
            pos = self._iptables_find_entry(ver, 'maclist')
        elif 'oklist' in src_name:
            pos = self._iptables_find_entry(ver, 'banlist')
            if pos is None:
                pos = self._iptables_find_entry(ver, 'maclist')
        else:
            pos = None
        cmd = '-A' if pos is None else '-I'
        for dev in self.conf['devs']:
            if self.conf[f'proto{ver}_enabled']:
                rule = self._iptables_get_rule(src_name, dev)
                cpc = self._iptable_cmd(ver, '-C', self.conf['chain'], rule)
                logger.debug("rc: %d, stdout: %r, stderr: %r", cpc.returncode, cpc.stdout, cpc.stderr)
                if cpc.returncode != 0:
                    ruler = [] if pos is None else [str(pos), ]
                    ruler.extend(rule)
                    cpc = self._iptable_cmd(ver, cmd, self.conf['chain'], ruler)
                    if cpc.returncode != 0:
                        logger.warning("command '%s' failed with '%s, %r, %r'", cmd, self.conf['chain'], pos, ruler)


    def iptables_delete(self, src_name):
        """
        Undo what iptables_insert adds.
        """
        logger.debug(src_name)
        ver = '6' if '6' in src_name else '4'
        for dev in self.conf['devs']:
            logger.debug(dev)
            rule = self._iptables_get_rule(src_name, dev)
            cpc = self._iptable_cmd(ver, '-C', self.conf['chain'], rule)
            logger.debug("rc: %d, stdout: %r, stderr: %r", cpc.returncode, cpc.stdout, cpc.stderr)
            if cpc.returncode != 0:
                cpc = self._iptable_cmd(ver, '-D', self.conf['chain'], rule)
                if cpc.returncode != 0:
                    logger.warning("command '-D' failed for chain %s matching %r'", self.conf['chain'], rule)


    def _iptables_new_chain_if_needed(self, ver, chain):
        """
        Create a chain, if it does not already exist.
        """
        cpc = self._iptable_cmd(ver, '-nL', chain)
        if len(cpc.stdout) != 0:
            logger.debug("chain %s already exists", chain)
        else:
            logger.debug("creating chain %s", chain)
            cpc = self._iptable_cmd(ver, '-N', chain)
            if cpc.returncode != 0:
                raise RuntimeError(f"rc = {cpc.returncode}, chain = {chain}, stdout = {cpc.stdout}, stderr = {cpc.stderr}")


    def _iptables_create_final_jump(self, ver, opt):
        """
        All ipset matches jump to a chain created here to either ACCEPT or DROP a remote source (maybe after logging it first).
        """
        chain = self.conf[f"log_{opt}"]
        self._iptables_new_chain_if_needed(ver, chain)
        if self.conf[f"log_{opt}_enabled"]:
            # add logging first, if so configured
            rule = ['-j', 'LOG']
            key = f"log_{opt}_opts"
            if self.conf.get(key, False) and self.conf[key]:
                rule.extend(self.conf[key].split(' '))
            key = f"log_{key}_prefix"
            if self.conf.get(key, False) and self.conf[key]:
                rule.extend(['--log-prefix', self.conf[key]])
            cpc  = self._iptable_cmd(ver, '-A', chain, rule)
            if cpc.returncode != 0:
                raise RuntimeError(f"rc = {cpc.returncode}, stdout = {cpc.stdout}, stderr = {cpc.stderr}")
        # This isn't really
        cpc = self._iptable_cmd(ver, '-A', chain, ['-j', opt.upper()])
        if cpc.returncode != 0:
            raise RuntimeError(f"rc = {cpc.returncode}, stdout = {cpc.stdout}, stderr = {cpc.stderr}")


    def iptables_create(self):
        """
        Initial iptables chains setup.
        """
        for ver in ("4", "6"): # pylint: disable=R1702
            if not self.conf[f"proto{ver}_enabled"]:
                logger.debug("IPv%s is not enabled", ver)
                continue
            logger.debug(ver)
            # Create an 'accept' chain that may log activity
            self._iptables_create_final_jump(ver, 'accept')
            # Create an 'drop' chain that may log activity
            self._iptables_create_final_jump(ver, 'drop')
            # Create a single place where ipsets are scanned.
            self._iptables_new_chain_if_needed(ver, self.conf['chain'])
            # Load the input, forward, and output chains with jumps to that single place.
            for ii in ('lan', 'wan'):
                for jj in ('input', 'forward', 'output'):
                    chain = self.conf[f"{ii}_{jj}chains_{ver}"]
                    cpc = self._iptable_cmd(ver, '-L', chain)
                    if cpc.returncode == 0:
                        cpc = self._iptable_cmd(ver, '-C', chain, ['-j', self.conf['chain']])
                        if cpc.returncode != 0:
                            logger.debug("adding jump to chain %s from %s", self.conf['chain'], chain)
                            cpc = self._iptable_cmd(ver, "-I", chain, ['1', '-j', self.conf['chain']])
                            if cpc.returncode != 0:
                                raise RuntimeError(f"rc = {cpc.returncode}, stdout = {cpc.stdout}, stderr = {cpc.stderr}")
                        else:
                            logger.debug("source chain %s already has jump", chain)
                    else:
                        logger.debug("source chain %s does not exist", chain)


    def _iptables_del_chain_if_exists(self, ver, chain):
        """
        Remove a chain, if it exists.
        """
        cpc = self._iptable_cmd(ver, '-nL', chain)
        if len(cpc.stdout) == 0:
            logger.debug("chain %s does not exist", chain)
        else:
            logger.debug("removing chain %s", chain)
            cpc = self._iptable_cmd(ver, '-F', chain)
            if cpc.returncode != 0:
                logger.warning("rc = %d, stdout = %s, stderr = %s", cpc.returncode, cpc.stdout, cpc.stderr)
            cpc = self._iptable_cmd(ver, '-X', chain)
            if cpc.returncode != 0:
                logger.warning("rc = %d, stdout = %s, stderr = %s", cpc.returncode, cpc.stdout, cpc.stderr)


    def iptables_destroy(self):
        """
        Undo what iptables_create sets up.
        """
        # First remove the jumps
        for ver in ('4', '6'):
            for ii in ('lan', 'wan'):
                for jj in ('input', 'forward', 'output'):
                    chain = self.conf[f"{ii}_{jj}chains_{ver}"]
                    cpc = self._iptable_cmd(ver, '-C', chain, ['-j', self.conf['chain']])
                    if cpc.returncode == 0:
                        logger.debug("removing jump to chain %s from %s", self.conf['chain'], chain)
                        cpc = self._iptable_cmd(ver, "-D", chain, ['-j', self.conf['chain']])
                        if cpc.returncode != 0:
                            logger.warning("rc = %d, stdout = %s, stderr = %s", cpc.returncode, cpc.stdout, cpc.stderr)
                    else:
                        logger.debug("target chain %s does not exist", chain)
            self._iptables_del_chain_if_exists(ver, self.conf['chain'])
            self._iptables_del_chain_if_exists(ver, self.conf['log_accept'])
            self._iptables_del_chain_if_exists(ver, self.conf['log_drop'])


    def _ipset_cmd(self, opts):
        """
        Wrap calling ipset, with error logging.
        """
        cmd = [self.conf['ipset_cmd'], ]
        cmd.extend(opts)
        logger.debug(cmd)
        logger.debug(' '.join(cmd))
        try:
            cpc = run(cmd, check=False, capture_output=True, text=True)
            logger.debug("rc: %d, stdout: %r, stderr: %r", cpc.returncode, cpc.stdout, cpc.stderr)
        except Exception as err: # pylint: disable=W0703
            logger.error(err)
        return cpc


    def ipset_create(self, set_file):
        """
        Create an ipset.

        @param set_file: file generated by a prep_ method
        """
        set_name = set_file.stem
        logger.debug("checking %s for existing entries", set_name)
        cpc = self._ipset_cmd(['-q', '-n', 'list', set_name])
        if len(cpc.stdout) != 0:
            logger.debug("removing entries in set %s", set_name)
            rc = self._ipset_flush(set_name, iptables=False).returncode
        else:
            logger.debug("creating a new %s set", set_name)
            maxlen = len(set_file.read_text().split("\n")) + 262144
            ipver = 'inet6' if '6' in set_name else 'inet'
            for key in ('maclist', 'oklist', 'banlist'):
                if key in set_name:
                    cpc = self._ipset_cmd(['create', set_name, 'hash:mac', 'hashsize', '64', 'maxelem', str(maxlen),
                                           'counters', 'timeout', self.conf.get(key + '_timeout', '0')])
                    break
            else:
                cpc = self._ipset_cmd(['create', set_name, 'hash:net', 'hashsize', '64', 'maxelem', str(maxlen),
                                       'family', ipver, 'counters'])
            rc = cpc.returncode
        return rc


    def ipset_restore(self, set_file):
        """
        Load a file generated by one of the prep methods.
        """
        logger.debug("loading %s", set_file.as_posix())
        cpc = self._ipset_cmd(['-!', 'restore', '-file', set_file.as_posix()])
        return cpc.returncode


    def ipset_restore_backup(self, set_name):
        """
        gunzip decompress the given input file. tmp_load and src_name must be set in cnf.
        """
        inpath = Path(os.path.join(self.conf['backupdir'], f"{set_name}.gz"))
        if not inpath.exists():
            logger.warning("cannot find input file %s", inpath.as_posix())
            return
        set_file = os.path.join(self.conf['tmpdir'], f"{set_name}.set")
        try:
            with gzip.open(inpath, 'rb') as infile:
                with open(set_file, 'w', encoding='utf8') as outfile:
                    shutil.copyfileobj(infile, outfile)
        except Exception as err: # pylint: disable=W0703
            logger.error(err)


    def ipset_remove_backup(self, set_name):
        """
        Remote a gzip compressed file.
        """
        inpath = Path(os.path.join(self.conf['backupdir'], f"{set_name}.gz"))
        inpath.unlink(missing_ok=True)


    def ipset_get_counts(self, src_name):
        """
        Count total entries, cidr entries, mac address entries.

        @param src_name: ipset to list
        @return: count, cidr count, mac address count as integers
        """
        m1 = re.compile(r"(([0-9A-Z][0-9A-Z]:){5}[0-9A-Z]{2} )")
        m2 = re.compile(r"(/[0-9]{1,3} )")
        cnt = cnt_mac = cnt_cidr = 0
        logger.debug("getting counts for %s", src_name)
        cpc = self._ipset_cmd(['-q', 'list', src_name])
        src_list = cpc.stdout.split("\n")
        for line in src_list:
            if line.startswith('Number of entries:'):
                cnt = int(line.split(' ')[3])
            if m1.match(line):
                cnt_mac += 1
            if m2.search(line):
                cnt_cidr += 1
        logger.debug("count=%d, cidr=%d, mac=%d", cnt, cnt_cidr, cnt_mac)
        if 'load_counts' in self.conf:
            self.conf['load_counts'][src_name] = cnt
        return cnt, cnt_cidr, cnt_mac


    def _ipset_flush(self, set_name, iptables=True):
        """
        Remove named ipset from the kernel
        """
        logger.debug(set_name)
        if iptables:
            self.iptables_delete(set_name)
        cpc = self._ipset_cmd(['-q', '-n', 'list', set_name])
        if len(cpc.stdout) > 0:
            cpc = self._ipset_cmd(['-q', 'flush', set_name])
        return cpc


    def _ipset_suspend_save_and_flush(self, set_name):
        """
        Write the named ipset to a file, then flush it from the kernel.

        @param set_name: ipset name
        """
        cpc = self._ipset_cmd(['-q', '-n', 'list', set_name])
        if len(cpc.stdout) > 0:
            set_file = f"{self.conf['backupdir']}/{set_name}.save"
            cpc = self._ipset_cmd(['-q', 'save', set_name, '|', 'tail', '-n', '+2', '-file', set_file])
            if cpc.returncode == 0:
                self._ipset_flush(set_name)


    def ipset_suspend(self):
        """
        Save and stop all ipsets.
        """
        Path(self.conf['backupdir']).mkdir(parents=True)
        for src in self.conf['sources'] + self.conf['localsources']:
            if src == "maclist":
                self._ipset_suspend_save_and_flush(src)
            else:
                for proto in ("4", "6"):
                    self._ipset_suspend_save_and_flush(f"{src}_{proto}")


    def ipset_resume(self):
        """
        Load suspended ipset.
        """
        srcd = Path(self.conf['backupdir'])
        if not srcd.is_dir():
            logger.error("Backup directory %s does not exist, so can't resume", self.conf['backupdir'])
            return
        for set_file in srcd.glob("*.save"):
            if self.ipset_restore(set_file) == 0:
                set_file.unlink()


    def _destroy_src(self, set_name):
        """
        Remove the named ipset, if it exists.
        """
        logger.debug(set_name)
        cpc = self._ipset_cmd(['-q', '-n', 'list', set_name])
        if len(cpc.stdout) > 0:
            cpc = self._ipset_cmd(['-q', 'destroy', set_name])
            return cpc.returncode # if non-0, we need to re-run
        return 0 # do not re-run over the ipset not existing


    def ipset_stop(self, second=False):
        """
        Remoce all iptables and ipsets.
        """
        # Remove any related iptables entries first.
        self.iptables_destroy()
        logger.debug("local config: %r", self.conf['localsources'])
        logger.debug("remote sets: %r", self.conf['sources'])
        logger.debug("extras: %r", self.conf['extrasources'])
        redo = False
        for set_name in self.conf['localsources'] + self.conf['sources'] + self.conf['extrasources']:
            logger.debug(set_name)
            if set_name == 'maclist':
                rc = self._destroy_src(set_name)
                if rc != 0:
                    redo = True
            else:
                for ii in ('4', '6'):
                    rc = self._destroy_src(f"{set_name}_{ii}")
                    if rc != 0:
                        redo = True
        if redo and not second:
            # Sometime things don't get removed on the first pass, so try again.
            self.ipset_stop(second=True)


    def _download_url(self, name, src, dst, comp): # pylint: disable=R1710
        """
        Download the given file to given location.
        """
        logger.debug("src: %s, dst: %s, comp: %r", src, dst, comp)
        start_ts = datetime.datetime.now()
        if self.conf['skip'] and Path(dst).exists():
            logger.debug("skipping download of new copy of %s", dst)
            return
        try:
            with request.urlopen(src) as req:
                logger.debug(req.code)
                if req.code != 200:
                    logger.error(req.reason)
                    return req.code
                with open(dst, 'wb') as chain:
                    if comp == 'gz':
                        chain.write(gzip.decompress(req.read()))
                    else:
                        chain.write(req.read())
            stop_ts = datetime.datetime.now()
            logger.debug("downloaded %s in %r", src, stop_ts - start_ts)
        except Exception as err: # pylint: disable=W0703
            with open(os.path.join(self.conf['tmpdir'], f"{name}.err"), 'w', encoding='utf8') as errlog:
                errlog.write(err)
            logger.error(err)


    def download(self, src_name, src_url, comp):
        """
        Manage download types.
        """
        logger.debug(src_name)
        if "country" in src_name:
            # handle country related downloads
            for country in self.conf['countries']:
                csrc = f"{src_url}{country}-aggregated.zone"
                cdst = f"{self.conf['tmpdir']}/{src_name}-{country}.src"
                logger.debug("%s -> %s", csrc, cdst)
                self._download_url(src_name, csrc, cdst, comp)
        elif "asn" in src_name:
            # handle asn related downloads
            for asn in self.conf['asns']:
                asrc = f"{src_url}AS{asn}"
                adst = f"{self.conf['tmpdir']}/{src_name}-{asn}.src"
                logger.debug("%s -> %s", asrc, adst)
                self._download_url(src_name, asrc, adst, comp)
        else:
            # handle normal downloads
            dst = f"{self.conf['tmpdir']}/{src_name}.src"
            logger.debug("%s -> %s", src_url, dst)
            self._download_url(src_name, src_url, dst, comp)


    def download_remote(self, srcs):
        """
        Download controller.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for src_name in self.conf['sources']:
                logger.debug(src_name)
                if src_name not in srcs:
                    logger.warning("undefined source %s", src_name)
                    continue
                comp = srcs[src_name].get('comp', None)
                # handle external IPv4 source downloads in a thread
                if self.conf['proto4_enabled'] and srcs[src_name].get('url_4', False) and srcs[src_name].get('rule_4', False):
                    logger.debug(srcs[src_name]['url_4'])
                    executor.submit(self.download, src_name + '_4', srcs[src_name]['url_4'], comp)
                # handle external IPv6 source downloads in a thread
                if self.conf['proto6_enabled'] and srcs[src_name].get('url_6', False) and srcs[src_name].get('rule_6', False):
                    logger.debug(srcs[src_name]['url_6'])
                    executor.submit(self.download, src_name + '_6', srcs[src_name]['url_6'], comp)
        rc = 0
        for err_file in Path(self.conf['tmpdir']).glob("*.err"):
            rc += 1
            logger.error("banips processing failed with iptables errors during download processing. See %r", err_file)

        logger.debug("%d download errors", rc)
        return rc


    def prep_remote(self, srcs): # src_name, src_rc, src_settype, src_rule, tmp_load, tmp_file):
        """
        Download post-processing.
        """
        for src_file in Path(self.conf['tmpdir']).glob("*.src"):
            dst_file = os.path.join(self.conf['tmpdir'], src_file.stem)  + '.set'
            logger.debug(dst_file)
            parts = src_file.stem.split('_')
            if len(parts) != 2 or parts[0] not in self.conf['sources']:
                logger.warning("%s does not look like a valid input file.", src_file.as_posix())
                continue
            src_rule = srcs[parts[0]].get('rule_' + parts[1], None)
            if src_rule is None:
                logger.warning("rule_%s not found in the source JSON for %s", parts[1], parts[0])
                continue
            flag = 0 if not src_rule[2] or src_rule[2][0] != 'IGNORECASE' else re.IGNORECASE
            nl = "\n" if not src_rule[2] or src_rule[2][0] != 'FS' else src_rule[2][1]
            logger.debug("pattern: %s, flag=%d", src_rule[0], flag)
            regex = re.compile(src_rule[0], flags=flag)
            logger.debug("formatting %s into %s", src_file.as_posix(), dst_file)
            try:
                with open(src_file, 'r', encoding='utf8', newline=nl) as infile:
                    with open(dst_file, 'w', encoding='utf8') as outfile:
                        for line in infile:
                            #logger.debug(line)
                            rematch = regex.search(line)
                            if rematch:
                                out = []
                                for ii, val in enumerate(src_rule[1]):
                                    out.append(val if ii % 2 == 0 else rematch.group(val))
                                outfile.write(''.join(out) + "\n")
                if not self.conf['keep']:
                    src_file.unlink()
            except Exception as err: # pylint: disable=W0703
                logger.error(err)


    def _prep_list(self, src_name, regex, upper=False):
        """
        Format a maclist, banlist, or oklist for injest.
        """
        logger.debug(src_name)
        src_file = Path(self.conf[src_name.split('_')[0]])
        dst_file = os.path.join(self.conf['tmpdir'], src_name) + '.set'
        logger.debug("formatting %s into %s", src_file.as_posix(), dst_file)
        try:
            with open(src_file, 'r', encoding='utf8') as infile:
                with open(dst_file, 'w', encoding='utf8') as outfile:
                    for line in infile:
                        stripped = line.strip()
                        logger.debug(stripped)
                        if stripped.startswith('#'):
                            continue
                        rematch = regex.match(stripped)
                        if rematch: # The line is an IP address.
                            val = rematch.group(1).upper() if upper else rematch.group(1)
                            outfile.write(f'add {src_name} "{val}"\n')
                        else: # The line is not an IP address, so try DNS resolution to get an address.
                            try:
                                # For a valid hostname, this will fetch 01or more IPv4 and/or IPv6 addresses.
                                for addr in socket.getaddrinfo(stripped, 80, proto=socket.IPPROTO_TCP):
                                    # pylint: disable=E1101
                                    if (self.conf['proto4_enabled'] and addr[0] == socket.AddressFamily.AF_INET) or \
                                       (self.conf['proto6_enabled'] and addr[0] == socket.AddressFamily.AF_INET6):
                                        outfile.write(f'add {src_name} "{addr[4][0]}"\n')
                            except socket.gaierror:
                                logger.warning("invalid hostname found: %s", stripped)
                                continue
        except Exception as err: # pylint: disable=W0703
            logger.error(err)


    def prep_local(self):
        """
        Load local source files (maclist, banlist, oklist)
        """
        regexm = re.compile("([0-9A-z][0-9A-z]:){5}[0-9A-z]{2}([[:space:]]|$)")
        # Define IPv4 address pattern needed to pull from the source file.
        regex4 = re.compile("(([0-9]{1,3}\\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)")
        # Define IPv6 address pattern needed to pull from the source file.
        regex6 = re.compile("(([0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}:?(\\/(1?[0-2][0-8]|[0-9][0-9]))?)")
        for src_name in self.conf['localsources']:
            logger.debug(src_name)
            if not _filetest(self.conf[src_name]):
                logger.debug("input file %s not found", self.conf[src_name])
                continue
            if src_name == "maclist":
                self._prep_list('maclist', regexm, upper=True)
                continue
            if self.conf['proto4_enabled']:
                if src_name == "banlist" and not self.conf['oklistonly']:
                    self._prep_list('banlist_4', regex4)
                elif src_name == "oklist":
                    self._prep_list('oklist_4', regex4)
            if self.conf['proto6_enabled']:
                if src_name == "banlist" and not self.conf['oklistonly']:
                    self._prep_list('banlist_6', regex6)
                elif src_name == "oklist":
                    self._prep_list('oklist_6', regex6)


    def load_sets(self):
        """
        Load ipset configuration files generated by the prep_ methods.
        """
        self.conf['load_counts'] = {}
        for set_file in Path(self.conf['tmpdir']).glob("*.set"):
            logger.debug(set_file)
            if _filetest(set_file) and self.ipset_create(set_file) == 0 and self.ipset_restore(set_file) == 0:
                self.iptables_insert(set_file.stem)
                trgtgz = os.path.join(self.conf['backupdir'], f"{set_file.stem}.gz")
                logger.debug("backing up %s to %s", set_file.as_posix(), trgtgz)
                try:
                    with open(set_file, 'r', encoding='utf8') as infile:
                        with gzip.open(trgtgz, 'wb') as outfile:
                            for line in infile:
                                output.write(line)
                except Exception as err: # pylint: disable=W0703
                    logger.error(err)
                set_file.unlink()
                self.conf['load_counts'][set_file.stem] = self.ipset_get_counts(set_file.stem)[0]


    def ipset_query(self):
        """
        Query ipsets for certain IP.
        """
        match = False

        if not self.conf['param']:
            print("Missing search term, please submit a single ip or mac address\n")
            return

        query_start = datetime.datetime.now()
        print(f"search '{self.conf['param']}' in banIP related IPSets")

        logger.debug("local config: %r", self.conf['localsources'])
        logger.debug("remote sets: %r", self.conf['sources'])
        logger.debug("extras: %r", self.conf['extrasources'])
        for src in self.conf['localsources'] + self.conf['sources'] + self.conf['extrasources']:
            cmd = [self.conf['ipset_cmd'], '-q', '-n', 'list', src]
            logger.debug(cmd)
            cpc = run(cmd, check=False, capture_output=True)
            if src == "maclist" and len(cpc.stdout) > 0:
                cmd = [self.conf['ipset_cmd'], '-q', 'test', src, self.conf['param']]
                logger.debug(cmd)
                cpc = run(cmd, check=False, capture_output=True)
                if cpc.returncode == 0:
                    match = True
                    print(f"  - found in IPSet '{src}'\n")
                    break
            else:
                for proto in ("4", "6"):
                    val = f"{src}_{proto}"
                    cmd = [self.conf['ipset_cmd'], '-q', '-n', 'list', val]
                    logger.debug(cmd)
                    cpc = run(cmd, check=False, capture_output=True)
                    if len(cpc.stdout) > 0:
                        cmd = [self.conf['ipset_cmd'], '-q', 'test', val, self.conf['param']]
                        logger.debug(cmd)
                        cpc = run(cmd, check=False, capture_output=True)
                        if cpc.returncode == 0:
                            match = True
                            print(f"  - found in IPSet '{src}_{proto}'")
            query_end = datetime.datetime.now()
            if query_end - query_start > datetime.timedelta(seconds=self.conf['query_timeout']):
                print("  - [...]\n")
                break
        if not match:
            print("  - no match\n")


    def _report_getcntpackets(self, src):
        """
        Extract info from ipset for the given set.
        """
        cpc = self._ipset_cmd(['-q', 'list', src])
        if len(cpc.stdout) == 0:
            return 0, 0, 0, []
        m1 = re.compile(r"/[0-9]{1,3} ")
        cnt = cnt_acc = cnt_cidr = 0
        rval = []
        for line in cpc.stdout.split("\n"):
            if line.startswith('Number of entries:'):
                cnt = int(line.split(' ')[3])
                logger.debug("%d entries", cnt)
            if m1.search(line):
                logger.debug("CIDR match")
                cnt_cidr += 1
            parts = line.split(' ')
            try:
                pos = parts.index('packets')
            except ValueError:
                continue
            logger.debug("packet match")
            cnt_acc += 1
            rval.append([parts[0], parts[pos + 1]])
        return cnt, cnt_acc, cnt_cidr, rval


    def _report_content(self, jout): # pylint: disable=R0201
        """
        Output preparation.
        """
        rval = [":::\n::: report on all banIP related IPSets\n:::",
                f"Report timestamp           ::: {jout['timestamp']}",
                f"Number of all IPSets       ::: {jout['cnt_set_sum']}",
                f"Number of all entries      ::: {jout['cnt_sum']}",
                f"Number of IP entries       ::: {jout['cnt_ip_sum']}",
                f"Number of CIDR entries     ::: {jout['cnt_cidr_sum']}",
                f"Number of MAC entries      ::: {jout['cnt_mac_sum']}",
                f"Number of accessed entries ::: {jout['cnt_acc_sum']}"]
        if jout['ipsets']:
            rval.extend([":::\n::: IPSet details\n:::",
                         f"{'Name':>25s}{'Type':>12}{'Count':>11}{'Cnt_IP':>10}{'Cnt_CIDR':>10}" \
                         f"{'Cnt_MAC':>10}{'Cnt_ACC':>10} Entry details (Entry/Count)",
                         "    " + "-" * 116])
            for ipset, data in jout['ipsets'].items():
                rval.append(f"{ipset:>25}{data['type']:>12}{data['count']:>11}{data['count_ip']:>10}"
                            f"{data['count_cidr']:>10}{data['count_mac']:>10}{data['count_acc']:>10}")
                if data['member_acc']:
                    rval.append(' ' * 88 + f"{' '.join(data['member_acc']):>25}")
        return rval


    def _report_output(self, jout):
        """
        Send the report to a file, email, or display.
        """
        report_json = f"{self.conf['reportdir']}/ban_report.json"
        report_txt = f"{self.conf['reportdir']}/ban_mailreport.txt"
        logger.debug("action: %r, report_json: %r, report_txt: %r", self.conf['param'], report_json, report_txt)
        if self.conf['param'] == "json":
            print(json.dumps(jout, sort_keys=True, indent=2))
            return
        if  self.conf['chain'] in self.conf['ipt4_savecmd'] or self.conf['chain'] in self.conf['ipt6_savecmd']:
            # What's the point of this ^ test?
            with open(report_json, 'w', encoding='utf8') as outj:
                json.dump(jout, outj)
        content = self._report_content(jout)
        # why are we always writing this file?
        with open(report_txt, 'w', encoding='utf8') as outf:
            outf.write("\n".join(content))
        if self.conf['param'] == "cli":
            print("\n".join(content))
        elif self.conf['mail_enabled']:
            logger.warning("mail not implemented yet")
            #and -x self.conf['mailservice']:
            #(conf['mailservice'] "${content}" >/dev/null 2>&1) &
            #bg_pid="${!}"


    def ipset_report(self):
        """
        Generate statistics.
        """
        cnt_set_sum = 0

        # build data set
        jout = {'ipsets': {}}
        cnt_mac = cnt_acc_sum = cnt_mac_sum = cnt_ip_sum = cnt_cidr_sum = cnt_sum = 0
        logger.debug("local config: %r", self.conf['localsources'])
        logger.debug("remote sets: %r", self.conf['sources'])
        logger.debug("extras: %r", self.conf['extrasources'])
        for src in self.conf['localsources'] + self.conf['sources'] + self.conf['extrasources']:
            if src in self.conf['extrasources']:
                set_type = "n/a"
            else:
                set_type = self._gettype(src)
            if src == "maclist":
                cnt, cnt_acc, cnt_cidr, src_list = self._report_getcntpackets(src)
                cnt_acc_sum += cnt_acc
                cnt_mac = cnt_mac_sum = cnt
                cnt_sum += cnt
                if cnt > 0:
                    jout['ipsets'][src] = {'type': set_type,
                                           'count': cnt,
                                           'count_ip': 0,
                                           'count_cidr': 0,
                                           'count_mac': cnt,
                                           'count_acc': cnt_acc,
                                           'member_acc': []}
                    for val in src_list:
                        jout['ipsets'][src]['member_acc'].append({'member': val[0],
                                                                  'packets': val[1]})
                cnt_set_sum += 1
            else:
                for proto in ("4", "6"):
                    key = f"{src}_{proto}"
                    cnt, cnt_acc, src_list, _ = self._report_getcntpackets(key)
                    if cnt > 0:
                        cnt, cnt_acc, cnt_cidr, src_list = self._report_getcntpackets(key)
                        cnt_acc_sum += cnt_acc
                        cnt_mac_sum = cnt
                        cnt_sum += cnt
                        cnt_ip = cnt - cnt_cidr - cnt_mac
                        cnt_ip_sum += cnt_ip
                        cnt_cidr_sum += cnt_cidr
                        jout['ipsets'][key] = {'type': set_type,
                                               'count': cnt,
                                               'count_ip': cnt_ip,
                                               'count_cidr': cnt_cidr,
                                               'count_mac': 0,
                                               'count_acc': cnt_acc,
                                               'member_acc': []}
                        for val in src_list:
                            jout['ipsets'][src]['member_acc'].append({'member': val[0],
                                                                      'packets': val[1]})
                    cnt_set_sum += 1
        jout['timestamp'] = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        jout['cnt_set_sum'] = cnt_set_sum
        jout['cnt_ip_sum'] = cnt_ip_sum
        jout['cnt_cidr_sum'] = cnt_cidr_sum
        jout['cnt_mac_sum'] = cnt_mac_sum
        jout['cnt_sum'] = cnt_sum
        jout['cnt_acc_sum'] = cnt_acc_sum
        self._report_output(jout)


    def ipset_exporter(self):
        """
        Run a web server that makes ipsets/iptables metrics available.

        Output on /metrics path will look like:

        # HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
        # TYPE promhttp_metric_handler_requests_in_flight gauge
        promhttp_metric_handler_requests_in_flight 1
        # HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
        # TYPE promhttp_metric_handler_requests_total counter
        promhttp_metric_handler_requests_total{code="200"} 270854
        promhttp_metric_handler_requests_total{code="500"} 0


        All other paths will return 404.
        """
        server_address = (self.conf['exporter_host'], self.conf['exporter_port'])
        httpd = ThreadingHTTPServer(server_address, PromMetrics)
        httpd.server = self
        httpd.serve_forever()


    def _main_list_output(self, part): # pylint: disable=R0201
        """
        Turn awk print statements into something Python can do.

        print \"add drop_6 \"$1}", -> ["add drop_r ", 1]
        print \"add dshield_4 \"$1 \"/\"$3}", -> ["add dshield_4 ", 1,  "/", 3]
        """
        rval = []
        parts = part.split('}')[0].split('"')
        logger.debug(parts)
        for ii in parts[1:]:
            if ii.startswith('$'):
                rval.append(int(ii[1:]))
            else:
                rval.append(ii)
        logger.debug(rval)
        return rval


    def _main_list_sources(self):
        """
        Load JSON formated list of address lst sources, then parse the awk patterns into python style regexes.
        """
        with open(self.conf['srcfile'], 'r', encoding='utf8') as sources:
            srcs = json.load(sources)
        for key in srcs:
            for rule in ('rule_4', 'rule_6'):
                if rule not in srcs[key]:
                    continue
                parts = srcs[key][rule].split('/{')
                append = []
                if parts[0].startswith('BEGIN'):
                    sub = parts[0].split('/', 1)
                    logger.debug(sub)
                    append = sub[0].split('{', 1)[1].split('}', 1)[0].split('=')
                    append[1] = append[1].strip('"')
                    parts[0] = '/' + sub[1]
                srcs[key][rule] = [parts[0][1:], self._main_list_output(parts[1]), append]
        logger.debug("sources: %s", pformat(srcs))
        return srcs


    def main(self):
        """
        Update ipsets.
        """
        if self.conf['action'] in ('start', 'download', 'refresh'):
            srcs = self._main_list_sources()
            self.download_remote(srcs)
            if self.conf['action'] in ('start', 'refresh'):
                if self.conf['action'] == 'start':
                    try:
                        self.iptables_create()
                    except RuntimeError as rerr:
                        logger.fatal(rerr)
                        sys.exit(1)
                self.prep_remote(srcs)
                self.prep_local()
                self.load_sets()
            if 'load_counts' in self.conf:
                sets = len(self.conf['load_counts'])
                count = sum(self.conf['load_counts'].values())
                logger.info("%d IPSets with overall %d IPs/Prefixes loaded successfully", sets, count)
        else:
            getattr(self, f"ipset_{self.conf['action']}")()


class PromMetrics(BaseHTTPRequestHandler):
    """
    Implement do_GET to return metrics at the /metrics path, otherwise 404.
    """
    def _output(self, name, rval, pcount, bcount, ccount): # pylint: disable=R0201
        """
        Add to the content to be sent to Prometheus.
        """
        rval.append("# HELP banIPs_blocked_packets Total number of packets blocked by the set")
        rval.append("# TYPE banIPs_blocked_backets counter")
        rval.append(f'banIPs_blocked_packets{{ipset="{name}"}} {pcount}')
        rval.append("# HELP banIPs_blocked_bytes Total number of bytes blocked by the set")
        rval.append("# TYPE banIPs_blocked_bytes counter")
        rval.append(f'banIPs_blocked_bytes{{ipset="{name}"}} {bcount}')
        if ccount:
            rval.append("# HELP banIPs_blocked_packets_by_region"
                        " Total number of packets from the country and region")
            rval.append("# TYPE banIPs_blocked_backets_by_region counter")
            for key, val in ccount.items():
                rval.append(f'banIPs_blocked_packets_by_region{{ipset="{name}",'
                            f'country_code="{key[0]}",region_code="{key[1]}"}} {val}')
            ccount.clear()

    def do_GET(self):
        """
        If the request path is /metrics, return blocked address counts.
        """
        if self.path != '/metrics':
            self.send_error(404)
            return
        rval = []
        geo4 = pygeoip.GeoIP(self.server.conf['geoip4']) if GEOIP and self.server.conf['geoip4'] else None
        geo6 = pygeoip.GeoIP(self.server.conf['geoip6']) if GEOIP and self.server.conf['geoip6'] else None
        cmd = [self.server.conf['ipset_cmd'], '-q', 'list']
        cpc = run(cmd, check=False, capture_output=True, text=True)
        if cpc.returncode == 0:
            first = True
            pcount = bcount = 0
            ccount = {}
            for line in cpc.stdout.split("\n"):
                parts = line.strip().split(' ')
                if parts[0] == 'Name:':
                    if not first:
                        self._output(parts[1], rval, pcount, bcount, ccount)
                        pcount = bcount = 0
                        first = False
                if parts[1] == 'packets':
                    pcount += int(parts[2])
                    bcount += int(parts[4])
                    if geo4 and '.' in parts[0]:
                        rec = geo4.record_by_addr(parts[0])
                    if geo6 and ':' in parts[0]:
                        rec = geo6.record_by_addr(parts[0])
                    key = (rec['country_code'], rec['region_code'])
                    if key not in ccount:
                        ccount[key] = 0
                    ccount[key] += int(parts[2])
            if not first:
                self._output(parts[1], rval, pcount, bcount, ccount)
        self.send_response(200, message='\n'.join(rval))
        self.end_headers()


if __name__ == '__main__':
    import argparse
    m_parser = argparse.ArgumentParser(description='Load configured ipsets')
    m_parser.add_argument('-D', '--debug', action='store_true')
    m_parser.add_argument('-V', '--verbose', action='store_true')
    m_parser.add_argument('-b', '--banip', action='store_true',
                          help='OpenWRT banip format configuration file pointed to by -c')
    m_parser.add_argument('-c', '--config', default='/etc/banips/banips.conf',
                          help='INI style configuration file')
    m_parser.add_argument('-s', '--srcfile', default=DEFS['srcfile'],
                          help='JSON IP source list')
    m_parser.add_argument('-S', '--skip', action='store_true',
                          help='Skip downloading, if the target file exists')
    m_parser.add_argument('-K', '--keep', action='store_true',
                          help='Keep downloaded files for use with -S')
    m_parser.add_argument('action', metavar='A', type=str, nargs='?',
                          default=DEFS['action'], choices=COMMANDS,
                          help=f"What to do. One of: {'|'.join(COMMANDS)}")
    m_parser.add_argument('param', metavar='P', type=str, nargs='?',
                          help="required IP address for a query; optional type of report;" \
                          " optional name of a set to refresh, suspend, resume, restore_backup, or remove_backup")
    m_args = m_parser.parse_args()
    if m_args.debug:
        logger.setLevel(logging.DEBUG)
    elif m_args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    m_banips = BanIPs(vars(m_args))
    m_banips.main()
