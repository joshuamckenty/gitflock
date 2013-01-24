from collections import namedtuple as NT
from datetime import datetime
import string
import re

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.smi import builder, view, error
from numpy import int64, float64

# NOTE!!!
# It is best to install the pysnmp-mibs package from pypi... this makes
# a lot of symbolic MIB names "just work"


# See this link below for many oneliner examples...
# http://pysnmp.sourceforge.net/examples/4.x/v3arch/oneliner/index.html

class v2c(object):
    """Build an SNMPv2c manager object"""
    def __init__(self, ipaddr=None, device=None, community='Public',
        retries=3, timeout=9):
        self.device = device
        self.ipaddr = ipaddr
        self.community = community
        self.SNMPObject = NT('SNMPObject', ['modName', 'datetime', 'symName',
            'index', 'value'])
        self.SNMPIndexed = NT('SNMPIndexed', ['modName', 'datetime', 'symName',
            'index', 'value'])
        self.query_timeout = float(timeout)/int(retries)
        self.query_retries = int(retries)
        self._index = None

        self.cmdGen = cmdgen.CommandGenerator()
        #mibBuilder = builder.MibBuilder()
        #mibPath = mibBuilder.getMibPath()+('/opt/python/Models/Network/MIBs',)
        #mibBuilder.setMibPath(*mibPath)
        #mibBuilder.loadModules(
        #    'RFC-1213',
        #    )
        #mibView = view.MibViewController(mibBuilder)

    def index(self, oid=None):
        """Build an SNMP Manager index to reference in get or walk operations.  First v2c.index('ifName').  Then, v2c.get_index('ifHCInOctets', 'eth0') or v2c.walk_index('ifHCInOctets').  Instead of referencing a numerical index, the index will refer to the value that was indexed."""
        self._index = dict()
        self._intfobj = dict()
        snmpidx = self.walk(oid=oid)
        for ii in snmpidx:
            ## the dicts below are keyed by the SNMP index number
            # value below is the text string of the intf name
            self._index[ii.index] = ii.value
            # value below is the intf object
            if not (self.device is None):
                self._intfobj[ii.index] = self.device.find_match_intf(ii.value,
                    enforce_format=False)

    def walk_index(self, oid=None):
        """Example usage, first index with v2c.index('ifName'), then v2c.get_index('ifHCInOctets', 'eth0')"""
        if not (self._index is None):
            tmp = list()
            snmpvals = self.walk(oid=oid)
            for idx, ii in enumerate(snmpvals):
                tmp.append([ii.modName, datetime.now(), ii.symName,
                    self._index[ii.index], ii.value])

            return map(self.SNMPIndexed._make, tmp)
        else:
            raise ValueError, "Must populate with SNMP.v2c.index() first"

    def walk(self, oid=None):
        if isinstance(self._format(oid), tuple):
            errorIndication, errorStatus, errorIndex, \
            varBindTable = self.cmdGen.nextCmd(
                        cmdgen.CommunityData('test-agent', self.community),
                        cmdgen.UdpTransportTarget((self.ipaddr, 161),
                        retries=self.query_retries,
                        timeout=self.query_timeout),
                        self._format(oid),
                    )
            # Parsing only for now... no return value...
            self._parse(errorIndication, errorStatus, errorIndex, varBindTable)
        elif isinstance(oid, str):
            errorIndication, errorStatus, errorIndex, \
                             varBindTable = self.cmdGen.nextCmd(
                # SNMP v2
                cmdgen.CommunityData('test-agent', self.community),
                # Transport
                cmdgen.UdpTransportTarget((self.ipaddr, 161)),
                (('', oid),),
                #cmdgen.MibVariable(oid).loadMibs(),
                )
            return self._parse_resolve(errorIndication, errorStatus,
                errorIndex, varBindTable)
        else:
            raise ValueError, "Unknown oid format: %s" % oid

    def get_index(self, oid=None, index=None):
        """In this case, index should be similar to the values you indexed from... i.e. if you index with ifName, get_index('ifHCInOctets', 'eth0')"""
        if not (self._index is None) and isinstance(index, str):
            # Map the interface name provided in index to an ifName index...
            snmpvals = None
            for idx, value in self._index.items():
                if index == value:
                    # if there is an exact match between the text index and the
                    # snmp index value...
                    snmpvals = self.get(oid=oid, index=idx)
                    break
            else:
                # TRY mapping the provided text index into an interface obj
                _intfobj = self.device.find_match_intf(index)
                if not (_intfobj is None):
                    for key, val in self._intfobj.items():
                        if (val==_intfobj):
                            snmpvals = self.get(oid=oid, index=key)
                            break

            # Ensure we only parse a valid response...
            if not (snmpvals is None):
                tmp = [snmpvals.modName, datetime.now(), snmpvals.symName,
                    self._index[snmpvals.index], snmpvals.value]
                return self.SNMPIndexed._make(tmp)

        elif not isinstance(index, str):
            raise ValueError, "index must be a string value"
        else:
            raise ValueError, "Must populate with SNMP.v2c.index() first"

    def get(self, oid=None, index=None):
        if isinstance(self._format(oid), tuple):
            errorIndication, errorStatus, errorIndex, \
            varBindTable = self.cmdGen.getCmd(
                        cmdgen.CommunityData('test-agent', self.community),
                        cmdgen.UdpTransportTarget((self.ipaddr, 161),
                        retries=self.query_retries,
                        timeout=self.query_timeout),
                        self._format(oid),
                    )
            # Parsing only for now... no return value...
            self._parse(errorIndication, errorStatus, errorIndex, varBindTable)
        elif isinstance(oid, str) and isinstance(index, int):
            errorIndication, errorStatus, errorIndex, \
                             varBindTable = self.cmdGen.getCmd(
                # SNMP v2
                cmdgen.CommunityData('test-agent', self.community),
                # Transport
                cmdgen.UdpTransportTarget((self.ipaddr, 161)),
                (('', oid), index),
                #cmdgen.MibVariable(oid).loadMibs(),
                )
            return self._parse_resolve(errorIndication, errorStatus,
                errorIndex, [varBindTable])[0]
        else:
            raise ValueError, "Unknown oid format: %s" % oid

    def bulkwalk(self, oid=None):
        """SNMP bulkwalk a device.  NOTE: This often is faster, but does not work as well as a simple SNMP walk"""
        if isinstance(self._format(oid), tuple):
            errorIndication, errorStatus, errorIndex, varBindTable = self.cmdGen.bulkCmd(
                        cmdgen.CommunityData('test-agent', self.community),
                        cmdgen.UdpTransportTarget((self.ipaddr, 161),
                        retries=self.query_retries,
                        timeout=self.query_timeout),
                0,
                25,
                self._format(oid),
                )
            return self._parse(errorIndication, errorStatus,
                errorIndex, varBindTable)
        elif isinstance(oid, str):
            errorIndication, errorStatus, errorIndex, varBindTable = self.cmdGen.bulkCmd(
                        cmdgen.CommunityData('test-agent', self.community),
                        cmdgen.UdpTransportTarget((self.ipaddr, 161),
                        retries=self.query_retries,
                        timeout=self.query_timeout),
                0,
                25,
                (('', oid),),
                #cmdgen.MibVariable(oid).loadMibs(),
                )
            return self._parse_resolve(errorIndication, errorStatus,
                errorIndex, varBindTable)
        else:
            raise ValueError, "Unknown oid format: %s" % oid

    def _parse_resolve(self, errorIndication=None, errorStatus=None,
        errorIndex=None, varBindTable=None):
        """Parse MIB walks and resolve into MIB names"""
        retval = list()
        if errorIndication:
            print errorIndication
        else:
            if errorStatus:
                print '%s at %s\n' % (
                    errorStatus.prettyPrint(),
                    varBindTable[-1][int(errorIndex)-1]
                    )
            else:
                for varBindTableRow in varBindTable:
                    for oid, val in varBindTableRow:
                        (symName, modName), indices = cmdgen.mibvar.oidToMibName(
                            self.cmdGen.mibViewController, oid
                            )
                        val = cmdgen.mibvar.cloneFromMibValue(
                            self.cmdGen.mibViewController, modName, symName,
                            val)
                        # Try to parse the index as an int first,
                        # then as a string
                        try:
                            index = int(string.join(map(lambda v: v.prettyPrint(), indices), '.'))
                        except ValueError:
                            index = str(string.join(map(lambda v: v.prettyPrint(), indices), '.'))

                        # Re-format values as float or integer, if possible...
                        tmp = val.prettyPrint()
                        if re.search(r"""^\s*\d+\s*$""", tmp):
                            value = int64(tmp)
                        elif re.search(r"""^\s*\d+\.\d+\s*$""", tmp):
                            value = float64(tmp)
                        else:
                            value = tmp

                        retval.append(self.SNMPObject._make([modName,
                            datetime.now(), symName, index, value]))
            return retval

    def _parse(self, errorIndication, errorStatus, errorIndex,
        varBindTable):
        if errorIndication:
           print errorIndication
        else:
            if errorStatus:
                print '%s at %s\n' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
                    )
            else:
                for varBindTableRow in varBindTable:
                    for name, val in varBindTableRow:
                        print '%s = %s' % (name.prettyPrint(), val.prettyPrint())

    def _format(self, oid):
        """Format a numerical OID in the form of 1.3.4.1.2.1 into a tuple"""
        if isinstance(oid, str):
            if re.search('(\d+\.)+\d+', oid):
                tmp = list()
                for ii in oid.split('.'):
                    tmp.append(int(ii))
                return tuple(tmp)
        else:
            return oid