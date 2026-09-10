#!/usr/bin/env python3
"""Generate the supported SNMP object manifest. This is not an SNMP agent."""
from pathlib import Path
import csv

OUT = Path(__file__).resolve().parent/'mib-coverage.csv'
FIELDS = ['module','object','base_oid','syntax','mib_max_access','release_access','instance_index','value_source','formal_projection','reference']
WRITABLE = {'dot1qVlanForbiddenEgressPorts', 'dot1qVlanStaticName', 'ifAdminStatus', 'dot1qVlanStaticUntaggedPorts', 'dot1qVlanStaticEgressPorts', 'dot1qVlanStaticRowStatus', 'dot1qPvid', 'dot1xPaePortInitialize', 'dot1xPaePortReauthenticate', 'dot1xAuthAuthControlledPortControl'}
rows = []
def add(module,name,oid,syntax,idx,source,formal='outside-core',access='read-only'):
    refs={'SNMPv2-MIB':'RFC3418','IF-MIB':'RFC2863','BRIDGE-MIB':'RFC4188','Q-BRIDGE-MIB':'RFC4363','ENTITY-MIB':'RFC6933','IEEE8021-PAE-MIB':'IEEE8021-PAE-MIB 200406220000Z'}
    implemented = access if name in WRITABLE else 'not-readable-index' if access=='not-accessible' else 'read-only'
    if name in WRITABLE and module != 'IEEE8021-PAE-MIB':
        formal = formal.split(';')[0] + '; SetTransactions'
    rows.append(dict(zip(FIELDS,(module,name,oid,syntax,access,implemented,idx,source,formal,refs[module]))))

sys = '1.3.6.1.2.1.1'
for col,name,syntax,source,access in [
    (1,'sysDescr','DisplayString (0..255 octets)','Generic project identity and software version','read-only'),
    (2,'sysObjectID','OBJECT IDENTIFIER','Validated operator-configured identity.sys_object_id; public default null gates SNMP; explicit isolated-development override only','read-only'),
    (3,'sysUpTime','TimeTicks','Real management uptime modulo 2^32; not simulation time','read-only'),
    (4,'sysContact','DisplayString (0..255 octets)','Saved contact','read-write'),
    (5,'sysName','DisplayString (0..255 octets)','Saved switch name','read-write'),
    (6,'sysLocation','DisplayString (0..255 octets)','Saved location','read-write'),
    (7,'sysServices','INTEGER (0..127)','2: simulated layer-2 service','read-only'),
]: add('SNMPv2-MIB',name,f'{sys}.{col}',syntax,'0',source,access=access)

add('IF-MIB','ifNumber','1.3.6.1.2.1.2.1','Integer32','0','Configured physical interface count')
base='1.3.6.1.2.1.2.2.1'
for col,name,syntax,source,formal,access in [
 (1,'ifIndex','InterfaceIndex','Stable positive interface index','IfTable','read-only'),
 (2,'ifDescr','DisplayString','Configured physical interface description','outside-core','read-only'),
 (3,'ifType','IANAifType','ethernetCsmacd(6)','outside-core','read-only'),
 (4,'ifMtu','Integer32','Configured interface MTU','outside-core','read-only'),
 (5,'ifSpeed','Gauge32','Operational speed capped at 4294967295; zero when down','outside-core','read-only'),
 (6,'ifPhysAddress','PhysAddress','Stable simulated per-port MAC','outside-core','read-only'),
 (7,'ifAdminStatus','INTEGER','up(1) or down(2); valid RFC testing(3) is unsupported in this profile','IfTable','read-write'),
 (8,'ifOperStatus','INTEGER','up(1) or down(2) from modeled link state','IfTable','read-only'),
 (9,'ifLastChange','TimeTicks','Management-uptime timestamp of last operational transition; zero at boot','outside-core','read-only'),
 (10,'ifInOctets','Counter32','Low 32 bits of simulated ingress octets','outside-core','read-only'),
 (11,'ifInUcastPkts','Counter32','Low 32 bits of admitted simulated ingress unicast frames','outside-core','read-only'),
 (13,'ifInDiscards','Counter32','Simulated ingress admission drops','outside-core','read-only'),
 (14,'ifInErrors','Counter32','Zero: no physical error generator in first release','outside-core','read-only'),
 (16,'ifOutOctets','Counter32','Zero: no output traffic simulation','outside-core','read-only'),
 (17,'ifOutUcastPkts','Counter32','Zero: no output traffic simulation','outside-core','read-only'),
 (19,'ifOutDiscards','Counter32','Zero: no output traffic simulation','outside-core','read-only'),
 (20,'ifOutErrors','Counter32','Zero: no output traffic simulation','outside-core','read-only'),
]: add('IF-MIB',name,f'{base}.{col}',syntax,'ifIndex',source,formal,access)
base='1.3.6.1.2.1.31.1.1.1'
for col,name,syntax,source,access in [
 (1,'ifName','DisplayString','Stable interface name','read-only'),
 (6,'ifHCInOctets','Counter64','Simulated ingress octets','read-only'),
 (7,'ifHCInUcastPkts','Counter64','Admitted simulated ingress unicast frames','read-only'),
 (10,'ifHCOutOctets','Counter64','Zero: no output traffic simulation','read-only'),
 (11,'ifHCOutUcastPkts','Counter64','Zero: no output traffic simulation','read-only'),
 (14,'ifLinkUpDownTrapEnable','INTEGER','enabled(1) or disabled(2), configured through API','read-write'),
 (15,'ifHighSpeed','Gauge32','Operational speed in millions of bits/second; zero when down','read-only'),
 (17,'ifConnectorPresent','TruthValue','true(1): simulated physical port','read-only'),
 (18,'ifAlias','DisplayString (0..64 octets)','Saved interface alias','read-write'),
 (19,'ifCounterDiscontinuityTime','TimeStamp','Management uptime at latest counter reset; zero at boot','read-only'),
]: add('IF-MIB',name,f'{base}.{col}',syntax,'ifIndex',source,access=access)

base='1.3.6.1.2.1.17'
for suffix,name,syntax,source,formal,access in [
 ('1.1','dot1dBaseBridgeAddress','MacAddress','Configured bridge base MAC','outside-core','read-only'),
 ('1.2','dot1dBaseNumPorts','Integer32','Configured bridge-port count','outside-core','read-only'),
 ('1.3','dot1dBaseType','INTEGER','transparent-only(2)','outside-core','read-only'),
 ('4.1','dot1dTpLearnedEntryDiscards','Counter32','Learning-capacity rejection events since boot','outside-core','read-only'),
 ('4.2','dot1dTpAgingTime','Integer32 (10..1000000)','Configured age in simulated seconds','AgingTicks abstraction','read-write'),
]: add('BRIDGE-MIB',name,f'{base}.{suffix}',syntax,'0',source,formal,access)
for col,name,syntax,source in [
 (1,'dot1dBasePort','Integer32 (1..65535)','Stable bridge-port number'),
 (2,'dot1dBasePortIfIndex','InterfaceIndex','Explicit bridge-port to ifIndex mapping'),
]: add('BRIDGE-MIB',name,f'{base}.1.4.1.{col}',syntax,'bridgePort',source,'Dot1dBasePortTable')
for col,name,syntax,source in [
 (1,'dot1dTpFdbAddress','MacAddress','Learned MAC in selected legacy VLAN/FDB'),
 (2,'dot1dTpFdbPort','Integer32 (0..65535)','Learned bridge port; live rows never zero in this release'),
 (3,'dot1dTpFdbStatus','INTEGER','learned(3)'),
]: add('BRIDGE-MIB',name,f'{base}.4.3.1.{col}',syntax,'mac[6] (fixed-length, no length prefix)',source,'Dot1dTpFdbTable')

base='1.3.6.1.2.1.17.7.1'
for suffix,name,syntax,source,formal,access in [
 ('1.1','dot1qVlanVersionNumber','INTEGER','version1(1)','outside-core','read-only'),
 ('1.2','dot1qMaxVlanId','VlanId (Integer32 1..4094)','4094','outside-core','read-only'),
 ('1.3','dot1qMaxSupportedVlans','Unsigned32','4094','outside-core','read-only'),
 ('1.4','dot1qNumVlans','Unsigned32','Current configured VLAN inventory count','s.vlans','read-only'),
 ('1.5','dot1qGvrpStatus','EnabledStatus','disabled(2): no dynamic registration','outside-core','read-write'),
 ('4.1','dot1qVlanNumDeletes','Counter32','Number of successful VLAN deletions since management boot','outside-core','read-only'),
]: add('Q-BRIDGE-MIB',name,f'{base}.{suffix}',syntax,'0',source,formal,access)
add('Q-BRIDGE-MIB','dot1qFdbId',f'{base}.2.1.1.1','Unsigned32 (1..4294967295)','fdbId','FDB index only','Dot1qFdbTable',access='not-accessible')
add('Q-BRIDGE-MIB','dot1qFdbDynamicCount',f'{base}.2.1.1.2','Counter32','fdbId','Number of live dynamic entries in the FDB','Dot1qFdbTable')
for col,name,syntax,source,access in [
 (1,'dot1qTpFdbAddress','MacAddress','MAC part of index only','not-accessible'),
 (2,'dot1qTpFdbPort','Integer32 (0..65535)','Learned bridge port; live rows never zero in this release','read-only'),
 (3,'dot1qTpFdbStatus','INTEGER','learned(3)','read-only'),
]: add('Q-BRIDGE-MIB',name,f'{base}.2.2.1.{col}',syntax,'fdbId.mac[6] (fixed-length, no length prefix)',source,'Dot1qTpFdbTable',access)
for col,name,syntax,source,access in [
 (1,'dot1qVlanTimeMark','TimeFilter','Query filter index only; not the last-change timestamp','not-accessible'),
 (2,'dot1qVlanIndex','VlanIndex','VID part of index only','not-accessible'),
 (3,'dot1qVlanFdbId','Unsigned32','Stable distinct VLAN-to-FDB mapping','read-only'),
 (4,'dot1qVlanCurrentEgressPorts','PortList','Configured membership plus current authorized client VLAN membership; saved membership remains independent','read-only'),
 (5,'dot1qVlanCurrentUntaggedPorts','PortList','Independent configured untagged memberships; not derived from PVID','read-only'),
 (6,'dot1qVlanStatus','INTEGER','permanent(2)','read-only'),
 (7,'dot1qVlanCreationTime','TimeTicks','Creation in management uptime epoch','read-only'),
]: add('Q-BRIDGE-MIB',name,f'{base}.4.2.1.{col}',syntax,'timeFilter.vid',source,'Dot1qVlanCurrentTable; filter/timestamps outside-core',access)
for col,name,syntax,source in [
 (1,'dot1qVlanStaticName','SnmpAdminString (0..32 octets)','Saved VLAN name'),
 (2,'dot1qVlanStaticEgressPorts','PortList','Configured memberships'),
 (3,'dot1qVlanForbiddenEgressPorts','PortList','Independent configured forbidden memberships; disjoint from admitted'),
 (4,'dot1qVlanStaticUntaggedPorts','PortList','Independent configured untagged memberships; not derived from PVID'),
 (5,'dot1qVlanStaticRowStatus','RowStatus','GET active(1); SET active(1)/createAndGo(4)/destroy(6); permanent VLAN1'),
]: add('Q-BRIDGE-MIB',name,f'{base}.4.3.1.{col}',syntax,'vid',source,'Dot1qVlanStaticTable; name/forbidden outside-core','read-create')
for col,name,syntax,source,formal in [
 (1,'dot1qPvid','VlanIndex','Ingress VLAN classification; raw SET preserves untagged egress memberships','Dot1qPvid'),
 (2,'dot1qPortAcceptableFrameTypes','INTEGER','admitAll(1); source supports untagged and one explicit VID','outside-core'),
 (3,'dot1qPortIngressFiltering','TruthValue','true(1): unadmitted VLAN activity is rejected','Eligible/Admitted'),
 (4,'dot1qPortGvrpStatus','EnabledStatus','disabled(2): no dynamic registration','outside-core'),
]: add('Q-BRIDGE-MIB',name,f'{base}.4.5.1.{col}',syntax,'bridgePort',source,formal,'read-write')

base="1.3.6.1.2.1.47"
for column, (name, syntax, access, source) in enumerate([
    ('entPhysicalIndex', 'PhysicalIndex (Integer32 1..2147483647)', 'not-accessible', 'Index only; chassis1 and bridgePort+1'),
    ('entPhysicalDescr', 'SnmpAdminString (0..255 octets)', 'read-only', 'Saved switch description; Emulated Ethernet port for ports; UTF-8'),
    ('entPhysicalVendorType', 'AutonomousType (OBJECT IDENTIFIER)', 'read-only', '0.0: unknown registration'),
    ('entPhysicalContainedIn', 'PhysicalIndexOrZero (Integer32)', 'read-only', 'Chassis0; ports1'),
    ('entPhysicalClass', 'IANAPhysicalClass (INTEGER)', 'read-only', 'chassis(3) or port(10)'),
    ('entPhysicalParentRelPos', 'Integer32 (-1..2147483647)', 'read-only', 'Chassis-1; saved bridgePort for ports'),
    ('entPhysicalName', 'SnmpAdminString (0..255 octets)', 'read-only', 'Saved switch or port name; UTF-8'),
    ('entPhysicalHardwareRev', 'SnmpAdminString (0..255 octets)', 'read-only', 'Empty: unknown hardware revision'),
    ('entPhysicalFirmwareRev', 'SnmpAdminString (0..255 octets)', 'read-only', 'Empty: unknown firmware revision'),
    ('entPhysicalSoftwareRev', 'SnmpAdminString (0..255 octets)', 'read-only', 'Empty: unknown inventory software revision'),
    ('entPhysicalSerialNum', 'SnmpAdminString (0..32 octets)', 'read-write', 'Empty: no serial inventory'),
    ('entPhysicalMfgName', 'SnmpAdminString (0..255 octets)', 'read-only', 'Empty: unknown manufacturer'),
    ('entPhysicalModelName', 'SnmpAdminString (0..255 octets)', 'read-only', 'Empty: unknown model'),
    ('entPhysicalAlias', 'SnmpAdminString (0..32 octets)', 'read-write', 'Empty; independent of the saved 64-octet ifAlias'),
    ('entPhysicalAssetID', 'SnmpAdminString (0..32 octets)', 'read-write', 'Empty: no physical asset setting'),
    ('entPhysicalIsFRU', 'TruthValue (INTEGER)', 'read-only', 'false(2): no emulated replacement mechanism'),
    ('entPhysicalMfgDate', 'DateAndTime (8 or 11 octets)', 'read-only', 'Eight binary zero octets: unknown'),
    ('entPhysicalUris', 'OCTET STRING (URI list)', 'read-write', 'urn:uuid from persisted entity UUID; empty for non-UUID IDs'),
    ('entPhysicalUUID', 'UUIDorZero (0 or 16 octets)', 'read-only', 'Persisted UUID in 16-byte network order; empty for non-UUID IDs'),
], 1):
    add('ENTITY-MIB',name,f'{base}.1.1.1.1.{column}',syntax,'physicalIndex',source,
        'EntPhysicalTable; EntityInventory',access)
add('ENTITY-MIB','entAliasLogicalIndexOrZero','1.3.6.1.2.1.47.1.3.2.1.1','Integer32 (0..2147483647)','physicalIndex.logicalIndex','Index only; wildcard logicalIndex0','EntAliasMappingTable','not-accessible')
add('ENTITY-MIB','entAliasMappingIdentifier','1.3.6.1.2.1.47.1.3.2.1.2','RowPointer (OBJECT IDENTIFIER)','physicalIndex.0','Port pointer to ifIndex instance; filtering applies to pointer OID without dereference privilege','EntAliasMappingTable; EntityInventory','read-only')
add('ENTITY-MIB','entPhysicalChildIndex','1.3.6.1.2.1.47.1.3.3.1.1','PhysicalIndex (Integer32)','1.physicalPortIndex','Direct chassis-to-port edges; child index is readable','EntPhysicalContainsTable','read-only')
add('ENTITY-MIB','entLastChangeTime','1.3.6.1.2.1.47.1.4.1','TimeStamp (TimeTicks)','0','Actual projected-row change time; zero on management reboot; retained across uptime wrap and irrelevant/no-op/rejected changes','EntityInventory','read-only')

base='1.0.8802.1.1.1.1'
for suffix,name,syntax,source,access in [
 ('1.1','dot1xPaeSystemAuthControl','INTEGER (1..2)','enabled(1); no new global bypass owner','read-write'),
 ('1.2.1.2','dot1xPaePortProtocolVersion','Unsigned32','Actual observed EAPOL version; absent before an event','read-only'),
 ('1.2.1.3','dot1xPaePortCapabilities','BITS','Authenticator bit only:80 hex','read-only'),
 ('1.2.1.4','dot1xPaePortInitialize','TruthValue','True requests one completed port initialization; GET false; counters not reset','read-write'),
 ('1.2.1.5','dot1xPaePortReauthenticate','TruthValue','True requests port-wide renewal; GET false; valid access retained while pending','read-write'),
 ('2.1.1.1','dot1xAuthPaeState','INTEGER (1..10)','Represented authenticator state from actual events; auto/multi-auth and unmapped local outcomes omitted','read-only'),
 ('2.1.1.2','dot1xAuthBackendAuthState','INTEGER (1..8)','Represented backend state, not server reachability; ambiguous/unmapped instances omitted','read-only'),
 ('2.1.1.3','dot1xAuthAdminControlledDirections','INTEGER (0..1)','in(1); no egress enforcement','read-write'),
 ('2.1.1.4','dot1xAuthOperControlledDirections','INTEGER (0..1)','in(1)','read-only'),
 ('2.1.1.5','dot1xAuthAuthControlledPortStatus','INTEGER (1..2)','Actual effective service authorization, independent of carrier; auto/multi-auth omitted','read-only'),
 ('2.1.1.6','dot1xAuthAuthControlledPortControl','INTEGER (1..3)','forceUnauthorized1/auto2/forceAuthorized3 in the final candidate','read-write'),
 ('2.1.1.12','dot1xAuthReAuthPeriod','Unsigned32','Effective timer constant, server override versus local; not remaining time; auto/multi-auth omitted','read-write'),
 ('2.1.1.13','dot1xAuthReAuthEnabled','TruthValue','Actual effective reauthentication enablement; server zero period can be enabled','read-write'),
 ('2.1.1.14','dot1xAuthKeyTxEnabled','TruthValue','false(2); no EAPOL-Key/MACsec transmission','read-write'),
]:
 add('IEEE8021-PAE-MIB',name,f'{base}.{suffix}',syntax,'0' if suffix=='1.1' else 'ifIndex',source,'RadiusAuthorization; concrete PAE mapping',access)
for column,name,source in [
 (1,'dot1xAuthEapolFramesRx','Actual internal peer-to-NAS EAPOL frames'),
 (2,'dot1xAuthEapolFramesTx','Actual internal NAS-to-peer EAPOL frames'),
 (3,'dot1xAuthEapolStartFramesRx','Actual EAPOL-Start receive events'),
 (4,'dot1xAuthEapolLogoffFramesRx','Actual EAPOL-Logoff receive events; traffic-off is not Logoff'),
 (5,'dot1xAuthEapolRespIdFramesRx','Actual EAP-Response/Identity receive events'),
 (6,'dot1xAuthEapolRespFramesRx','Actual other EAP-Response receive events'),
 (7,'dot1xAuthEapolReqIdFramesTx','Actual EAP-Request/Identity transmit events'),
 (8,'dot1xAuthEapolReqFramesTx','Actual other EAP-Request transmit events'),
]:add('IEEE8021-PAE-MIB',name,f'{base}.2.2.1.{column}','Counter32','ifIndex',source+'; aggregate omitted after incomplete observation until management boot')
add('IEEE8021-PAE-MIB','dot1xAuthLastEapolFrameVersion',f'{base}.2.2.1.11','Unsigned32','ifIndex','Last actual received frame version; absent before receive or after observation loss')
add('IEEE8021-PAE-MIB','dot1xAuthLastEapolFrameSource',f'{base}.2.2.1.12','MacAddress (6 octets)','ifIndex','Last actual received frame source; absent before receive or after observation loss')
for column,name,source in [
 (3,'dot1xAuthEntersAuthenticating','CONNECTING to AUTHENTICATING on actual EAP-Response/Identity'),
 (4,'dot1xAuthAuthSuccessWhileAuthenticating','AUTHENTICATING to AUTHENTICATED on backend success'),
 (5,'dot1xAuthAuthTimeoutsWhileAuthenticating','AUTHENTICATING to ABORTING on exhausted backend response'),
 (6,'dot1xAuthAuthFailWhileAuthenticating','AUTHENTICATING to HELD on actual NAS Reject'),
]:add('IEEE8021-PAE-MIB',name,f'{base}.2.3.1.{column}','Counter32 (deprecated)','ifIndex',source+'; not inferred from peer exit; omitted after observation loss')
for column,name,syntax,source in [
 (1,'dot1xAuthSessionOctetsRx','Counter64','Current or last valid service admitted ingress octets'),
 (3,'dot1xAuthSessionFramesRx','Counter32','Current or last valid service admitted ingress frames'),
 (5,'dot1xAuthSessionId','SnmpAdminString (printable ASCII, at least3 octets)','Actual current or last valid session ID'),
 (6,'dot1xAuthSessionAuthenticMethod','INTEGER (1..2)','remoteAuthServer(1); not the EAP/MAB method code'),
 (7,'dot1xAuthSessionTime','TimeTicks','Simulated session duration in centiseconds modulo2^32; not SNMP uptime'),
 (8,'dot1xAuthSessionTerminateCause','INTEGER (1..7,999)','notTerminatedYet999 or exact PAE cause; unrepresentable ended causes omitted'),
]:add('IEEE8021-PAE-MIB',name,f'{base}.2.4.1.{column}',syntax,'ifIndex',source+'; before any session and auto/multi-auth omitted')

if __name__=='__main__':
    assert len({row['base_oid'] for row in rows}) == len(rows)
    assert len({row['object'] for row in rows}) == len(rows)
    with OUT.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS,lineterminator="\n")
        writer.writeheader();writer.writerows(rows)
    print(f'Wrote {len(rows)} objects to {OUT}')
