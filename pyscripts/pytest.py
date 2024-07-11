__version__ = '$Revision: 202210141118$'

#### Python Imports ####
import os
import re
import xml.dom.minidom
import tempfile



#### DMA Imports ####
import dmapythonvariables as dma_vars
import discovery
import oracletools
import ostools
import steplog
import parametertools


io_params = parametertools.parse_dma_params()

SERVER_NAME = ''
# <dma api>
NC_USER = dma_vars.dma_user
NC_URL = dma_vars.dma_url
ORG_NAME = dma_vars.organization_name
DMA_TOKEN = r"""${DMA.Token}""".strip()
NC_PASSWORD = DMA_TOKEN
TRUST_SSL_CERTS = 'True'
SERVER_NAME = dma_vars.server_name
SERVER_BECOME_ROUTINE = r""" ${Server.Become Routine} """.strip()
SERVER_ID = dma_vars.server_id
ENVAPI_OVERWRITE = True
ENVAPI_WRITE = True
TRUST_SSL_CERTS = (TRUST_SSL_CERTS.upper() in ['TRUE', 'T', 'YES', 'Y', '1'])
# <end dma api>
IS_WIN = ostools.is_windows()
if SERVER_NAME in ['', ' ', None]:
    SERVER_NAME = ostools.get_full_hostname()
###############################################################################
#                      Windows Support                                        #
###############################################################################


DBLIST = []
DBS = []

SVCNAME = {}
ASM = {}
ORAHOME = {}
LASTPATCHID = {}
PSU = {}
OPATCH_VERSION = {}
ORACLEVERSION = {}
PORT = {}
TNSADMIN = {}

if IS_WIN:
    COMMAND = 'sc query state= all'
    OUTPUT = ostools.run_command(COMMAND)[0] 
    for line in OUTPUT.split("\n"):
        if line.find('OracleService') > -1:
            SVCNAME = line.split(":")[1].rstrip().strip()
            DB = line.split(":")[1].rstrip().strip().split('OracleService')[1]
            if not "%s:%s:False" % (DB, SVCNAME) in DBLIST:
                DBLIST.append('%s:%s:False' % (DB, SVCNAME))
                if line.find('OracleASMService') > -1:
                    SVCNAME = line.split(":")[1].rstrip().strip()
                    DB = line.split(":")[1].rstrip().strip().split('OracleASMService')[1]
                    DB = "%s" % DB
                    if not "%s:%s:True" % (DB, SVCNAME) in DBLIST:
                        DBLIST.append('%s:%s:True' % (DB, SVCNAME))
    if len(DBLIST) == 0:
        steplog.success("No Windows Oracle instances detected")

    SVCNAME = {}
    ASM = {}
    ORAHOME = {}
    LASTPATCHID = {}
    PSU = {}
    OPATCH_VERSION = {}
    ORACLEVERSION = {}
    PORT = {}
    TNSADMIN = {}

    for DB in DBLIST:
        DBNAME = DB.split(":")[0]
        try:
            steplog.debug('Set DBNAME = %s from DB %s' % (DBNAME, DB))
            DBS.append(DBNAME)
            SVCNAME[DBNAME] = DB.split(":")[1]
            ASM[DBNAME] = DB.split(":")[2]
            COMMAND = 'sc qc %s' % SVCNAME[DBNAME]
            OUTPUT = ostools.run_command(COMMAND)[0].split("\n")
            for line in OUTPUT:
                if line.find("BINARY_PATH_NAME") > -1:
                    ORAHOME[DBNAME] = line.split(" : ")[1].rstrip().strip().split('\\bin\\')[0]
            OPATCHBIN = os.path.join(ORAHOME[DBNAME], 'OPatch', 'opatch.bat')
            LASTPATCHID[DBNAME] = "None"
            PSU[DBNAME] = "None"
            OPATCH_VERSION[DBNAME] = "None"
            ORACLEVERSION[DBNAME] = "None"
            os.environ['ORACLE_HOME'] = ORAHOME[DBNAME]
            os.environ['ORACLE_SID'] = DBNAME
            if os.path.isfile(OPATCHBIN):
                steplog.info('Found opatch binary on system')
                OPATCHCMD = "%s lsinventory -patch_id" % OPATCHBIN
                OUTPUT, __, rc = ostools.run_command(OPATCHCMD)
                if rc != 0 or OUTPUT.lower().find('failed with error code') > -1:
                    steplog.warn('Opatch failed on system, maybe oracle version < 11, trying to fallback to previous syntax')
                    OPATCHCMD = "%s\\OPatch\\opatch lsinventory" % ORAHOME[DBNAME]
                    OUTPUT, __, rc2 = ostools.run_command(OPATCHCMD)
                    if rc2 != 0:
                        steplog.error('Cannot gather patch version in any way')
                    FOUNDPATCH = 'None'
                    for line in OUTPUT.split('\n'):
                        if line.lstrip().strip().lower().startswith('patch'):
                            if FOUNDPATCH == 'None':
                                FOUNDPATCH = line.lstrip().strip().split()[1].lstrip().strip()
                            steplog.info('Found installed patch %s' % line.lstrip().strip().split()[1].lstrip().strip())
                    LASTPATCHID[DBNAME] = FOUNDPATCH
                for line in OUTPUT.split('\n'):
                    if line.lower().find('opatch version') > -1:
                        OPATCH_VERSION[DBNAME] = line.split(":")[1].rstrip().strip()
                        steplog.info('Identified opatch version %s' % OPATCH_VERSION[DBNAME])
                    if line.lower().find('unique patch id') > -1:
                        LASTPATCHID[DBNAME] = line.split(":")[1].rstrip().strip()
                        steplog.info('Identified lastpatchid %s' % LASTPATCHID[DBNAME])
                    if line.lower().find('database patch set update') > -1 or line.lower().find('database psu') > -1:
                        if PSU[DBNAME] == "None":
                            PSU[DBNAME] = "PSU %s" % line.split(":")[2].split("(")[0].strip().rstrip()
                            steplog.info('Identified PSU %s' % PSU[DBNAME])
                    elif line.lower().find('windows db bundle patch') > -1 and line.lower().find('patch description:') > -1:
                        line = line.lower().strip()
                        if line.startswith("patch description"):
                            patch_level = line.replace("patch description", "").replace("windows db bundle patch", "").replace(":", "").replace("'", "").replace('"', "").split("(")[0].strip()
                            PSU[DBNAME] = patch_level
                    if line.lower().startswith('oracle database'):
                        ORACLEVERSION[DBNAME] = line.split()[len(line.split()) - 1]
                        steplog.info('Identified oracle version %s' % ORACLEVERSION[DBNAME])
            else:
                steplog.warn('Unable to find opatch binary on dbhome, expected file %s not found' % OPATCHBIN)
                steplog.info('Trying to get oracle information via sql query')
                SQLPLUSBIN = os.path.join(ORAHOME[DBNAME], 'bin', 'sqlplus.exe')
                if not os.path.isfile(SQLPLUSBIN):
                    steplog.error('Cannot find %s on system' % SQLPLUSBIN)
                sqlfile = tempfile.mktemp('.sql', 'ver')
                sqldesc = open(sqlfile, 'w')
                sqldesc.write('select version from v$instance;')
                sqldesc.close()
                SQLCMD = """%s / as sysdba @ %s""" % (SQLPLUSBIN, sqlfile)
                output, __, rc = ostools.run_command(SQLCMD)
                os.remove(sqlfile)
                if rc != 0:
                    steplog.error('Cannot connect in any way to the database')
                for line in output.split('\n'):
                    if len(line.strip().lower().split('.')) > 2:
                        steplog.info('FOUND %s ' % line)
                        if str(line.strip().lower().split('.')[0]).isdigit() and str(line.strip().lower().split('.')[1]).isdigit():
                            ORACLEVERSION[DBNAME] = line.strip()
                            steplog.info('Oracle Version %s ' % ORACLEVERSION[DBNAME])
                steplog.warn('Cannot get patches information since opatch is not available')

            TNSPINGCMD = "%s\\bin\\tnsping %s" % (ORAHOME[DBNAME], DBNAME)
            OUTPUT = ostools.run_command(TNSPINGCMD)[0].split("\n")
            NEXTLINE = 0
            for line in OUTPUT:
                if line.lower().find("port =") > -1:
                    PORT[DBNAME] = line.lower().split("port = ")[1].split(")")[0].rstrip().strip()
                if line.lower().find("used parameter files") > -1 or NEXTLINE == 1:
                    if NEXTLINE == 1:
                        TNSADMINFILE = line.strip()
                        SIZE = len(TNSADMINFILE.split("\\")[len(TNSADMINFILE.split("\\")) - 1]) + 1
                        TNSADMIN[DBNAME] = TNSADMINFILE[:-SIZE]
                        NEXTLINE = 0
                    else:
                        NEXTLINE = 1
        except:
            steplog.warn('Errors in %s discovery ' % DBNAME)
            DBS.remove(DBNAME)

    if len(DBS) == 0:
        steplog.warn("No Discoverable Windows Oracle instances detected")


###############################################################################
#                                   Classes                                   #
###############################################################################

class OracleEntity(discovery.DMAEntity):
    crs_info = {}
    home_infos = {}
    listeners = []
    pmon_procs = []
    tnslsnr_procs = []

    @classmethod
    def find_listeners(cls):
        def get_listeners():
            listeners = []
            if IS_WIN:
                return listeners

            # Note: tnslsnr_path = "bin/tnslsnr" on unix
            tnslsnr_path = os.path.join('bin', 'tnslsnr')

            for proc in cls.tnslsnr_procs:
                line = proc['ps_line']
                words = filter(bool, line.split())
                if len(words) > 2:
                    for word, next_word in zip(words, words[1:]):
                        if word.endswith(tnslsnr_path):
                            listener = {}
                            listener['name'] = next_word
                            listener['home'] = os.path.dirname(os.path.dirname(word))
                            listener['user'] = proc.get('user') if proc.get('user') else words[0]
                            listener['TNS_ADMIN'] = proc['env'].get('TNS_ADMIN')
                            listener.update(get_status_info(listener))
                            listeners.append(listener)
            return listeners

        def get_status_info(listener):
            name = listener['name']
            home = listener['home']
            user = listener['user']
            tns_admin = listener['TNS_ADMIN']
            steplog.debug('listener name = %r' % (name,))
            steplog.debug('listener home = %r' % (home,))
            steplog.debug('listener user = %r' % (user,))
            steplog.debug('listener TNS_ADMIN = %r' % (tns_admin,))

            env_string = oracletools.get_oracle_env_string(home, tns_admin=tns_admin)
            lsnrctl = os.path.join(home, 'bin', 'lsnrctl')

            cmd = 'sh -c "%s; %s status %s"' % (env_string, lsnrctl, name)

            text, errors, status = ostools.sudo_run_command(cmd, user=user)
            steplog.debug('text = %r' % text)
            steplog.debug('errors = %r' % errors)
            steplog.debug('status = %r' % status)
            if not text or status != 0:
                msg = "Could not determine listener information. Verify the listener is working."

                steplog.error(msg)
                return {}

            ora_file = ''
            try:
                ora_file = re.findall(r'(?i)Listener Parameter File\s*(\S*)', text)[-1]
            except StandardError:
                pass

            instances = re.findall(r'(?i)Instance \"(.*?)\", status', text)
            instances = dict.fromkeys(instances).keys()
            instances.sort()
            ports = re.findall(r'(?i)PROTOCOL=tcp.*PORT=(\d+)', text)
            ports = dict.fromkeys(ports).keys()

            return {'ora_file': ora_file,
                    'instances': instances,
                    'ports': ports}

        # Note: tnslsnr_path = "bin/tnslsnr" on unix
        tnslsnr_path = os.path.join('bin', 'tnslsnr')

        cls.tnslsnr_procs = ostools.get_proc_info(tnslsnr_path)
        cls.listeners = get_listeners()
        steplog.debug('listeners = %r' % (cls.listeners,))

    @classmethod
    def parse_inventories(cls, inventory_locations=()):
        steplog.debug('In parse_inventories')

        def fetch_inventory_dirs(inv_locs):
            """Returns a list of (dir, group) tuples."""

            # Prepare the list with defaults for both windows and unix.
            inv_locs = list(inv_locs)
            inv_locs.append(os.environ.get('ProgramFiles', '/') +
                            '/Oracle/Inventory')
            if os.path.exists('/var/opt/oracle/oraInst.loc'):
                inv_locs.append('/var/opt/oracle/oraInst.loc')
            if os.path.exists('/etc/oraInst.loc'):
                inv_locs.append('/etc/oraInst.loc')
            # Convert all paths to be os correct.
            inv_locs = map(os.path.normpath, inv_locs)
            inv_locs = map(os.path.normcase, inv_locs)

            steplog.debug('inv_locs = %r' % (inv_locs,))
            if not inv_locs:
                return []

            inv_dirs = []

            if IS_WIN:
                return [(inv_locs[0], None)]

            for inv_file in inv_locs:
                try:
                    text = sudo_file_read(inv_file)
                except IOError:
                    continue
                text = text.strip()
                if not text:
                    continue
                inv_data = {'group': '',
                            'dir': '',
                            }
                for line in [l.strip() for l in text.splitlines() if l.strip()]:
                    if line.startswith('inventory_loc'):
                        inv_data['dir'] = line.split('=')[1].strip()
                    elif line.startswith('inst_group'):
                        inv_data['group'] = line.split('=')[1].strip()
                inv_dirs.append((inv_data['dir'], inv_data['group']))

            return inv_dirs

        def get_version(info_elem):
            oracle_home = info_elem['Home']
            crs_flag = info_elem.get('CRS', None)

            crsctl = os.path.join(oracle_home, 'bin', 'crsctl')
            sqlplus = os.path.join(oracle_home, 'bin', 'sqlplus')
            if IS_WIN:
                sqlplus += '.exe'

            if crs_flag and os.path.exists(crsctl):
                cmd = '%s query crs activeversion' % crsctl
                for line in os.popen(cmd).readlines():
                    if (line.startswith('Oracle Clusterware active') or
                            line.startswith('CRS active version on the cluster is')):

                        return line.split('[')[1].split(']')[0]
            user = ostools.determine_file_owner(sqlplus)

            os.environ['ORACLE_HOME'] = oracle_home
            cmd = "%s -V" % (sqlplus,)
            output, _, status = ostools.sudo_run_command(cmd, user=user, try_first=True)
            if status != 0:
                raise ValueError('Unable to run sqlplus.')
            for line in output.splitlines():
                if line.startswith('SQL*Plus: Release'):
                    return line.split()[2]

            raise ValueError('Unable to determine oracle version.')

        def fetch_homes(inv_dirs):
            inv_info = []
            for inv_dir, inv_group in inv_dirs:
                inv_file = os.path.join(inv_dir, 'ContentsXML',
                                        'inventory.xml')
                try:
                    inv_file_contents = sudo_file_read(inv_file)
                except IOError:
                    continue

                dom = xml.dom.minidom.parseString(inv_file_contents)
                for elem in dom.getElementsByTagName('HOME'):
                    info_elem = {}
                    info_elem['Group'] = inv_group
                    info_elem['Name'] = elem.getAttribute('NAME')
                    info_elem['Home'] = home_loc = elem.getAttribute('LOC')
                    info_elem['Type'] = elem.getAttribute('TYPE')
                    info_elem['Index'] = elem.getAttribute('IDX')
                    info_elem['Removed'] = (elem.getAttribute('REMOVED') == 'T')
                    info_elem['CRS'] = (elem.getAttribute('CRS').upper() == 'TRUE')

                    #bypass if a home is *NOT* real Oracle Home by checking sqlplus and oracle binary
                    if not os.path.exists(os.path.join(home_loc, 'bin', 'sqlplus')) \
                             and not os.path.exists(os.path.join(home_loc, 'bin', 'oracle')):
                        continue


                    info_elem['Nodes'] = nodes = []
                    for nodeList in elem.getElementsByTagName('NODE_LIST'):
                        for node in nodeList.getElementsByTagName('NODE'):
                            nodes.append(node.getAttribute('NAME'))
                    nodes.sort()

                    info_elem['Owner'] = None
                    if not IS_WIN:
                        install_path = os.path.join(home_loc, 'install')
                        try:
                            info_elem['Owner'] = ostools.determine_file_owner(install_path)
                        except IOError:
                            steplog.debug('Despite what the inventory is telling us, there is no installation at this location: %s' % home_loc)
                            continue

                    try:
                        info_elem['Version'] = get_version(info_elem)
                    except (ValueError, IOError):
                        info_elem['Version'] = 'Undetermined'

                    info_elem['Cluster Name'] = None
                    if info_elem['CRS']:
                        cmd = os.path.join(info_elem['Home'], 'bin', 'cemutlo -n')
                        output, _, _ = ostools.sudo_run_command(cmd, user=info_elem['Owner'])
                        info_elem['Cluster Name'] = output.strip()

                    inv_info.append(info_elem)
                    steplog.debug(info_elem)
            return inv_info

        def find_crs(inv_info):
            valid = filter(lambda x: (not x['Removed'] and
                                      x['CRS'] and
                                      x['Owner']),
                           list(inv_info))

            valid = stable_uniq(valid)

            try:
                pivot = valid.pop()
                for info_dict in valid:
                    if info_dict != pivot:
                        raise ValueError('Found multiple {CRS_Home}s')
                steplog.debug('crs_info = %r' % (pivot,))
                return pivot
            except IndexError:
                return None

        def find_oracle_homes(inv_info):
            return filter(lambda x: (not x['Removed'] and (IS_WIN or
                                                           bool(x['Home']))),
                          list(inv_info))

        if IS_WIN:
            return

        steplog.info('Starting oracle inventory process.')
        inv_dirs = fetch_inventory_dirs(inventory_locations)
        steplog.debug('inv_dirs = %r' % (inv_dirs,))
        all_homes = fetch_homes(inv_dirs)
        steplog.debug('all_homes = %r' % (all_homes,))

        cls.crs_info = find_crs(all_homes)
        steplog.debug('cls.crs_info = %r' % (cls.crs_info,))
        cls.home_infos = find_oracle_homes(all_homes)
        steplog.debug('cls.home_infos = %r' % (cls.home_infos,))

    @classmethod
    def get_home_info(cls, target_home):
        for home in cls.home_infos:
            if home['Home'] == target_home:
                return home

    @classmethod
    def get_sids_via_crs(cls):
        sids = {}
        if not cls.crs_info:
            msg = 'CRS not found.  Looking for SIDS via other mechanisms.'
            steplog.info(msg)
            return sids
        srvctl = os.path.join(cls.crs_info['Home'], 'bin', 'srvctl')
        steplog.debug('srvctl path = ' + repr(srvctl))

        node_name = SERVER_NAME.split('.')[0]
        steplog.debug('node_name = ' + repr(node_name))

        cmd = srvctl + ' config database'
        out, _, rc = ostools.sudo_run_command(cmd)
        if rc != 0:
            steplog.error('Could not find any databases using "%s".' % cmd)
            return sids
        dbs = out.splitlines()
        for db in dbs:

            sid = None
            home = None

            # All roads to sids and homes start with this command:
            cmd = '%s config database -d %s' % (srvctl, db)
            out, _, rc = ostools.sudo_run_command(cmd)
            sid_home = ''
            if 'differs from the program version' in out:
                steplog.info('Using DB Home to run the srvctl command')
                home = str(out).split()[-1].strip('.')
                srvctl = os.path.join(home, 'bin', 'srvctl')
                cmd = '%s config database -d %s' % (srvctl, db)
                out, _, rc = ostools.sudo_run_command(cmd)
            # Get SID and HOME on RAC < 11.2
            sid_home = re.search(r'(?m)^%s (\S*) (\S*)' % node_name, out)


            if sid_home:
                sid = sid_home.group(1)
                home = sid_home.group(2)
                steplog.debug('sid = ' + repr(sid))
                steplog.debug('home = ' + repr(home))

            if not home:
                # Home on RAC 11.2
                home = re.search(r'(?m)^Oracle home: (.*)$', out)
                if home:
                    home = home.group(1)
                    steplog.debug('home = ' + repr(home))

            if not sid:
                # Get the sid on RAC 11.2
                cmd = '%s status instance -d %s -n %s' % (srvctl, db, node_name)
                out, _, rc = ostools.sudo_run_command(cmd)
                if rc == 0:
                    sid = re.findall(r'Instance (\S*) is[\S\s]+running on node', out)
                    if not sid:
                        continue
                    sid = sid[0]
                    steplog.debug('sid = ' + repr(sid))

            if home and sid:
                sids[sid] = home

        steplog.debug('sids found via crs = ' + repr(sids))
        return sids

    @classmethod
    def get_sids_via_ps(cls):
        sids = {}

        if IS_WIN:
            return sids

        cls.pmon_procs = ostools.get_proc_info('ora_pmon')

        pmon_stripper = re.compile(r'^ora_pmon_')

        sids = {}
        for proc in cls.pmon_procs:
            steplog.debug('proc info = %r' % proc)
            sid = proc['ps_line'].strip().split()[-1]
            sid = pmon_stripper.sub('', sid, 1)
            home = None
            try:
                sid = proc['env']['ORACLE_SID']
                home = proc['env'].get('ORACLE_HOME')
            except KeyError:
                pass
            sids[sid] = home

        steplog.verbose('sids from ps = %r' % sids)
        return sids

    @classmethod
    def get_sids_via_oratab(cls):
        sids = {}

        if IS_WIN:
            return sids

        known_oratabs = []
        if os.path.exists('/etc/oratab'):
            known_oratabs.append('/etc/oratab')
        if os.path.exists('/var/opt/oracle/oratab'):
            known_oratabs.append('/var/opt/oracle/oratab')

        for oratab in known_oratabs:
            try:
                oratab = sudo_file_read(oratab, mode='r').splitlines()
            except (IOError, EnvironmentError):
                continue

            for line in [elem.strip() for elem in oratab if elem.strip()]:
                if not re.search(r'^\s*#', line):
                    steplog.debug(line)
                    sid, home = line.strip().split(':')[:2]
                    sids[sid] = home

        steplog.verbose('sids from oratab = %r' % sids)
        return sids

    def __init__(self, oracle_sid, oracle_home):
        self.oracle_home = oracle_home
        self.oracle_sid = oracle_sid
        self.tns_admin = None
        self._can_query = None
        self.user = None

    def discover_self(self):
        if IS_WIN:
            self.user = 'system'
        else:
            self.user = ostools.determine_file_owner(self.oracle_home)
            try:
                sqlplus_user = ostools.determine_file_owner(os.path.join(self.oracle_home, 'bin', 'sqlplus'))
                if sqlplus_user:
                    self.user = sqlplus_user
            except StandardError:
                pass

    def query(self, sql):
        """Query the db via sqlplus"""
        # TODO: Store the conn object in the instance, so we don't have to
        #       remake it every run.  Then just call conn.query()
        output = oracletools.connect_and_query(sql, self.oracle_home,
                                               self.oracle_sid, user=self.user)
        steplog.debug('output = ' + repr(output))
        return output

    def query_row(self, sql):
        try:
            return self.query(sql)[0]
        except IndexError:
            return []
        except ValueError:
            return None

    def query_value(self, sql):
        try:
            return self.query_row(sql)[0]
        except (AttributeError, IndexError):
            return None

    def can_query(self):
        steplog.verbose('Checking to see if %s can query.' % self.oracle_sid)
        if self._can_query is None:
            output = self.query_value('select count(1) from dual')
            steplog.verbose('can query output = %r' % (output,))
            self._can_query = (output == '1')
        steplog.verbose('can_query = %r' % (self._can_query,))
        return self._can_query

    def get_relevant_listeners(self):
        return [listener for listener in self.listeners if
                self.oracle_sid in listener.get('instances', [])]


##################
# Server Classes #
##################


####################
# Instance Classes #
####################

@discovery.DMAServer.register_instance_class
class OracleInstance(discovery.DMAInstance, OracleEntity):

    @classmethod
    def discover_instances(cls, parent_servers):
        instances = []

        if IS_WIN:
            discovered_instances = []
            for DB in DBS:
                discovered_instances.append(cls(DB, ORAHOME[DB], parent_servers))
            return discovered_instances


        steplog.info('Finding Oracle instances via ps')
        ps_sids = cls.get_sids_via_ps()

        steplog.info('Finding Oracle instances via oratab')
        oratab_sids = cls.get_sids_via_oratab()

        sids = {}
        for sid_dict in (oratab_sids, ps_sids):
            for sid, home in sid_dict.items():
                if home:
                    sids[sid] = home

        steplog.debug('sids = %r' % (sids,))

        inventories = [os.path.join(home, 'oraInst.loc') for home in
                       dict.fromkeys(sids.values()).keys()]
        cls.parse_inventories(inventories)

        steplog.info('Finding Oracle instances via crs')
        crs_sids = cls.get_sids_via_crs()

        # Remove "probably bad" sids from the oratab_sids dict.  These are SIDs
        # that have been named impropperly, and it's caused by RAC
        # installations.
        # if RAC database modify oracle_sid name accordingly
        for oratab_sid, oratab_home in list(oratab_sids.items()):
            if cls.crs_info and not re.search("ASM", oratab_sid, re.I):
                sid = oratab_sid
                oracle_home = cls.crs_info['Home']
                db_type = oracletools.get_RAC_database_type(oracle_home, sid)
                if db_type == "RACOneNode":
                    rac_number = oracletools.get_rac_node_number(oracle_home, sid)
                    if rac_number:
                        sid = "%s_%s" % (sid, rac_number)
                elif db_type == "RAC":
                    rac_number = oracletools.get_rac_node_number(oracle_home, sid)
                    if rac_number:
                        is_policy_managed = oracletools.is_policy_managed(oracle_home, sid)
                        if is_policy_managed:
                            sid = "%s_%s" % (sid, rac_number)
                        else:
                            sid = "%s%s" % (sid, rac_number)
                if not sid == oratab_sid:
                    steplog.debug("We delete %s and we add %s to the list of Oracle SIDs" % (oratab_sid, sid))
                    del oratab_sids[oratab_sid]
                    oratab_sids[sid] = oratab_home
                oratab_sid = sid

            if oratab_sid in crs_sids or oratab_sid in ps_sids:
                continue

            sid_re = re.compile(r'^%s(\d+)$' % re.escape(oratab_sid))
            for crs_sid, crs_home in crs_sids.items():
                if oratab_home == crs_home and sid_re.search(crs_sid):
                    msg = 'Assuming "%s" from oratab is supposed to be "%s" found in crs.'
                    steplog.info(msg % (oratab_sid, crs_sid))
                    del oratab_sids[oratab_sid]
                    break

        # Remake the sids dict with the "now correct" oratab_sids.
        sids = {}
        for sid_dict in (oratab_sids, crs_sids, ps_sids):
            for sid, home in sid_dict.items():
                if home:
                    sids[sid] = home

        steplog.debug('sids = ' + repr(sids))

        cls.find_listeners()

        for sid, home in sids.items():
            steplog.debug('sid and home are: %r      %r' % (sid, home))
            info = cls.get_home_info(home)
            if info:
                instance = cls(sid, info, parent_servers)
                instance.set_value('Database Platform', 'Oracle')
                instances.append(instance)

        return instances

    def __init__(self, sid, info_dict, parents):
        steplog.debug('info_dict = %r' % (info_dict,))
        discovery.DMAInstance.__init__(self, sid, parents)
        if IS_WIN:
            self.user = 'system'
            self.password = ''
            self.windows_domain = ''
            try:
                self.asm = ASM[self.name]
            except:
                steplog.warn('No %s ASM information available' % self.name)
        else:
            OracleEntity.__init__(self, sid, info_dict['Home'])
            self.info_dict = info_dict
            self.asm = 'False'  # This will be correctly set later.
        self.oracle_version = ''
        self.dbms_type = 'Oracle'

    def discover_self(self):
        steplog.info('Discovering information about instance "%s"' % self.name)

        OracleEntity.discover_self(self)
        if IS_WIN:
            self.set_value('oracle home', ORAHOME[self.name])
        else:
            self.set_value('oracle home', self.oracle_home)
        self.set_value('os user', self.user)
        if not IS_WIN:
            self.set_asm()

        self.set_tns_admin()
        self.set_port()
        if IS_WIN:
            self.set_bin_location()

        self.set_host()
        self.set_instance_name()
        self.set_version()
        self.set_version_infos()
        # This patch level is undoubtedly more accurate than from lsinventory,
        # so it's run last in order to take prescidence.
        self.set_critical_patch_level()
        


    def set_bin_location(self):
        try:
            bin_location = ORAHOME[self.name]
            self.set_value('oracle home', bin_location)
            return bin_location
        except:
            steplog.warn('No %s home information available' % self.name)
            return ' '

    def set_host(self):
        self.host = self.parents[0].name

    def set_instance_name(self):
        if IS_WIN:
            self.set_value('instance name', self.name)
            return self.name  
        if not self.can_query():
            return
        val = self.query_value("""select instance_name from v$instance""")
        steplog.verbose('instance_name = %r' % (val,))
        if val:
            self.set_value('instance name', val)

    def set_version(self):
        if IS_WIN:
            try:
                instance_version = ORACLEVERSION[self.name]
                self.set_value('oracle version', instance_version)
                return instance_version
            except:
                steplog.warn('No %s version information available' % self.name)
                return ' '
        if not self.can_query():
            return
        val = self.query_value("""select banner
                                    from v$version
                                   where banner like 'Oracle Database%'""")
        steplog.verbose('version = %r' % (val,))
        if val:
            if "-" in val:
                val = val.split("-")[0].split()[-1]
            self.set_value('version', val)
            self.oracle_version = val

    def set_version_infos(self):
        if IS_WIN:
            try:
                opatch = OPATCH_VERSION[self.name]
                self.set_value('opatch', opatch)
                lastpatchid = LASTPATCHID[self.name]
                self.set_value('last patch id', lastpatchid)
                patchlevel = str(PSU[self.name]).replace("'", "").replace('"', "")
                self.set_value('patch level', patchlevel)
                return " "
            except:
                steplog.warn('No %s patch information available' % self.name)
                return ' '
        user = ostools.determine_file_owner(os.path.join(self.oracle_home, 'OPatch', 'opatch'))
        cmd = 'ORACLE_HOME=%s;export ORACLE_HOME;%s lsinventory' % (self.oracle_home,
                                                        os.path.join(self.oracle_home, 'OPatch', 'opatch'))
        out, _, _ = ostools.sudo_run_command(cmd, user=user)
        if not out.strip():
            return

        # Get the Oracle Database Version
        pattern = re.compile('(Oracle Database|Oracle Grid Infrastructure)\s+\w+\s+([\d\.]+)')
        match = pattern.search(out)
        if match:
            self.set_value('Oracle Version', match.group(2))

        # Get the OPatch Version
        pattern = re.compile('OPatch version\s+:\s+([\d\.]+)\s*$', re.M)
        match = pattern.search(out)
        if match:
            self.set_value('Opatch', match.group(1))

        # Get the Patch Level
        patch_level = ''
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("Patch description:"):
                patch_level = line.split(":")[-1].split("(")[0].strip()
                break
        if not patch_level:
            pattern = re.compile(r"Patch\s+(\d+)\s")
            match = pattern.search(out)
            if match:
                patch_level = match.group(1)
		patch_level = str(patch_level).replace("'", "").replace('"', "")
        self.set_value('Patch Level',patch_level)

        # Get the Unique Patch ID
        last_patch_id = ''
        pattern = re.compile(r"Unique Patch ID:\s+(\d+)")
        match = pattern.search(out)
        if match:
            last_patch_id = match.group(1)
        self.set_value('Last Patch ID', last_patch_id)

    def set_critical_patch_level(self):
        patch_level = None
        if not IS_WIN:
            patch_level = oracletools.get_critical_patch_level(self.oracle_home,
                                                               self.oracle_sid, oracle_version=self.oracle_version)
        else:
            patch_level = PSU[self.name]
        steplog.info("Name: %s\nPatch : %s\n"%(self.name, patch_level))
        if patch_level:
            patch_level = str(patch_level).replace("'", "").replace('"', "")
            self.set_value('Patch Level', patch_level)


    def set_virtual_name(self):
        if not self.can_query():
            return
        val = self.query_value("""select host_name from v$instance""")
        steplog.verbose('host / virtual_name = %r' % (val,))
        if val:
            self.set_value('host', val)

    def set_asm(self):
        if not self.can_query():
            steplog.debug('Can not query this instance.  Unable to determine ASM status.')
            return
        self.asm = 'False'

        sql = """select value from v$parameter where name = 'instance_type'"""
        val = self.query_value(sql)
        if val and val.lower() == 'asm':

            sql = """select db_name from v$asm_client"""
            val = self.query_value(sql)
            if val:
                self.asm = 'True'
        steplog.verbose('asm = %r' % (self.asm,))

    def set_port(self):
        if IS_WIN:
            try:
                instance_port = PORT[self.name]
                self.port = instance_port
                return instance_port
            except:
                steplog.warn('No %s port information available' % self.name)
                return ' '
        if not self.listeners:
            return None
        listeners = self.get_relevant_listeners()
        steplog.debug('listener for instance "%r" are %r' % (self.oracle_sid, listeners))
        best_listeners = [listener for listener in listeners if
                          listener['home'] == self.oracle_home]
        for listener in best_listeners + listeners:
            if listener['ports']:
                self.port = listener['ports'][0]
                if 'TNS_ADMIN' in listener and listener['TNS_ADMIN']:
                    self.tns_admin = listener['TNS_ADMIN']
                break

        steplog.debug('self.port = %r' % (self.port,))

    def set_tns_admin(self):
        if IS_WIN:
            try:
                tnsadmin = TNSADMIN[self.name]
                self.set_value('tns admin', tnsadmin)
                return tnsadmin
            except:
                steplog.warn('No %s tnsadmin information available' % self.name)
                return ' '
        steplog.debug('Finding listener for instance: %s' % self.oracle_sid)
        for listener in self.get_relevant_listeners():
            if 'TNS_ADMIN' in listener:
                self.tns_admin = listener['TNS_ADMIN']

        # The overwrite behavior here is indended.
        for proc in self.pmon_procs:
            try:
                if proc['env']['ORACLE_SID'] == self.oracle_sid:
                    self.tns_admin = proc['env']['TNS_ADMIN']
            except KeyError:
                continue

        if self.tns_admin is None:
            self.tns_admin = os.path.join(self.oracle_home, 'network', 'admin')

        steplog.debug('Setting TNS_ADMIN: ' + repr(self.tns_admin))
        self.set_value('TNS ADMIN', self.tns_admin)

    def discover_children(self):
        if IS_WIN:
            #self.children.append(OracleDatabase(self.name, self))
            self.children = [OracleDatabase(self.name, self.name,
                                                ORAHOME[self.name], [self])]
        else:
            steplog.debug('Finding Children for instance %r' % self.name)
            self.children = []
            if not self.can_query():
                steplog.debug('Can not query. Exiting.')
                return

            val = self.query_value("""select value from v$parameter where upper(name) = 'DB_UNIQUE_NAME'""")
            steplog.debug('child discovery val: %r' % (val,))
            if val:
                self.children = [OracleDatabase(val, self.oracle_sid,
                                                self.oracle_home, [self])]
            pdbs = []
            try:
                val = self.query_value("""SELECT CDB FROM V$DATABASE""")

                if "YES" in val:
                    self.set_value("isCDB", 'True')
                else:
                    self.set_value("isCDB", 'False')

                val = self.query("""SELECT PDB_NAME FROM DBA_PDBS""")
                steplog.debug("PDBs: "+str(val))
                for v in val:
                    if v:
                        pdbs.append(v[0])
                steplog.debug('Consolidated PDBS: '+str(pdbs))
                pdbs = list(set(pdbs)-set(['PDB$SEED','pdb$seed']))
                if pdbs:
                    self.children.extend([OracleDatabase(pd , self.oracle_sid, self.oracle_home, [self]) for pd in pdbs])
                    self.set_value('PDBs', ", ".join(pdbs))
            except:
                pass


####################
# Database Classes #
####################

class OracleDatabase(discovery.DMADatabase, OracleEntity):
    def __init__(self, name, oracle_sid, oracle_home, parents):
        discovery.DMADatabase.__init__(self, name, parents)
        OracleEntity.__init__(self, oracle_sid, oracle_home)

    def discover_self(self):
        OracleEntity.discover_self(self)
        self.set_unique_name()
        self.set_ispdb()

    def set_unique_name(self):
        self.set_value('unique name', self.name)

    def set_ispdb(self):
        steplog.info("Checking if the database is a pdb..")
        #val = self.query_value("""SELECT CDB FROM V$DATABASE""")
        try:
            val = self.query_value("""select PDB_NAME from DBA_PDBS""" )
            steplog.info("..", val)
            if self.name in val:
                self.set_value('ispdb', 'True')
            else:
                self.set_value('ispdb', 'False')
        except:
            pass


###############################################################################
#                            Stand Alone Functions                            #
###############################################################################

def sudo_file_read(file_path, mode='r', user=None):
    # TODO: This function needs to be windows friendly too.
    try:
        return file(file_path, mode).read()
    except IOError:
        steplog.debug('Attempting to switch users to open %r' % file_path)

    if not user:
        user = ostools.determine_file_owner(file_path)

    cmd = 'cat "%s"' % file_path

    output, errors, status = ostools.sudo_run_command(cmd, user=user)
    if status != 0:
        msg = 'Can not read %r even while trying to switch users to %r.  ERROR: %r'
        raise IOError(msg % (file_path, user, errors))
    return output


def stable_uniq(sequence):
    new_sequence = []
    for elem in sequence:
        if elem not in new_sequence:
            new_sequence.append(elem)
    try:
        return type(sequence)(new_sequence)
    except TypeError:
        return new_sequence


###############################################################################
#                                    main                                     #
###############################################################################

@discovery.report_status_header
def main():

    discovery.main(
        org_name=ORG_NAME,
        server_name=SERVER_NAME,
        nc_url=NC_URL,
        nc_user=NC_USER,
        nc_password=NC_PASSWORD,
        trust_ssl=TRUST_SSL_CERTS,
        envapi_write=ENVAPI_WRITE,
        envapi_overwrite=ENVAPI_OVERWRITE
    )

def discover_oo(param_dict=None):
    if "servername" in param_dict:
       servername = param_dict["servername"]
    else:
        servername = None
    return discovery.main_oo(servername)
	
	
if __name__ == '__main__':
    try:
        main()
    except StandardError, e:
        steplog.handle_exception(e)
