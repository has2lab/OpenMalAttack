import lief
import random
import tempfile
import os
import subprocess
import json
import sys
import array
import struct
import random
import tempfile
import subprocess
import functools
import signal
import multiprocessing

class MalwareManipulator(object):
    def __init__(self, bytez: bytes):
        self.bytez = bytez
        self.packed_section_names = {'.aspack', '.adata', 'ASPack', '.ASPack', '.boom', '.ccg', '.charmve', 'BitArts', 'DAStub',
                                     '!EPack', '.ecode', '.edata', '.enigma1', '.enigma2', '.enigma2', '.FSG!', '.gentee', 'kkrunchy',
                                     'lz32.dll', '.mackt', '.MaskPE', 'MEW', '.mnbvcx1', '.mnbvcx2', '.MPRESS1', '.MPRESS2', '.neolite',
                                     '.neolit', '.nsp1', '.nsp0', '.nsp2', 'nps1', 'nps0', 'nps2', '.packed', 'pebundle', 'PEBundle',
                                     'PEC2TO', 'PECompact2', 'PE2', 'pec', 'pec1', 'pec2', 'pec2', 'pec3', 'pec4', 'pec5', 'pec6',
                                     'PEC2MO', 'PELOCKnt', '.perplex', 'PESHiELD', '.petite', '.pinclie', 'ProCrypt', '.RLPack',
                                     '.rmnet', 'RCryptor', '.RPCrypt', '.seau', ',sforce3', '.shrink1', '.shrink2', '.shrink3',
                                     '.spack', '.svkp', 'Themida', '.Themida', '.taz', '.tsuarch', '.tsustub', '.packed', 'PEPACK!!',
                                     '.Upack', '.ByDwing', 'UPX0', 'UPX1', 'UPX2', 'UPX3', 'UPX!', '.UPX0', '.UPX1', '.UPX2',
                                     '.vmp0', '.vmp1', '.vmp2', 'VProtect', '.winapi', 'WinLicen', '_winzip_', '.WWPACK', 'WWP32', '.yP', '.y0da'}
    def _ispacked(self, pe):
        for s in pe.sections:
            if s.name in self.packed_section_names:
                return True
        return False

    def _section_rename_if_exists(self, pe, section_name, target_name):
        for s in pe.sections:
            if s.name == section_name:
                break
        if s.name == section_name:
            s.name = target_name

    def add_section(self, section_name: str, characteristics: int, section_content: bytes):
        pe = lief.parse(raw=self.bytez)
        if self._ispacked(pe):
            return  # don't mess with sections if the file is packed
        replace_name = '.' + ''.join(list(map(chr, [random.randint(ord('a'), ord('z')) for _ in range(6)])))  # example: .nzomcu
        self._section_rename_if_exists(pe, section_name, replace_name)  # rename if exists
        section = lief.PE.Section(name=section_name, content=list(section_content), characteristics=characteristics)
        pe.add_section(section, lief.PE.SECTION_TYPES.UNKNOWN)
        self.bytez = self._build(pe)
        return self.bytez

    def rename_section_(self, section_name: str, target_name: str):
        pe = lief.parse(raw=self.bytez)
        if self._ispacked(pe):
            return  # don't mess with sections if the file is packed
        self._section_rename_if_exists(pe, section_name, target_name)  # rename if exists
        self.bytez = self._build(pe)  # idempotent if the section doesn't exist
        return self.bytez

    def set_timestamp(self, timestamp: int):
        pe = lief.parse(raw=self.bytez)
        pe.header.time_date_stamps = timestamp
        self.bytez = self._build(pe)
        return self.bytez

    def append_overlay(self, content: bytes):
        self.bytez += content
        return self.bytez

    def add_imports(self, library, functions):
        pe = lief.parse(raw=self.bytez)
        lib = pe.add_library(library)
        for f in functions:
            lib.add_entry(f)
        self.bytez = self._build(pe)
        return self.bytez

    def upx_unpack(self):
        # dump to a temporary file
        tmpfilename = os.path.join(
            tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

        with open(tmpfilename, 'wb') as outfile:
            outfile.write(self.bytez)

        # test with upx -t
        with open(os.devnull, 'w') as DEVNULL:
            retcode = subprocess.call(
                ['upx', tmpfilename, '-t'], stdout=DEVNULL, stderr=DEVNULL
            )

        if retcode == 0:
            with open(os.devnull, 'w') as DEVNULL:
                retcode = subprocess.call(
                    ['upx', tmpfilename, '-d', '-o', tmpfilename + '_unpacked'], stdout=DEVNULL, stderr=DEVNULL
                )
            if retcode == 0:
                with open(tmpfilename + '_unpacked', 'rb') as result:
                    self.bytez = result.read()

        os.unlink(tmpfilename)
        return self.bytez

ACTION_TABLE = {
    'add_section': 'add_section',
    'append_overlay': 'append_overlay',
    'set_timestamp': 'set_timestamp',
    'add_imports': 'add_imports',
    'upx_unpack': 'upx_unpack',
}

def modify_without_breaking(bytez, actions=[], seed=None):
    for action in actions:

        _action = ACTION_TABLE[action]

        # we run manipulation in a child process to shelter
        # our malware model from rare parsing errors in LIEF that
        # may segfault or timeout
        def helper(_action, shared_list):
            # TODO: LIEF is chatty. redirect stdout and stderr to /dev/null

            # for this process, change segfault of the child process
            # to a RuntimeEror
            def sig_handler(signum, frame):
                raise RuntimeError

            signal.signal(signal.SIGSEGV, sig_handler)

            bytez = array.array('B', shared_list[:]).tobytes()
            # TODO: LIEF is chatty. redirect output to /dev/null
            if type(_action) is str:
                _action = MalwareManipulator(bytez).__getattribute__(_action)
            else:
                _action = functools.partial(_action, bytez)

            # redirect standard out only in this queue
            try:
                shared_list[:] = _action(seed)
            except (RuntimeError, UnicodeDecodeError, TypeError, lief.not_found) as e:
                # some exceptions that have yet to be handled by public release of LIEF
                print("==== exception in child process ===")
                print(e)
                # shared_bytez remains unchanged

        # communicate with the subprocess through a shared list
        # can't use multiprocessing.Array since the subprocess may need to
        # change the size
        manager = multiprocessing.Manager()
        shared_list = manager.list()
        shared_list[:] = bytez  # copy bytez to shared array
        # define process
        p = multiprocessing.Process(target=helper, args=(_action, shared_list))
        p.start()  # start the process
        try:
            p.join(5)  # allow this to take up to 5 seconds...
        except multiprocessing.TimeoutError:  # ..then become petulant
            print('==== timeouterror ')
            p.terminate()

        bytez = array.array('B', shared_list[:]).tobytes()  # copy result from child process
        p.terminate()
    # import hashlib
    # m = hashlib.sha256()
    # m.update(bytez)
    # print("new hash: {}".format(m.hexdigest()))
    return bytez