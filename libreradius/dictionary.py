import os
import logging


class Dictionary():
    def __init__(self):
        self.dictionary = {}
        self.vendors = {}
        self.codecs = {}
        self.log = logging.getLogger('Dictionary')

    def load(self, dictionary_file="/usr/share/freeradius/dictionary"):
        assert os.path.isfile(dictionary_file)

        current_vendor = None

        with open(dictionary_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('#'):
                    self.log.info(line)

                if line.startswith('$INCLUDE'):
                    included_file = line.split()[1]
                    path = os.path.dirname(dictionary_file)
                    included_file = os.path.normpath(
                        os.path.join(path, included_file)
                        )
                    assert os.path.exists(included_file)
                    self.load(included_file)

                if line.startswith('VENDOR'):
                    a, vendor, code, *_ = line.split()
                    self.vendors[vendor] = code
                if line.startswith('BEGIN-VENDOR'):
                    a, vendor, *_ = line.split()
                    current_vendor = self.vendors[vendor]
                if line.startswith('END-VENDOR'):
                    current_vendor = None

                if line.startswith('ATTRIBUTE'):
                    a, name, code, vtype, *_ = line.split()
                    if current_vendor:
                        code = (current_vendor, code)
                    self.dictionary[name] = code
                    self.dictionary[code] = name
                    self.codecs[code] = vtype

                if line.startswith('VALUE'):
                    a, vtype, name, value, *_ = line.split()
                    vtype = "%s.value" % vtype
                    if not self.dictionary.get(vtype):
                        self.dictionary[vtype] = {}
                    self.dictionary[vtype][name] = value


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    d = Dictionary()
    d.load()
