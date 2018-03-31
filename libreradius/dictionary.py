import os
import logging


class Dictionary():
    def __init__(self):
        self.dictionary = {}
        self.vendors = {}
        self.codecs = {}
        self.log = logging.getLogger('Dictionary')

    def __call__(self, name):
        return self.dictionary[name]

    def load(self, dictionary_file="/usr/share/freeradius/dictionary"):
        assert os.path.isfile(dictionary_file)
        current_vendor = None

        with open(dictionary_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('#'):
                    self.log.debug(line)

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
                    self.vendors[vendor] = int(code)
                if line.startswith('BEGIN-VENDOR'):
                    a, vendor, *_ = line.split()
                    current_vendor = self.vendors[vendor]
                if line.startswith('END-VENDOR'):
                    current_vendor = None

                if line.startswith('ATTRIBUTE'):
                    a, name, code, vtype, *attrs = line.split()
                    try:
                        code = int(code)
                    except ValueError:
                        self.log.warning('Unsuported attribute %s type %s', code, vtype)
                    if current_vendor:
                        code = (current_vendor, code)
                    self.dictionary[name] = code
                    self.dictionary[code] = name
                    self.codecs[code] = getattr(self, vtype, lambda x, y: x)
                    if attrs:
                        if "encrypt=1" in attrs[0]:
                            self.codecs[code] = self.decrypt_1(self.codecs[code])

                if line.startswith('VALUE'):
                    a, vtype, name, value, *_ = line.split()
                    vtype = "%s.value" % vtype
                    if not self.dictionary.get(vtype):
                        self.dictionary[vtype] = {}
                    self.dictionary[vtype][name] = value
        return self

    def decrypt_1(self, decoder):
        def decrypt(data, packet):
            data = packet.pw_decrypt(data)
            return decoder(data, packet)
        return decrypt

    def integer(self, data, packet):
        if data is None:
            return
        return int.from_bytes(data, byteorder='big')

    def decode(self, packet, key):
        if isinstance(key, str):
            key = self.dictionary[key]
        decoder = self.codecs[key]
        data = b''.join(packet.get(key, b''))
        return decoder(data, packet)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    d = Dictionary()
    d.load()
