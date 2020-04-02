from carrot import *
import simplecrypt, tarfile, os, json, shutil, hashlib, binascii, random, string

####################
###### ERRORS ######
####################

class AuthenticationError(BaseException):    # Errors related to permissions
    def __init__(self, *args, sep=" "):
        self.args = args
        self.sep = sep
    def __repr__(self):
        return self.sep.join(self.args)
class LoginError(AuthenticationError): pass
class IDError(AuthenticationError): pass # Wrong authentication token
class PermissionDenied(AuthenticationError): pass # Wrong permissions
class UserAlreadyLoged(AuthenticationError): pass # Someone else is already loged as this user

class UserAlreadyExists(BaseException): pass
class CorruptedData(BaseException): pass


class ALL: pass


def unique_user(f):
    def wrapper(self, user, *args, **kwargs):
        if user not in self.users:
            return f(self, user, *args, **kwargs)
    return wrapper
            

def user_required(f):
    def wrapper(self, user, key, *args, **kwargs):
        if user in self.rights and hashlib.pbkdf2_mac("sha256", decrypt_password(key, self.rights[user]), bytes(self.config["crypto"]["salt"], self.config["default"]["encoding"]), int(self.config["crypto"]["iterations"])) == self.hash:
            return f(self, (user, key), *args, **kwargs)
        self.logger.write("User %s attempted unsuccessfully to do %s." % (user, f), source="dbinterface", type_="info", verbosity=2)
        raise PermissionDenied("This user has no rights over this operations or has the wrong key")
    return wrapper




def generate_table_password(size=64):
    return "".join(random.choice(string.printable.translate(str.maketrans('', '', string.whitespaces))) for i in range(size))

def generate_table_salt(size=10):
    return generate_table_password(size)

def encrypt_password(key, passwd, salt):
    # passwd is 64 bytes randomly generated passwd
    # key is user's passwd
    # salt is table's unique salt
    res = b""
    for i1, i2 in zip(hashlib.sha512(key + salt).digest(), passwd):
        res += bytes([i1^i2])
    return res

def decrypt_password(key, savestate, salt):
    # savestate is 64 bytes generated with encrypt_password
    # key is user's passwd
    res = b""
    for i1, i2 in zip(hashlib.sha512(key + salt).digest(), savestate):
        res += bytes([i1^i2])
    return res


def base(n, b):
    res = []
    while n:
        res.insert(0,n%b)
        n//=b
    return res

class Section:
    def __init__(self, struct):
        self.struct = struct
        self.size = Int32()
    def read(self, flux):
        pos, size = self.size.read(flux.read(4))
        pos, content = self.struct.read(flux.read(size))
        return content
    def write(self, content):
        flux = self.struct.write(content)
        size = len(flux)
        return self.size.write(size) + flux


class Table:
    name = String()
    salt = Bytes(8)
    passwd = Bytes(32)
    right = Struct(Int(), Bytes(64))
    rights = List(right)
    
    struct = Struct(
        name,
        salt,
        passwd,
        rights
    )
        
    def __init__(self, id_, file, ofile, name, hash_, rights, salt, meta, logger, config):
        self.password = None
        self.hash = hash_
        self.id = id_
        self.name = name
        self.file = file
        self.ofile = ofile
        self.header = header
        self.rights = rights
        self.lines = []
        self.logger = logger
        self.is_open = 0
        self.users = []
        self.salt = salt
        self.meta = meta
        self._closer = concw(write_string, gen_write_bytes(8), gen_write_bytes(32), gen_write_list(concw(write_int, gen_write_bytes(64))))
        
    def _open(self, user, key):
        with open(self.file, 'rb') as f:
            with open(self.ofile, 'wb') as f2:
                self.password = decrypt_password(key, self.rights[user])
                f2.write(simplecrypt.decrypt(self.password), f.read())
    def _close(self):
        with open(self.ofile, 'rb') as f:
            with open(self.file, 'wb') as f2:
                f2.write(simplecrypt.encrypt(self.password, f.read()))
        with open(self.ofile, 'wb') as f:
            # avoid letting unused unencrypted tables
            f.write(b'\n')
        self.password = None
    def close(self):
        if self.is_open:
            self._close()
        with open(self.file, 'rb') as f:
            res = self._closer(self.name, self.salt, self.hash, self.rights.items())
            res = write_int32(len(res)) + res
            return res + f.read()
        
    @unique_user
    @user_required
    def open(self, credentials):
        if self.is_open == 0:
            self._open(*credentials)
        self.is_open += 1

    @user_required
    def closet(self, credentials):
        if credentials[0] in self.users:
            self.users.remove(credentials[0])
            self.is_open -= 1
            if self.is_open == 0:
                self._close()
    @user_required
    def add(self, credentials, line):
        if len(line) != len(self.header):
            raise TypeError("Line doesn't fit the header size")
        for i in range(len(line)):
            pass
        
class User:
    name = String()
    passwd = Bytes(32)
    groups = List(Int())
    struct = Struct(
        name,
        passwd,
        groups
    )
    def __init__(self, name, hash_, groups, logger, config):
        self.name = name
        self.hash = hash_
        self.groups = groups
        self.meta = meta
        self.logger = logger
        self.config = config
        self.loged = False
        self.freeze = False
        self.key = None
        self.connection_id = -1
        self._closer = concw(write_string, gen_write_bytes(32), gen_write_list(write_int))
    def login(self, key, id_):
        if self.loged:
            raise UserAlreadyLoged("Someone is already loged in with this user")
        if hashlib.pbkdf2_hmac('sha256', key, bytes(config["crypto"]["salt"], config["main"]["encoding"]), int(config["crypto"]["iterations"])) != self.hash:
            raise LoginError("Wrong password")
        self.loged = True
        self.connection_id = id_
        self.key = key
    def logout(self):
        self.loged = False
        self.freeze = False
        self.key = None
        self.connection_id = -1
    def close(self):
        return self._closer(self.name, self.hash, self.groups)

class Group:
    name = String()
    salt = Bytes(8)
    right = Struct(Int(), Bytes(64))
    rights = List(right)
    struct = Struct(
        name,
        salt,
        rights
    )
    def __init__(self, name, salt, rights):
        self.name = name
        self.rights = rights
        self.salt = salt
        self._closer = concw(write_string + gen_write_bytes(8) + gen_write_list(concw(write_int, gen_write_bytes(64))))
    def get_passwd(self, user, key):
        if user in self.rights:
            return decrypt_password(key, self.rights[user], self.salt)
    def close(self):
        return self._closer(self.name, self.salt, self.rights.items())
        
class Database:
    version = List(Int())
    name = String()
    nbusers = Int()
    nbgroups = Int()
    nbtables = Int()
    header = Struct(
        version,
        name,
        nbusers,
        nbgroups,
        nbtables
    )
    users = List(User.struct)
    tables = List(Table.struct)
    groups = List(Group.struct)
    header_section = Section(header)
    users_section = Section(users)
    groups_section = Section(groups)
    tables_section = Section(tables)
    
    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        self._init_vars()
        
    def _init_vars(self):
        self.file = self.config["pdb"]["file"]
        self.version = ""
        self.name = ""
        self.is_open = False
        self.users = []
        self.groups = []
        self.tables = []

    def open(self):
        if self.is_open: return
        self.directory = self.config["pdb.O"]["temp_dir"]
        try:
            os.mkdir(self.directory)
        except FileExistsError:
            if self.logger:
                self.logger.write("Temporary directory %s found before been created -> deleting the old one, creating new one" % self.directory, source="dbinterface", type_="warning")
                self.logger.flush()
            shutil.rmtree(self.directory)
            os.mkdir(self.directory)
        try:
            file_stream = open(self.file, 'rb')
        except FileNotFoundError:
            if self.logger:
                self.logger.write("Database not found, created blank one.", source="dbinterface", type_="info")
                self.logger.flush()
            version = [int(e) for e in self.config["main"]["version"].split(".")]
            name = self.config["default"]["db_name"]
            users = [(self.config["default"]["user_name"], hashlib.pbkdf2_hmac('sha256', bytes(self.config["default"]["user_password"], self.config["default"]["encoding"]), bytes(self.config["crypto"]["salt"], self.config["default"]["encoding"]), int(self.config["crypto"]["iterations"])), [])]
            tables = []
            groups = []
            nb_users = 1
            nb_tables = 0
            nb_groups = 0

            content = self.header_section.write([
                version,
                name,
                nb_users,
                nb_tables,
                nb_groups]) + self.users_section.write(users) + self.groups_section.write(groups) + self.tables_section.write(tables)
            
            with open(self.config["pdb"]["file"], 'wb') as f:
                f.write(content)
            del version, name, users, groups, tables, nb_users, nb_tables, nb_groups, content
            file_stream = open(self.config["pdb"]["file"], 'rb')
        try:
            self.header = self.header_section.read(file_stream)
        except IndexError:
            self.logger.write("Header of file %s is corrupted" % file, source="dbinterface", type_="error")
            self.logger.flush()
            raise CorruptedData("Cannot read header")
        try:
            self.users = self.users_section.read(file_stream)
        except IndexError:
            self.logger.write("Users map of database %s is corrupted" % self.header["name"], source="dbinterface", type_="error")
            self.logger.flush()
            self._init_vars()
            raise CorruptedData("Cannot read users map")
        try:
            self.groups = self.groups_section.read(file_stream)
        except IndexError:
            self.logger.write("Groups map of database %s is corrupted" % self.header["name"], source="dbinterface", type_="error")
            self.logger.flush()
            self._init_vars()
            raise CorruptedData("Cannot read groups map")
        try:
            self.tables = self.tables_section.read(file_stream)
        except IndexError:
            self.logger.write("Tables map of database %s is corrupted" % self.header["name"], source="dbinterface", type_="error")
            self.logger.flush()
            self._init_vars()
            raise CorruptedData("Cannot read tables map")
        self.is_open = True
        file_stream.close()
    def _read_pdb_tables(self, file_stream, header):
        self.table_map = {}
        for i in range(header["nbtable"]):
            _, size_header = read_int32(file_stream.read(4))
            header_data = file_stream.read(size_header)
            metadata = {
                "pos_name": 0
            }
            metadata["pos_salt"], metadata["name"] = read_string(header_data, metadata["pos_name"])
            metadata["pos_hash"], metadata["salt"] = gen_read_bytes(8)(header_data, metadata["pos_salt"])
            metadata["pos_nb_rights"], metadata["hash"] = gen_read_bytes(32)(header_data, metadata["pos_salt"])
            metadata["pos_rights"], metadata["nb_rights"] = read_int(header_data, metadata["pos_nb_rights"])
            metadata["pos_table"] = metadata["pos_rights"]
            metadata["rights"] = {}
            for j in range(metadata["nb_rights"]):
                metadata["pos_table"], id_ = read_int(header_data, metadata["pos_table"])
                metadata["pos_table"], metadata["rights"][id_] = gen_read_bytes(64)(header_data, metadata["pos_table"])
            if size_header != metadata["pos_table"]:
                self.logger.write("Header of table %s is corrupted, BUT readable" % metadata["name"], source="dbinterface", type_="warning")
            with open(self.directory + os.sep + i + self.config["pdb.O"]["table_ext"], 'wb') as f:
                f.write(header_data)
                real_chunk_size = min(config["pdb"]["MAXCHUNKSIZE"], header["sizetables"] - (4 + size_header))
                size_left = header["sizetables"] - (4 + size_header)
                while size_left > real_chunk_size:
                    f.write(file_stream.read(real_chunk_size))
                    size_left -= real_chunk_size
                f.write(file_stream.read(size_left))
            self.table_map[i] = Table(i, self.directory + os.sep + i + self.config["pdb.O"]["table_ext"], self.directory + os.sep + i + self.config["pdb.O"]["open_ext"], metadata["name"], metadata["hash"], metadata["rights"], metadata["salt"], metadata, self.logger, self.config)
    def _read_type(self, content, pos):
        pos, type_ = read_int(content, pos)
        tmap = {0: read_int, 1: read_float, 2: read_string, 4: read_date, 5: read_time, 6: read_datetime, 8: read_bool}
        if type_ == 3:
            pos, sb = self._read_type(content, pos)
            return pos, gen_read_list(sb)
        elif type_ == 7:
            pos, sz = read_int(content, pos)
            types = []
            for i in sz:
                pos, sb = _read_type(content, pos)
                types.append(sb)
            return pos, gen_read_table(types)
        else:
            return pos, tmap[type_]
    def _read_pdb_users(self, content, header):
        users = []
        pos = 0
        for i in range(header["nbusers"]):
            pos, name = read_string(content, pos)
            pos, hash_ = gen_read_bytes(32)(content, pos)
            pos, groups = gen_read_list(read_int)(content, pos)
            users.append(User(name, hash_, groups))
        return pos, users
    def _read_pdb_groups(self, content, header):
        groups = []
        pos = 0
        for i in range(header["nbgroups"]):
            pos, name = read_string(content, pos)
            pos, salt =  gen_read_bytes(8)(content, pos)
            pos, rights = dict(gen_read_list(concr(read_int, gen_read_bytes(64))))
            groups.append(Group(name, salt, rights))
        return pos, groups
    def _read_pdb_header(self, content):
        header = {}
        pos, version = gen_read_list(read_int)(content)
        header["version"] = ".".join(str(e) for e in version)
        pos, header["name"] = read_string(content, pos)
        pos, header["nbusers"] = read_int(content, pos)
        pos, header["nbgroups"] = read_int(content, pos)
        pos, header["nbtables"] = read_int(content, pos)
        pos, header["sizeusers"] = read_int(content, pos)
        pos, header["sizegroups"] = read_int(content, pos)
        pos, header["sizetables"] = gen_read_list(read_int)(content, pos)
        return pos, header
    def create_user(self, user, passwd):
        pass
    def login(self, user, key, id_):
        for usr in self.users:
            if usr.name == user:
                usr.login(key, id_)
                return usr
        raise LoginError("User not found")

    def close(self):
        for user_instance in self.user_instances.values():
            user_instance.logout(0)
        with open(os.sep.join((self.directory, "users.json")), "w") as f:
            f.write(json.dumps(self.users) + "\n")
        cwd, dirs, files = next(os.walk(self.directory))
        tar = tarfile.open(self.file, "w")
        for elem in dirs + files:
            tar.add(os.sep.join((self.directory, elem)))
        tar.close()
        shutil.rmtree(self.directory)
        self.is_open = False
