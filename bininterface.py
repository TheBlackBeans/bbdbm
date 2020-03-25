import datetime

__all__ = [
    "read_int",
    "read_int32",
    "read_float",
    "read_string",
    "gen_read_bytes",
    "read_date",
    "read_datetime",
    "read_time",
    "gen_read_list",
    "gen_read_table",
    "read_header",
    "read_bool",
    "write_int",
    "write_float",
    "write_string",
    "write_date",
    "write_datetime",
    "write_time",
    "gen_write_list",
    "gen_write_table",
    "gen_write_bytes",
    "write_bool",
    "write_int32",
    "concr",
    "concw"
]

def concr(*fs):
    def wrapper(flux, pos=0):
        res = []
        for f in fs:
            pos, r = f(flux, pos)
            res.append(r)
        return pos, tuple(res)
    return wrapper

def concw(*fs):
    def wrapper(*tps):
        if len(fs) != len(tps):
            raise TypeError("Wrong types")
        res = b""
        for f, t in zip(fs, tps):
            res += f(t)
        return res
    return wrapper

# ***********************
#    READ BYTES

def read_int(flux, pos=0):
    bits = bin(flux[pos])[2:].rjust(8, "0")
    result = bits[:7]
    pos += 1
    while bits[7] == "1":
        bits = bin(flux[pos])[2:].rjust(8, "0")
        result += bits[:7]
        pos += 1
    return pos, int(result, 2)

def read_int32(flux, pos=0):
    res = 0
    for i, ii in enumerate(flux[pos:pos+4]):
        res += 256**(3-i)*ii
    return pos+4, res

def read_bool(flux, pos=0):
    pos, r = read_int(flux, pos)
    return pos, bool(r)

def read_float(flux, pos=0):
    pos, number = read_int(flux, pos)
    pos, position = read_int(flux, pos)
    number *= 10 ** -position
    return pos, number
def gen_read_bytes(size):
    def read_bytes(flux, pos=0):
        result = b""
        for i in range(size):
            result += bytes([flux[pos]])
            pos += 1
        return pos, result
    return read_bytes

def read_string(flux, pos=0):
    result = ""
    while flux[pos] != 0:
        result += chr(flux[pos])
        pos += 1
    pos += 1
    return pos, result

def gen_read_list(type_):
    def read_list(flux, pos=0):
        values = []
        pos, size = read_int(flux, pos)
        for i in range(size):
            pos, result = type_(flux, pos)
            values.append(result)
        return pos ,values
    return read_list

def read_date(flux, pos=0):
    pos, year = read_int(flux, pos)
    pos, month = read_int(flux, pos)
    pos, day = read_int(flux, pos)
    return pos, datetime.date(year, month, day)

def read_time(flux, pos=0):
    pos, hour = read_int(flux, pos)
    pos, minute = read_int(flux, pos)
    pos, second = read_int(flux, pos)
    pos, micro = read_int(flux, pos)
    return pos, datetime.time(hour, minute, second, micro)

def read_datetime(flux, pos=0):
    pos, year = read_int(flux, pos)
    pos, month = read_int(flux, pos)
    pos, day = read_int(flux, pos)
    pos, hour = read_int(flux, pos)
    pos, minute = read_int(flux, pos)
    pos, second = read_int(flux, pos)
    pos, micro = read_int(flux, pos)
    return pos, datetime.datetime(year, month, day, hour, minute, second, micro)

def gen_read_table(types_):
    def read_table(flux, pos=0):
        pos, size = read_int(flux, pos)
        result = []
        for i in range(size):
            result.append([])
            for type_ in types_:
                pos, r = type_(flux, pos)
                result[-1].append(r)
        return pos, result
    return read_table

def read_single_type(flux, pos=0):
    pos, r = read_int(flux, pos)
    type_, nb_args, parsers = header_types_read[r]
    args = []
    for i in range(nb_args):
        pos, arg = parsers[i](flux, pos)
        args.append(arg)
    if args:
        type_ = type_(*args)
    return pos, type_


header_types_read = {
    0: (read_int, 0,[]),
    1: (read_float, 0,[]),
    2: (read_string, 0,[]),
    3: (gen_read_list, 1,[read_single_type]),
    4: (read_date, 0,[]),
    5: (read_time, 0,[]),
    6: (read_datetime, 0,[]),
    7: (gen_read_table, 1,[gen_read_list(read_single_type)])
}

    

def read_header(flux, pos=0):
    pos, name = read_string(flux, pos)
    pos, types_ = gen_read_list(read_single_type)(flux, pos)
    pos, size = read_int(flux, pos)
    return pos, (name, types_, size)


#****************
# WRITE BYTES

base_ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def tobase(i, b):
    if i == 0:
        return "0"
    digs = []
    while i:
        digs.append(base_[int(i % b)])
        i //= b
    return "".join(digs[::-1])

def tochunks(string, size):
    chunks = []
    nb_iterations = len(string)//size + int(len(string)%size!=0)
    for i in range(nb_iterations):
        chunks.append(string[size*i:size*(i+1)])
    return chunks

def base(n, b):
    res = []
    while n:
        res.insert(0,n%b)
        n//=b
    return res

def write_int32(number):
    b = base(number, 256)
    if len(b) > 4:
        raise ValueError("Number is greater or equal to 2^32, which is the (open) maximum for an int32")
    return bytes((4-len(b))*[0] + b)

def gen_write_bytes(size):
    def write_bytes(b):
        if len(b) != size: raise ValueError("Bytes must have lenght %s" % size)
        return b

def write_int(number):
    number = tobase(number, 2)
    number = tochunks(("0" * (7-len(number) % 7) + number), 7)
    for i in range(len(number)):
        if i == len(number) - 1:
            number[i] = number[i] + "0"
        else:
            number[i] = number[i] + "1"
    return bytes([int(i, 2) for i in number])

def write_bool(value):
    return write_int(int(value))

def write_float(number):
    position = len(str(float(number)).split(".")[1])
    number *= 10 ** position
    return write_int(number) + write_int(position)

def write_string(string):
    return bytes(string, "utf-8") + b'\x00'

def gen_write_list(type_):
    def write_list(list_):
        result = write_int(len(list_))
        for element in list_:
            result += type_(element)
        return result
    return write_list

def write_date(date):
    return write_int(date.year) + write_int(date.month) + write_int(date.day)

def write_time(time):
    return write_int(time.hour) + write_int(time.minute) + write_int(time.second) + write_int(time.microsecond)

def write_datetime(datetime_):
    return write_int(datetime_.year) + write_int(datetime_.month) + write_int(datetime_.day) + write_int(datetime_.hour) + write_int(datetime_.minute) + write_int(datetime_.second) + write_int(datetime_.microsecond)

def gen_write_table(types_):
    def write_table(table):
        result = write_int(len(table))
        for line in table:
            for i in range(len(types_)):
                result += types_[i](line[i])
        return result
    return write_table

def write_single_type(flux, pos=0):
    pos, r = read_int(flux, pos)
    type_, nb_args, parsers = header_types_write[r]
    args = []
    for i in range(nb_args):
        pos, arg = parsers[i](flux, pos)
        args.append(arg)
    if args:
        type_ = type_(*args)
    return pos, type_


header_types_write = {
    0: (write_int, 0,[]),
    1: (write_float, 0,[]),
    2: (write_string, 0,[]),
    3: (gen_write_list, 1,[write_single_type]),
    4: (write_date, 0,[]),
    5: (write_time, 0,[]),
    6: (write_datetime, 0,[]),
    7: (gen_write_table, 1,[gen_write_list(write_single_type)])
}
