import sys

class linking_loader:
    def __init__(self):
        self.PROGADDR = int(sys.argv[1], 16)
        self.MEMORY = ''
        self.obj_files = []
        self.ESTAB = {}
        self.read_file()
        self.pass1()
        self.pass2()
        for key in self.ESTAB:
            print("%s:%s" % (key, hex(self.ESTAB[key])))

        for i in range(0, len(self.MEMORY)):
            if (i % 32 == 0):
                print("\n%s " % hex(self.PROGADDR + int((i / 2)))[2:], end='')
            print("%s" % self.MEMORY[i], end=" ")
        print("")

    def read_file(self):
        for filename in sys.argv[2:]:
            self.obj_files.append(obj_file(filename))

    def pass1(self):
        CSADDR = self.PROGADDR
        for obj in self.obj_files:
            self.ESTAB[obj.H_record.progname] = CSADDR
            for d_record in obj.D_records:
                self.ESTAB[d_record.label] = CSADDR + d_record.address_dec
            CSADDR += obj.H_record.proglen_dec
            self.MEMORY += '.'*obj.H_record.proglen_dec*2

    def pass2(self):
        CSADDR = self.PROGADDR
        for obj in self.obj_files:
            for t_record in obj.T_records:
                mem_index = t_record.address_dec
                mem_index += CSADDR - self.PROGADDR
                mem_index = mem_index * 2
                self.MEMORY = self.MEMORY[:mem_index] + t_record.content + self.MEMORY[mem_index+t_record.length_hex:]

            for m_record in obj.M_records:
                mem_index = m_record.address_dec
                mem_index += CSADDR - self.PROGADDR
                mem_index = mem_index * 2
                if(m_record.length_dec == 5):
                    mem_index += 1
                relocation_value = int(self.MEMORY[mem_index:mem_index+m_record.length_dec], 16)

                if relocation_value >= int(pow(2, m_record.length_bit - 1)):
                    relocation_value -= int(pow(2, m_record.length_bit))

                if m_record.isplus:
                    relocation_value += self.ESTAB[m_record.content]
                else:
                    relocation_value -= self.ESTAB[m_record.content]

                relocation_value = hex((relocation_value + (1 << m_record.length_bit)) % (1 << m_record.length_bit))[2:].upper()
                relocation_value = '0'*(m_record.length_dec-len(relocation_value)) + relocation_value
                self.MEMORY = self.MEMORY[:mem_index] + relocation_value + self.MEMORY[mem_index+m_record.length_dec:]
            CSADDR += obj.H_record.proglen_dec
class obj_file:
    def __init__(self, obj_file):
        self.obj_file = obj_file
        self.D_records = []
        self.T_records = []
        self.M_records = []
        self.load_file()

    def load_file(self):
        with open(self.obj_file, 'r') as f:
            for line in f.read().splitlines():
                if line.startswith('H'):
                    self.H_record = H_record(line)
                elif line.startswith('D'):
                    record_num = (len(line)-1)//12
                    for i in range(record_num):
                        self.D_records.append(D_record(line[i*12+1:i*12+13]))
                elif line.startswith('T'):
                    self.T_records.append(T_record(line))
                elif line.startswith('M'):
                    self.M_records.append(M_record(line))

class H_record:
    def __init__(self, H_record):
        self.H_record = H_record.split()
        self.progname = self.H_record[0][1:]
        self.progaddr = H_record[7:13]
        self.proglen = H_record[13:]
        self.progaddr_dec = int(self.progaddr, 16)
        self.proglen_dec = int(self.proglen, 16)

class D_record:
    def __init__(self, D_record):
        self.D_record = D_record.split()
        self.label = self.D_record[0]
        self.address = self.D_record[1]
        self.address_dec = int(self.address, 16)

class T_record:
    def __init__(self, T_record):
        self.T_record = T_record
        self.address = T_record[1:7]
        self.address_dec = int(self.address, 16)
        self.length = T_record[7:9]
        self.length_dec = int(self.length, 16)
        self.length_hex = int(self.length, 16) * 2
        self.content = T_record[9:]

class M_record:
    def __init__(self, M_record):
        self.M_record = M_record
        self.address = M_record[1:7]
        self.address_dec = int(self.address, 16)
        self.length = M_record[7:9]
        self.length_dec = int(self.length, 16)
        self.length_bit = self.length_dec*4
        if M_record[9] == '+':
            self.isplus = True
        elif M_record[9] == '-':
            self.isplus = False
        self.content = M_record[10:]

if __name__ == '__main__':
    l = linking_loader()