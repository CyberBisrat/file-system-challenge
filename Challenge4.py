#!/usr/bin/env python
import struct

with open('./FATdisk.vhd', 'rb') as f:
    vhd = f.read()

def parse_metadata(data):
    filename = data[0:13]
    date_time = data[13:18]
    last_access = data[18:20]
    msb_cluster = data[20:22]
    modification_date_time = data[22:26]
    lsb_cluster = data[26:28]
    file_size_bits = data[28:32]

    # FAT 32
    # cluster_address = (struct.unpack('<H', msb_cluster)[0] << 16) + struct.unpack('<H',lsb_cluster)[0]
    # FAT 16
    cluster_address = struct.unpack('<H',lsb_cluster)[0]

    return [filename, date_time, last_access, msb_cluster, modification_date_time, msb_cluster, file_size_bits], cluster_address

# Find possible offsets at which there might is a deleted file
writable_part = 10
for i, b in enumerate(vhd):
    if b == 0xe5:
        next_bytes = vhd[i+1:i+writable_part]
        if all([0x20 <= b and b <= 128 for b in next_bytes]):
            print(f'Metadata: {i} @ {vhd[i:i+32]}')


# Found \xe5CRET.ZIP file, let's read its metadata and get the cluster data
# Other data can be found by reading MBR/FAT metadata with an hex editor like okteta
sector_size = 512
cluster_size = sector_size * 2
partition_offset = 0x10000
cluster_offset = 134
offset = 275008 # SECRET.ZIP offset in disk
fields, cluster_addr = parse_metadata(vhd[offset:offset+40])
file_length = struct.unpack('<I', fields[-1])[0]

offset_in_disk = (cluster_addr + cluster_offset) * cluster_size + partition_offset
file_content = vhd[offset_in_disk:offset_in_disk + file_length]
with open('secret.zip', 'wb') as f:
    f.write(file_content)

