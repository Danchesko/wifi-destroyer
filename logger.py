import messages

def show_connected_ips(devices_identities):
    print(messages.CONNECTED_DEVICES_MSG)
    for num, devices in enumerate(devices_identities):
        print(f'{num})\t{devices.ip}\t{devices.mac}')


def permission_denied():
    print(messages.PERMISSION_ERROR)