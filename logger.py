import messages

def show_connected_ips(devices_identities):
    print(messages.CONNECTED_DEVICES_MSG)
    for num, devices in enumerate(devices_identities):
        print(f'{num})\t{devices.ip}\t{devices.mac}')


def permission_denied():
    print(messages.PERMISSION_ERROR)


def blocking_for(time):
    if time:
        print(f'Blocking connections for {time} seconds...')
    else:
        print(messages.BLOCKING_INDEFINETELY)
    print(messages.YOU_CAN_CANCEL)


def restoring_connections():
    print(messages.RESTORING_CONNECTIONS)


def connections_restored():
    print(messages.CONNECTIONS_RESTORED)